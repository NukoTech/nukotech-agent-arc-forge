from __future__ import annotations

import hashlib
import importlib
from pathlib import Path

import yaml


def _modules():
    composer = importlib.import_module("nukotech_agent_arc.composer")
    receipts = importlib.import_module("nukotech_agent_arc.receipts")
    assert hasattr(composer, "CompositionRequest"), "CompositionRequest is not implemented"
    assert hasattr(composer, "compose"), "compose is not implemented"
    assert hasattr(receipts, "canonical_json_bytes"), "canonical JSON is not implemented"
    return composer, receipts


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_yaml(path: Path, value: dict) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=True), encoding="utf-8")


def _workspace(
    tmp_path: Path,
    *,
    authorized=True,
    declared_hash=None,
    authorization_subject="marketing-operator",
):
    artifact = tmp_path / "components" / "safe-skill.txt"
    artifact.parent.mkdir()
    payload = b"safe skill\n"
    artifact.write_bytes(payload)
    digest = declared_hash or _sha(payload)

    recipe = {
        "schema": "nukotech.agent_arc.recipe.v1",
        "id": "marketing-operator",
        "version": "1.0.0",
        "purpose": "Create drafts only",
        "authority_profile": "draft-only",
        "components": [
            {"id": "safe-skill", "version": "1.0.0", "type": "skill", "sha256": digest}
        ],
        "requested_capabilities": ["draft_content"],
        "side_effects": [],
        "stop_conditions": ["operator_stop"],
        "acceptance_tests": ["draft_created"],
        "receipt_policy": "canonical-json",
    }
    registry = {
        "schema": "nukotech.agent_arc.registry.v1",
        "registry_version": "0.3.0-alpha.1",
        "product": {"id": "nukotech-agent-arc", "status": "LOCAL_COMPOSER_ALPHA"},
        "components": [
            {
                "schema": "nukotech.agent_arc.component.v1",
                "id": "safe-skill",
                "version": "1.0.0",
                "type": "skill",
                "sha256": digest,
                "path": "components/safe-skill.txt",
                "license": "MIT",
                "provenance": {"source": "first-party", "owner": "example"},
                "dependencies": [],
                "conflicts": [],
                "capabilities": ["draft_content"],
                "side_effects": [],
                "stop_conditions": ["operator_stop"],
                "rollback": ["remove_candidate"],
            }
        ],
    }
    authorization = {
        "schema": "nukotech.agent_arc.authorization.v1",
        "id": "example-operator-test",
        "subject": authorization_subject,
        "allowed_capabilities": ["draft_content"] if authorized else [],
        "allowed_side_effects": [],
        "prohibited_effects": ["public_publish", "spend_money", "delete_data"],
    }
    recipe_path = tmp_path / "recipe.yaml"
    registry_path = tmp_path / "registry.yaml"
    authorization_path = tmp_path / "authorization.yaml"
    _write_yaml(recipe_path, recipe)
    _write_yaml(registry_path, registry)
    _write_yaml(authorization_path, authorization)
    return recipe_path, registry_path, authorization_path


def _request(composer, tmp_path: Path, **kwargs):
    recipe, registry, authorization = _workspace(tmp_path, **kwargs)
    return composer.CompositionRequest(
        recipe_path=recipe,
        registry_path=registry,
        authorization_path=authorization,
        component_root=tmp_path,
    )


def test_valid_composition_emits_manifest_and_success_receipt(tmp_path: Path) -> None:
    composer, receipts = _modules()

    result = composer.compose(_request(composer, tmp_path))

    assert result.status == "COMPOSED"
    assert result.issues == ()
    assert result.architecture_manifest["recipe"] == {"id": "marketing-operator", "version": "1.0.0"}
    assert result.architecture_manifest["components"][0]["id"] == "safe-skill"
    assert [decision.stage.value for decision in result.security_decisions] == ["pre_compose", "pre_package"]
    assert result.receipt_bytes == receipts.canonical_json_bytes(result.receipt)
    assert result.receipt["status"] == "COMPOSED"
    assert result.receipt["authorization_subject"] == "marketing-operator"


def test_invalid_recipe_schema_emits_refusal_without_manifest(tmp_path: Path) -> None:
    composer, _ = _modules()
    request = _request(composer, tmp_path)
    recipe = yaml.safe_load(request.recipe_path.read_text(encoding="utf-8"))
    del recipe["purpose"]
    _write_yaml(request.recipe_path, recipe)

    result = composer.compose(request)

    assert result.status == "REFUSED"
    assert result.architecture_manifest is None
    assert "required" in [issue.code for issue in result.issues]
    assert result.receipt["schema"] == "nukotech.agent_arc.refusal_receipt.v1"


def test_hash_resolution_failure_emits_refusal(tmp_path: Path) -> None:
    composer, _ = _modules()
    result = composer.compose(_request(composer, tmp_path, declared_hash="a" * 64))

    assert result.status == "REFUSED"
    assert [issue.code for issue in result.issues] == ["component_hash_mismatch"]


def test_policy_failure_emits_refusal(tmp_path: Path) -> None:
    composer, _ = _modules()
    result = composer.compose(_request(composer, tmp_path, authorized=False))

    assert result.status == "REFUSED"
    assert "capability_not_authorized" in [issue.code for issue in result.issues]


def test_mismatched_authorization_subject_emits_refusal(tmp_path: Path) -> None:
    composer, _ = _modules()
    result = composer.compose(
        _request(composer, tmp_path, authorization_subject="different-architecture")
    )

    assert result.status == "REFUSED"
    assert [issue.code for issue in result.issues] == ["authorization_subject_mismatch"]


def test_security_denial_emits_refusal(tmp_path: Path) -> None:
    composer, _ = _modules()
    security = importlib.import_module("nukotech_agent_arc.security")

    class DenyProvider:
        name = "test-deny"

        def evaluate(self, stage, context):
            return security.SecurityDecision(
                decision=security.Decision.DENY,
                code="test_denial",
                reasons=("denied for test",),
                evidence_hash=security.security_context_hash(stage, context),
                provider=self.name,
                stage=stage,
            )

    result = composer.compose(_request(composer, tmp_path), DenyProvider())

    assert result.status == "REFUSED"
    assert [issue.code for issue in result.issues] == ["security_test_denial"]


def test_schema_refusal_keeps_all_stably_sorted_issues(tmp_path: Path) -> None:
    composer, _ = _modules()
    request = _request(composer, tmp_path)
    _write_yaml(request.recipe_path, {"schema": "wrong"})

    result = composer.compose(request)
    ordering = [(issue.path, issue.code, issue.message) for issue in result.issues]

    assert len(ordering) > 2
    assert ordering == sorted(ordering)


def test_identical_inputs_produce_byte_identical_manifest_and_receipt(tmp_path: Path) -> None:
    composer, receipts = _modules()
    request = _request(composer, tmp_path)

    first = composer.compose(request)
    second = composer.compose(request)

    assert receipts.canonical_json_bytes(first.architecture_manifest) == receipts.canonical_json_bytes(
        second.architecture_manifest
    )
    assert first.receipt_bytes == second.receipt_bytes
    assert b"timestamp" not in first.receipt_bytes


def test_composer_never_invokes_install_or_execute_security_stages(tmp_path: Path) -> None:
    composer, _ = _modules()
    security = importlib.import_module("nukotech_agent_arc.security")

    class RecordingProvider:
        name = "recording"

        def __init__(self):
            self.stages = []

        def evaluate(self, stage, context):
            self.stages.append(stage)
            return security.SecurityDecision(
                decision=security.Decision.ALLOW,
                code="test_allow",
                reasons=("allowed for test",),
                evidence_hash=security.security_context_hash(stage, context),
                provider=self.name,
                stage=stage,
            )

    provider = RecordingProvider()
    result = composer.compose(_request(composer, tmp_path), provider)

    assert result.status == "COMPOSED"
    assert provider.stages == [security.SecurityStage.PRE_COMPOSE, security.SecurityStage.PRE_PACKAGE]
