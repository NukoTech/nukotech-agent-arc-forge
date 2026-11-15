from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from nukotech_agent_arc.models import Recipe, ResolvedComponent


def _policy():
    module = importlib.import_module("nukotech_agent_arc.policy")
    assert hasattr(module, "AuthorizationEnvelope"), "AuthorizationEnvelope is not implemented"
    assert hasattr(module, "evaluate_policy"), "evaluate_policy is not implemented"
    return module


def _recipe(*, capabilities=("draft_content",), side_effects=()) -> Recipe:
    return Recipe(
        id="marketing-operator",
        version="1.0.0",
        purpose="Create drafts only",
        authority_profile="draft-only",
        components=(),
        requested_capabilities=tuple(capabilities),
        side_effects=tuple(side_effects),
        stop_conditions=("operator_stop",),
        acceptance_tests=("draft_created",),
        receipt_policy="canonical-json",
    )


def _component(
    *,
    component_id="safe-skill",
    license="MIT",
    provenance=None,
    dependencies=(),
    conflicts=(),
    capabilities=("draft_content",),
    side_effects=(),
    stop_conditions=("operator_stop",),
    rollback=("remove_candidate",),
) -> ResolvedComponent:
    return ResolvedComponent(
        id=component_id,
        version="1.0.0",
        type="skill",
        declared_sha256="a" * 64,
        actual_sha256="a" * 64,
        path=Path(f"/tmp/{component_id}.txt"),
        license=license,
        provenance=provenance if provenance is not None else {"source": "first-party", "owner": "example"},
        dependencies=tuple(dependencies),
        conflicts=tuple(conflicts),
        capabilities=tuple(capabilities),
        side_effects=tuple(side_effects),
        stop_conditions=tuple(stop_conditions),
        rollback=tuple(rollback),
    )


def _authorization(
    module,
    *,
    capabilities=("draft_content",),
    side_effects=(),
    subject="marketing-operator",
):
    return module.AuthorizationEnvelope(
        id="example-operator-test",
        subject=subject,
        allowed_capabilities=tuple(capabilities),
        allowed_side_effects=tuple(side_effects),
        prohibited_effects=("public_publish", "spend_money", "delete_data"),
    )


@pytest.mark.parametrize(
    ("component", "code"),
    [
        (_component(dependencies=("missing-skill",)), "unresolved_dependency"),
        (_component(license="UNKNOWN"), "unknown_license"),
        (_component(provenance={"source": "first-party"}), "missing_provenance"),
        (_component(stop_conditions=()), "missing_stop_condition"),
        (_component(rollback=()), "missing_rollback"),
    ],
)
def test_invalid_component_policy_fails_closed(component: ResolvedComponent, code: str) -> None:
    module = _policy()

    result = module.evaluate_policy(
        _recipe(),
        (component,),
        _authorization(module),
    )

    assert code in [issue.code for issue in result.issues]
    assert result.allowed is False


def test_declared_conflict_with_present_component_is_rejected() -> None:
    module = _policy()
    first = _component(conflicts=("other-skill",))
    other = _component(component_id="other-skill")

    result = module.evaluate_policy(_recipe(), (first, other), _authorization(module))

    assert "declared_conflict" in [issue.code for issue in result.issues]


def test_recipe_capability_cannot_exceed_authorization() -> None:
    module = _policy()

    result = module.evaluate_policy(
        _recipe(capabilities=("draft_content", "public_publish")),
        (_component(capabilities=("draft_content", "public_publish")),),
        _authorization(module),
    )

    assert "capability_not_authorized" in [issue.code for issue in result.issues]


def test_authorization_subject_must_match_recipe_identity() -> None:
    module = _policy()

    result = module.evaluate_policy(
        _recipe(),
        (_component(),),
        _authorization(module, subject="different-architecture"),
    )

    assert [issue.code for issue in result.issues] == ["authorization_subject_mismatch"]
    assert result.allowed is False


def test_component_capability_must_be_declared_by_recipe() -> None:
    module = _policy()

    result = module.evaluate_policy(
        _recipe(),
        (_component(capabilities=("draft_content", "read_private_mail")),),
        _authorization(module, capabilities=("draft_content", "read_private_mail")),
    )

    assert "component_capability_undeclared" in [issue.code for issue in result.issues]


def test_component_side_effect_must_be_declared_and_authorized() -> None:
    module = _policy()

    result = module.evaluate_policy(
        _recipe(),
        (_component(side_effects=("external_send",)),),
        _authorization(module, side_effects=("external_send",)),
    )

    assert "component_side_effect_undeclared" in [issue.code for issue in result.issues]


def test_zero_resolved_components_never_passes_policy() -> None:
    module = _policy()

    result = module.evaluate_policy(_recipe(), (), _authorization(module))

    assert [issue.code for issue in result.issues] == ["zero_components_resolved"]
    assert result.allowed is False


def test_valid_bounded_policy_passes() -> None:
    module = _policy()

    result = module.evaluate_policy(
        _recipe(),
        (_component(),),
        _authorization(module),
    )

    assert result.allowed is True
    assert result.issues == ()
