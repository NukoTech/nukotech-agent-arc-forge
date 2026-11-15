"""Deterministic Agent Arc composition pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .models import Recipe, Registry, ResolvedComponent
from .policy import AuthorizationEnvelope, evaluate_policy
from .receipts import canonical_json_bytes, decision_mapping, issue_mapping
from .registry import resolve_components
from .schema import ValidationIssue, validate_document
from .security import (
    SecurityDecision,
    SecurityProvider,
    SecurityStage,
    evaluate_security_gate,
)
from .yamlio import load_yaml_strict


COMPOSER_VERSION = "0.3.0-alpha.1"


@dataclass(frozen=True)
class CompositionRequest:
    recipe_path: Path
    registry_path: Path
    authorization_path: Path
    component_root: Path


@dataclass(frozen=True)
class CompositionResult:
    status: str
    architecture_manifest: Mapping[str, Any] | None
    receipt: Mapping[str, Any]
    receipt_bytes: bytes
    issues: tuple[ValidationIssue, ...]
    security_decisions: tuple[SecurityDecision, ...]
    components: tuple[ResolvedComponent, ...]


def _refusal(
    *,
    recipe_id: str,
    recipe_version: str,
    registry_version: str,
    issues: tuple[ValidationIssue, ...],
    security_decisions: tuple[SecurityDecision, ...] = (),
    components: tuple[ResolvedComponent, ...] = (),
) -> CompositionResult:
    ordered = tuple(sorted(issues))
    receipt = {
        "schema": "nukotech.agent_arc.refusal_receipt.v1",
        "status": "REFUSED",
        "composer_version": COMPOSER_VERSION,
        "recipe": {"id": recipe_id, "version": recipe_version},
        "registry_version": registry_version,
        "issues": [issue_mapping(issue) for issue in ordered],
        "security_decisions": [decision_mapping(item) for item in security_decisions],
    }
    return CompositionResult(
        status="REFUSED",
        architecture_manifest=None,
        receipt=receipt,
        receipt_bytes=canonical_json_bytes(receipt),
        issues=ordered,
        security_decisions=security_decisions,
        components=components,
    )


def _input_issue(kind: str) -> ValidationIssue:
    return ValidationIssue(path=f"/{kind}", code="input_load_error", message=f"{kind} input could not be loaded")


def _authorization_mapping(authorization: AuthorizationEnvelope) -> dict[str, Any]:
    return {
        "id": authorization.id,
        "subject": authorization.subject,
        "allowed_capabilities": list(authorization.allowed_capabilities),
        "allowed_side_effects": list(authorization.allowed_side_effects),
        "prohibited_effects": list(authorization.prohibited_effects),
    }


def _component_mapping(component: ResolvedComponent, root: Path) -> dict[str, Any]:
    return {
        "id": component.id,
        "version": component.version,
        "type": component.type,
        "sha256": component.actual_sha256,
        "path": component.path.relative_to(root).as_posix(),
        "license": component.license,
        "provenance": dict(sorted(component.provenance.items())),
        "capabilities": sorted(component.capabilities),
        "side_effects": sorted(component.side_effects),
        "stop_conditions": sorted(component.stop_conditions),
        "rollback": sorted(component.rollback),
    }


def _security_context(
    recipe: Recipe,
    authorization: AuthorizationEnvelope,
    components: tuple[ResolvedComponent, ...],
    root: Path,
    architecture_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "recipe": {
            "id": recipe.id,
            "version": recipe.version,
            "requested_capabilities": sorted(recipe.requested_capabilities),
            "side_effects": sorted(recipe.side_effects),
        },
        "authorization": _authorization_mapping(authorization),
        "components": [_component_mapping(item, root) for item in components],
    }
    if architecture_manifest is not None:
        context["architecture_manifest_sha256"] = hashlib.sha256(
            canonical_json_bytes(architecture_manifest)
        ).hexdigest()
    return context


def _security_issue(decision: SecurityDecision) -> ValidationIssue:
    return ValidationIssue(
        path=f"/security/{decision.stage.value}",
        code=f"security_{decision.code}",
        message=f"security gate did not allow transition: {decision.code}",
    )


def compose(
    request: CompositionRequest,
    security_provider: SecurityProvider | None = None,
) -> CompositionResult:
    """Compose a bounded architecture or return a deterministic refusal."""

    loaded: dict[str, Mapping[str, Any]] = {}
    for kind, path in (
        ("recipe", request.recipe_path),
        ("registry", request.registry_path),
        ("authorization", request.authorization_path),
    ):
        try:
            loaded[kind] = load_yaml_strict(Path(path))
        except Exception:
            return _refusal(
                recipe_id="",
                recipe_version="",
                registry_version="",
                issues=(_input_issue(kind),),
            )

    recipe_document = loaded["recipe"]
    registry_document = loaded["registry"]
    authorization_document = loaded["authorization"]
    schema_issues = tuple(
        sorted(
            validate_document(recipe_document, "recipe")
            + validate_document(registry_document, "registry")
            + validate_document(authorization_document, "authorization-envelope")
        )
    )
    recipe_id = str(recipe_document.get("id", ""))
    recipe_version = str(recipe_document.get("version", ""))
    registry_version = str(registry_document.get("registry_version", ""))
    if schema_issues:
        return _refusal(
            recipe_id=recipe_id,
            recipe_version=recipe_version,
            registry_version=registry_version,
            issues=schema_issues,
        )

    recipe = Recipe.from_mapping(recipe_document)
    registry = Registry.from_mapping(registry_document)
    authorization = AuthorizationEnvelope.from_mapping(authorization_document)
    resolution = resolve_components(recipe, registry, Path(request.component_root))
    if resolution.issues:
        return _refusal(
            recipe_id=recipe.id,
            recipe_version=recipe.version,
            registry_version=registry.registry_version,
            issues=resolution.issues,
            components=resolution.components,
        )

    policy = evaluate_policy(recipe, resolution.components, authorization)
    if policy.issues:
        return _refusal(
            recipe_id=recipe.id,
            recipe_version=recipe.version,
            registry_version=registry.registry_version,
            issues=policy.issues,
            components=resolution.components,
        )

    root = Path(request.component_root).resolve()
    decisions: list[SecurityDecision] = []
    pre_compose = evaluate_security_gate(
        security_provider,
        SecurityStage.PRE_COMPOSE,
        _security_context(recipe, authorization, resolution.components, root),
    )
    decisions.append(pre_compose)
    if not pre_compose.decision.is_permitted:
        return _refusal(
            recipe_id=recipe.id,
            recipe_version=recipe.version,
            registry_version=registry.registry_version,
            issues=(_security_issue(pre_compose),),
            security_decisions=tuple(decisions),
            components=resolution.components,
        )

    architecture_manifest = {
        "schema": "nukotech.agent_arc.architecture_manifest.v1",
        "composer_version": COMPOSER_VERSION,
        "recipe": {"id": recipe.id, "version": recipe.version},
        "registry_version": registry.registry_version,
        "authority_profile": recipe.authority_profile,
        "requested_capabilities": sorted(recipe.requested_capabilities),
        "side_effects": sorted(recipe.side_effects),
        "stop_conditions": sorted(recipe.stop_conditions),
        "components": [_component_mapping(item, root) for item in resolution.components],
    }
    pre_package = evaluate_security_gate(
        security_provider,
        SecurityStage.PRE_PACKAGE,
        _security_context(recipe, authorization, resolution.components, root, architecture_manifest),
    )
    decisions.append(pre_package)
    if not pre_package.decision.is_permitted:
        return _refusal(
            recipe_id=recipe.id,
            recipe_version=recipe.version,
            registry_version=registry.registry_version,
            issues=(_security_issue(pre_package),),
            security_decisions=tuple(decisions),
            components=resolution.components,
        )

    architecture_hash = hashlib.sha256(canonical_json_bytes(architecture_manifest)).hexdigest()
    receipt = {
        "schema": "nukotech.agent_arc.composition_receipt.v1",
        "status": "COMPOSED",
        "composer_version": COMPOSER_VERSION,
        "recipe": {"id": recipe.id, "version": recipe.version},
        "registry_version": registry.registry_version,
        "authorization_id": authorization.id,
        "authorization_subject": authorization.subject,
        "architecture_manifest_sha256": architecture_hash,
        "component_hashes": [item.actual_sha256 for item in resolution.components],
        "security_decisions": [decision_mapping(item) for item in decisions],
    }
    return CompositionResult(
        status="COMPOSED",
        architecture_manifest=architecture_manifest,
        receipt=receipt,
        receipt_bytes=canonical_json_bytes(receipt),
        issues=(),
        security_decisions=tuple(decisions),
        components=resolution.components,
    )
