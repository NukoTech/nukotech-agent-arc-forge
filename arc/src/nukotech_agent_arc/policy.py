"""Compatibility and authorization policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .models import Recipe, ResolvedComponent
from .schema import ValidationIssue


KNOWN_LICENSES = frozenset({"MIT", "Apache-2.0", "BSD-3-Clause", "MPL-2.0", "LicenseRef-Proprietary"})


@dataclass(frozen=True)
class AuthorizationEnvelope:
    id: str
    subject: str
    allowed_capabilities: tuple[str, ...]
    allowed_side_effects: tuple[str, ...]
    prohibited_effects: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AuthorizationEnvelope":
        return cls(
            id=str(value.get("id", "")),
            subject=str(value.get("subject", "")),
            allowed_capabilities=tuple(str(item) for item in value.get("allowed_capabilities") or ()),
            allowed_side_effects=tuple(str(item) for item in value.get("allowed_side_effects") or ()),
            prohibited_effects=tuple(str(item) for item in value.get("prohibited_effects") or ()),
        )


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    issues: tuple[ValidationIssue, ...]


def _issue(code: str, path: str, message: str) -> ValidationIssue:
    return ValidationIssue(path=path, code=code, message=message)


def evaluate_policy(
    recipe: Recipe,
    components: Sequence[ResolvedComponent],
    authorization: AuthorizationEnvelope,
) -> PolicyResult:
    """Fail closed unless resolved components fit recipe and authorization bounds."""

    if not components:
        issue = _issue("zero_components_resolved", "/components", "policy cannot pass with zero components")
        return PolicyResult(allowed=False, issues=(issue,))

    issues: list[ValidationIssue] = []
    present_ids = {component.id for component in components}
    requested_capabilities = set(recipe.requested_capabilities)
    declared_side_effects = set(recipe.side_effects)
    allowed_capabilities = set(authorization.allowed_capabilities)
    allowed_side_effects = set(authorization.allowed_side_effects)
    prohibited = set(authorization.prohibited_effects)

    if authorization.subject != recipe.id:
        issues.append(
            _issue(
                "authorization_subject_mismatch",
                "/subject",
                "authorization subject does not match recipe identity",
            )
        )

    for capability in sorted(requested_capabilities - allowed_capabilities):
        issues.append(
            _issue(
                "capability_not_authorized",
                "/requested_capabilities",
                f"capability is outside authorization: {capability}",
            )
        )
    for side_effect in sorted(declared_side_effects - allowed_side_effects):
        issues.append(
            _issue(
                "side_effect_not_authorized",
                "/side_effects",
                f"side effect is outside authorization: {side_effect}",
            )
        )
    for effect in sorted((requested_capabilities | declared_side_effects) & prohibited):
        issues.append(_issue("prohibited_effect", "/", f"authorization explicitly prohibits: {effect}"))

    for component in components:
        path = f"/components/{component.id}"
        for dependency in sorted(set(component.dependencies) - present_ids):
            issues.append(_issue("unresolved_dependency", path, f"missing dependency: {dependency}"))
        for conflict in sorted(set(component.conflicts) & present_ids):
            issues.append(_issue("declared_conflict", path, f"conflicting component is present: {conflict}"))
        if component.license not in KNOWN_LICENSES:
            issues.append(_issue("unknown_license", path, f"license is not approved: {component.license or '<empty>'}"))
        if not component.provenance.get("source") or not component.provenance.get("owner"):
            issues.append(_issue("missing_provenance", path, "component requires source and owner provenance"))
        for capability in sorted(set(component.capabilities) - requested_capabilities):
            issues.append(
                _issue(
                    "component_capability_undeclared",
                    path,
                    f"component capability is absent from recipe: {capability}",
                )
            )
        for side_effect in sorted(set(component.side_effects) - declared_side_effects):
            issues.append(
                _issue(
                    "component_side_effect_undeclared",
                    path,
                    f"component side effect is absent from recipe: {side_effect}",
                )
            )
        if not component.stop_conditions:
            issues.append(_issue("missing_stop_condition", path, "component has no stop condition"))
        if not component.rollback:
            issues.append(_issue("missing_rollback", path, "component has no rollback instruction"))

    ordered = tuple(sorted(issues))
    return PolicyResult(allowed=not ordered, issues=ordered)
