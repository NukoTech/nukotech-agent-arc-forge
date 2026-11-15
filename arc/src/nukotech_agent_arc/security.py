"""Provider-neutral security gates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .digests import digests_equal


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    HOLD = "hold"
    ESCALATE = "escalate"

    @property
    def is_permitted(self) -> bool:
        return self is Decision.ALLOW


class SecurityStage(str, Enum):
    PRE_COMPOSE = "pre_compose"
    PRE_PACKAGE = "pre_package"
    PRE_INSTALL = "pre_install"
    PRE_EXECUTE = "pre_execute"
    POST_EXECUTE = "post_execute"


@dataclass(frozen=True)
class SecurityDecision:
    decision: Decision
    code: str
    reasons: tuple[str, ...]
    evidence_hash: str
    provider: str
    stage: SecurityStage


class SecurityProvider(Protocol):
    name: str

    def evaluate(self, stage: SecurityStage, context: Mapping[str, Any]) -> SecurityDecision: ...


def security_context_hash(stage: SecurityStage, context: Mapping[str, Any]) -> str:
    """Return the canonical evidence hash a provider must bind to its decision."""

    payload = {"stage": stage.value, "context": context}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decision(
    *,
    provider: str,
    stage: SecurityStage,
    context: Mapping[str, Any],
    decision: Decision,
    code: str,
    reasons: tuple[str, ...],
) -> SecurityDecision:
    return SecurityDecision(
        decision=decision,
        code=code,
        reasons=reasons,
        evidence_hash=security_context_hash(stage, context),
        provider=provider,
        stage=stage,
    )


class LocalPolicyProvider:
    """Restrictive deterministic provider used when no external provider exists."""

    name = "local-policy"

    def evaluate(self, stage: SecurityStage, context: Mapping[str, Any]) -> SecurityDecision:
        authorization = context.get("authorization")
        if not isinstance(authorization, Mapping):
            return _decision(
                provider=self.name,
                stage=stage,
                context=context,
                decision=Decision.DENY,
                code="missing_authorization",
                reasons=("authorization envelope is required",),
            )

        recipe = context.get("recipe") if isinstance(context.get("recipe"), Mapping) else {}
        requested = set(recipe.get("requested_capabilities") or ())
        side_effects = set(recipe.get("side_effects") or ())
        allowed_capabilities = set(authorization.get("allowed_capabilities") or ())
        allowed_side_effects = set(authorization.get("allowed_side_effects") or ())
        prohibited = set(authorization.get("prohibited_effects") or ())

        unauthorized_capabilities = sorted(requested - allowed_capabilities)
        if unauthorized_capabilities:
            return _decision(
                provider=self.name,
                stage=stage,
                context=context,
                decision=Decision.DENY,
                code="unauthorized_capability",
                reasons=tuple(f"capability not authorized: {item}" for item in unauthorized_capabilities),
            )

        unauthorized_side_effects = sorted(side_effects - allowed_side_effects)
        if unauthorized_side_effects:
            return _decision(
                provider=self.name,
                stage=stage,
                context=context,
                decision=Decision.DENY,
                code="unauthorized_side_effect",
                reasons=tuple(f"side effect not authorized: {item}" for item in unauthorized_side_effects),
            )

        prohibited_requested = sorted((requested | side_effects) & prohibited)
        if prohibited_requested:
            return _decision(
                provider=self.name,
                stage=stage,
                context=context,
                decision=Decision.DENY,
                code="prohibited_effect",
                reasons=tuple(f"effect is prohibited: {item}" for item in prohibited_requested),
            )

        for component in context.get("components") or ():
            provenance = component.get("provenance") if isinstance(component, Mapping) else None
            if not isinstance(provenance, Mapping) or not provenance.get("source") or not provenance.get("owner"):
                return _decision(
                    provider=self.name,
                    stage=stage,
                    context=context,
                    decision=Decision.DENY,
                    code="missing_provenance",
                    reasons=("every component requires source and owner provenance",),
                )

        return _decision(
            provider=self.name,
            stage=stage,
            context=context,
            decision=Decision.ALLOW,
            code="policy_allow",
            reasons=("bounded local policy checks passed",),
        )


def required_composition_stages() -> tuple[SecurityStage, SecurityStage]:
    return (SecurityStage.PRE_COMPOSE, SecurityStage.PRE_PACKAGE)


def evaluate_security_gate(
    provider: SecurityProvider | None,
    stage: SecurityStage,
    context: Mapping[str, Any],
) -> SecurityDecision:
    """Evaluate one gate and convert provider failure to a non-leaking denial."""

    active = provider or LocalPolicyProvider()
    try:
        provider_name = active.name
        if not isinstance(provider_name, str) or not provider_name.strip():
            raise TypeError("invalid provider name")
    except Exception:
        provider_name = "unknown-provider"

    def fail_closed() -> SecurityDecision:
        return _decision(
            provider=provider_name,
            stage=stage,
            context=context,
            decision=Decision.DENY,
            code="provider_error",
            reasons=("security provider failed closed",),
        )

    try:
        response = active.evaluate(stage, context)
    except Exception:
        return fail_closed()

    valid = (
        isinstance(response, SecurityDecision)
        and isinstance(response.decision, Decision)
        and response.stage == stage
        and response.provider == provider_name
        and isinstance(response.code, str)
        and bool(response.code.strip())
        and isinstance(response.reasons, tuple)
        and bool(response.reasons)
        and all(isinstance(reason, str) and reason.strip() for reason in response.reasons)
        and digests_equal(response.evidence_hash, security_context_hash(stage, context))
    )
    return response if valid else fail_closed()
