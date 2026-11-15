from __future__ import annotations

import importlib


def _security():
    module = importlib.import_module("nukotech_agent_arc.security")
    assert hasattr(module, "LocalPolicyProvider"), "local provider is not implemented"
    assert hasattr(module, "evaluate_security_gate"), "gate wrapper is not implemented"
    return module


def _context(*, capabilities=("draft_content",), side_effects=(), provenance=True, authorization=True):
    value = {
        "recipe": {
            "id": "marketing-operator",
            "requested_capabilities": list(capabilities),
            "side_effects": list(side_effects),
        },
        "components": [
            {
                "id": "safe-skill",
                "provenance": {"source": "first-party", "owner": "example"} if provenance else {},
            }
        ],
    }
    if authorization:
        value["authorization"] = {
            "id": "example-operator-test",
            "allowed_capabilities": ["draft_content"],
            "allowed_side_effects": [],
            "prohibited_effects": ["public_publish", "spend_money"],
        }
    return value


def test_composition_requires_pre_compose_and_pre_package_in_order() -> None:
    module = _security()

    assert module.required_composition_stages() == (
        module.SecurityStage.PRE_COMPOSE,
        module.SecurityStage.PRE_PACKAGE,
    )


def test_missing_provider_uses_restrictive_local_provider() -> None:
    module = _security()

    decision = module.evaluate_security_gate(None, module.SecurityStage.PRE_COMPOSE, _context())

    assert decision.decision == module.Decision.ALLOW
    assert decision.provider == "local-policy"
    assert len(decision.evidence_hash) == 64


def test_missing_authorization_is_denied() -> None:
    module = _security()

    decision = module.evaluate_security_gate(
        module.LocalPolicyProvider(),
        module.SecurityStage.PRE_COMPOSE,
        _context(authorization=False),
    )

    assert decision.decision == module.Decision.DENY
    assert decision.code == "missing_authorization"


def test_unauthorized_capability_is_denied() -> None:
    module = _security()

    decision = module.evaluate_security_gate(
        module.LocalPolicyProvider(),
        module.SecurityStage.PRE_COMPOSE,
        _context(capabilities=("draft_content", "public_publish")),
    )

    assert decision.decision == module.Decision.DENY
    assert decision.code == "unauthorized_capability"


def test_undeclared_side_effect_is_denied() -> None:
    module = _security()

    decision = module.evaluate_security_gate(
        module.LocalPolicyProvider(),
        module.SecurityStage.PRE_COMPOSE,
        _context(side_effects=("external_send",)),
    )

    assert decision.decision == module.Decision.DENY
    assert decision.code == "unauthorized_side_effect"


def test_missing_component_provenance_is_denied() -> None:
    module = _security()

    decision = module.evaluate_security_gate(
        module.LocalPolicyProvider(),
        module.SecurityStage.PRE_COMPOSE,
        _context(provenance=False),
    )

    assert decision.decision == module.Decision.DENY
    assert decision.code == "missing_provenance"


def test_provider_exception_fails_closed_without_error_detail_leak() -> None:
    module = _security()

    class BrokenProvider:
        name = "broken"

        def evaluate(self, stage, context):
            raise RuntimeError("secret-like diagnostic must not escape")

    decision = module.evaluate_security_gate(BrokenProvider(), module.SecurityStage.PRE_PACKAGE, _context())

    assert decision.decision == module.Decision.DENY
    assert decision.code == "provider_error"
    assert decision.reasons == ("security provider failed closed",)
    assert "secret-like" not in repr(decision)


def test_malformed_provider_response_fails_closed() -> None:
    module = _security()

    class MalformedProvider:
        name = "malformed"

        def evaluate(self, stage, context):
            return None

    decision = module.evaluate_security_gate(
        MalformedProvider(),
        module.SecurityStage.PRE_COMPOSE,
        _context(),
    )

    assert decision.decision == module.Decision.DENY
    assert decision.code == "provider_error"


def test_wrong_stage_or_evidence_hash_fails_closed() -> None:
    module = _security()

    class StaleProvider:
        name = "stale"

        def evaluate(self, stage, context):
            return module.SecurityDecision(
                decision=module.Decision.ALLOW,
                code="stale_allow",
                reasons=("stale result",),
                evidence_hash="0" * 64,
                provider=self.name,
                stage=module.SecurityStage.PRE_INSTALL,
            )

    decision = module.evaluate_security_gate(
        StaleProvider(),
        module.SecurityStage.PRE_COMPOSE,
        _context(),
    )

    assert decision.decision == module.Decision.DENY
    assert decision.code == "provider_error"


def test_hold_and_escalate_are_not_allow_decisions() -> None:
    module = _security()

    assert module.Decision.HOLD.is_permitted is False
    assert module.Decision.ESCALATE.is_permitted is False
    assert module.Decision.DENY.is_permitted is False
    assert module.Decision.ALLOW.is_permitted is True
