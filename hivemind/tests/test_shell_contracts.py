from __future__ import annotations

import copy
import math
from uuid import uuid4

import pytest

from hive_protocol.core import ProtocolError, document_digest
from hive_protocol.product.shell_contracts import (
    MUTATION_ROUTES,
    OPERATIONAL_STATES,
    RELEASE_HOLDS,
    ROUTES,
    OperatorRequest,
    OperatorResponse,
    route_for,
)


SHA_A = "a" * 64


def _request() -> dict[str, object]:
    return {
        "schema_version": "hive.operator-request.v1",
        "request_id": str(uuid4()),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "action": "capture.preview",
        "expected_version": SHA_A,
        "idempotency_key": "operator-request-0001",
        "input": {"channel": "markdown", "title": "Bounded capture"},
    }


def _response(request_id: str) -> dict[str, object]:
    return {
        "schema_version": "hive.operator-response.v1",
        "request_id": request_id,
        "outcome": "OK",
        "reason_code": None,
        "object_version": SHA_A,
        "changed": False,
        "data": {"ready": True},
        "technical_evidence": [
            {
                "kind": "receipt",
                "ref": "receipt:operator-preview",
                "sha256": SHA_A,
            }
        ],
    }


def test_operator_contracts_round_trip_immutably_and_digest_stably() -> None:
    request_document = _request()
    request = OperatorRequest.from_dict(request_document)
    assert request.as_dict() == request_document
    assert request.digest == document_digest(request_document)
    returned = request.as_dict()
    returned["project_id"] = "changed"
    assert request.project_id == "HiveMind"

    response_document = _response(str(request.request_id))
    response = OperatorResponse.from_dict(response_document)
    assert response.as_dict() == response_document
    assert response.digest == document_digest(response_document)
    returned = response.as_dict()
    returned["changed"] = True
    assert response.changed is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version="hive.operator-request.v2"),
        lambda value: value.update(project_id="../escape"),
        lambda value: value.update(unexpected_authority="grant:all"),
        lambda value: value.update(expected_version="stale"),
        lambda value: value.update(idempotency_key="short"),
        lambda value: value.update(action="shell.command"),
        lambda value: value.update(input={"value": math.inf}),
        lambda value: value.update(input={"api_" + "key": "examplevalue12345"}),
    ],
)
def test_operator_request_rejects_open_unsafe_nonfinite_and_credential_fields(
    mutation,
) -> None:
    document = _request()
    mutation(document)
    with pytest.raises(ProtocolError):
        OperatorRequest.from_dict(document)


@pytest.mark.parametrize(
    "field",
    (
        "schema_version",
        "request_id",
        "tenant_id",
        "project_id",
        "action",
        "expected_version",
        "idempotency_key",
        "input",
    ),
)
def test_operator_request_requires_every_scope_and_replay_binding(field: str) -> None:
    document = _request()
    document.pop(field)
    with pytest.raises(ProtocolError):
        OperatorRequest.from_dict(document)


def test_operator_request_rejects_collapsed_identity_and_excessive_depth() -> None:
    document = _request()
    document["project_id"] = document["tenant_id"]
    with pytest.raises(ProtocolError, match="OPERATOR_IDENTITY_COLLAPSE"):
        OperatorRequest.from_dict(document)

    document = _request()
    nested: dict[str, object] = {}
    document["input"] = nested
    for _ in range(14):
        child: dict[str, object] = {}
        nested["child"] = child
        nested = child
    with pytest.raises(ProtocolError, match="OPERATOR_DOCUMENT_DEPTH"):
        OperatorRequest.from_dict(document)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version="hive.operator-response.v2"),
        lambda value: value.update(outcome="AUTHORIZED"),
        lambda value: value.update(reason_code="free form failure"),
        lambda value: value.update(object_version="*"),
        lambda value: value.update(unexpected_authority=True),
        lambda value: value.update(data={"authorization": "Bearer examplevalue12345"}),
        lambda value: value.update(data={"value": math.nan}),
        lambda value: value.update(
            technical_evidence=[
                {"kind": "receipt", "ref": "../secret", "sha256": SHA_A}
            ]
        ),
    ],
)
def test_operator_response_rejects_authority_secret_and_unbounded_evidence(
    mutation,
) -> None:
    document = _response(str(uuid4()))
    mutation(document)
    with pytest.raises(ProtocolError):
        OperatorResponse.from_dict(document)


def test_operator_response_rejects_raw_diagnostics_and_private_keys() -> None:
    document = _response(str(uuid4()))
    document["data"] = {"traceback": "sensitive implementation detail"}
    with pytest.raises(ProtocolError, match="OPERATOR_DIAGNOSTIC_DENIED"):
        OperatorResponse.from_dict(document)

    document = _response(str(uuid4()))
    document["data"] = {
        "material": "-----BEGIN " + "PRIVATE KEY-----\nnot-a-real-key"
    }
    with pytest.raises(ProtocolError):
        OperatorResponse.from_dict(document)


def test_status_and_release_hold_vocabulary_is_exact_and_distinct() -> None:
    assert OPERATIONAL_STATES == (
        "DOCUMENTED",
        "IMPLEMENTED",
        "RUNNING",
        "WORKING",
        "VERIFIED",
        "AUTHORIZED",
    )
    assert RELEASE_HOLDS == (
        "NOT_RELEASED",
        "NO_CUSTOMER_DEPLOYMENT",
        "NO_UNATTENDED_RUNNER",
        "NO_PERSISTENT_SERVICE",
        "WINDOWS_NATIVE_NOT_VERIFIED",
        "MACOS_NATIVE_NOT_VERIFIED",
    )
    assert len(OPERATIONAL_STATES) == len(set(OPERATIONAL_STATES))
    assert len(RELEASE_HOLDS) == len(set(RELEASE_HOLDS))


def test_route_catalog_is_closed_versioned_and_contains_no_generic_escape_hatch() -> None:
    assert len(ROUTES) == len({(route.method, route.path) for route in ROUTES})
    assert all(route.path.startswith("/api/v1/") for route in ROUTES)
    assert all(route.method in {"GET", "POST"} for route in ROUTES)
    assert all(route.mutation == (route.method == "POST") for route in ROUTES)
    assert not any(
        word in route.path or word in route.action
        for route in ROUTES
        for word in ("command", "execute", "shell", "subprocess", "eval")
    )
    assert len(MUTATION_ROUTES) >= 40
    assert all(
        route.approval in {"NONE", "DOMAIN_PREVIEW", "DOMAIN_EXACT"}
        for route in MUTATION_ROUTES
    )
    assert route_for("GET", "/api/v1/home").action == "home.read"
    assert route_for("POST", "/api/v1/memory/promote").approval == "DOMAIN_EXACT"
    assert route_for("POST", "/api/v1/workflows/rollback/apply").approval == "DOMAIN_EXACT"
    assert route_for("POST", "/api/v1/capture/admit").approval == "DOMAIN_PREVIEW"

    with pytest.raises(ProtocolError, match="OPERATOR_ROUTE_UNKNOWN"):
        route_for("POST", "/api/v1/arbitrary")
    with pytest.raises(ProtocolError, match="OPERATOR_ROUTE_UNKNOWN"):
        route_for("DELETE", "/api/v1/home")


def test_request_action_must_match_one_exact_route_action() -> None:
    for route in MUTATION_ROUTES:
        document = _request()
        document["action"] = route.action
        document["request_id"] = str(uuid4())
        parsed = OperatorRequest.from_dict(document)
        assert parsed.action == route.action

    document = copy.deepcopy(_request())
    document["action"] = "capture.unknown"
    with pytest.raises(ProtocolError, match="OPERATOR_ACTION_UNKNOWN"):
        OperatorRequest.from_dict(document)
