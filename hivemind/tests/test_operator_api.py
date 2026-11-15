from __future__ import annotations

import copy
import hashlib
import http.cookiejar
import json
import stat
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest

from hive_protocol.core import ProtocolError
from hive_protocol.product.api import OperatorAPI
from hive_protocol.product.server import make_server
from hive_protocol.product.workspace import HiveWorkspace


SHA_A = "a" * 64
SHA_B = "b" * 64
SESSION_ID = "browser-session-value-that-must-not-persist"
SESSION_DIGEST = hashlib.sha256(SESSION_ID.encode("utf-8")).hexdigest()


class FakeOperatorService:
    def __init__(self) -> None:
        self.current = "ABSENT"
        self.mutate_calls = 0
        self.recover_calls = 0
        self.read_calls = 0
        self.delay = 0.0
        self.error: Exception | None = None
        self.effect_without_recovery = False
        self.results: dict[str, dict] = {}

    def current_version(self, route, request) -> str:
        del route, request
        return self.current

    def object_key(self, route, request) -> str:
        object_id = request.input.get("object_id", "default")
        return f"{request.project_id}:{route.action}:{object_id}"

    def mutate(self, route, request, *, operation_key: str) -> dict:
        del route
        self.mutate_calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.effect_without_recovery:
            raise RuntimeError("effect occurred without a durable recovery result")
        if self.error is not None:
            raise self.error
        result = {
            "operation_key": operation_key,
            "request_digest": request.digest,
            "outcome": "APPLIED",
            "reason_code": None,
            "object_version": SHA_B,
            "changed": True,
            "data": {"applied": request.action},
            "technical_evidence": [
                {
                    "kind": "receipt",
                    "ref": "receipt:fake-domain-result",
                    "sha256": SHA_B,
                }
            ],
        }
        self.results[operation_key] = copy.deepcopy(result)
        self.current = SHA_B
        return result

    def recover(self, route, request, *, operation_key: str) -> dict | None:
        del route, request
        self.recover_calls += 1
        result = self.results.get(operation_key)
        return copy.deepcopy(result) if result is not None else None

    def read(
        self,
        route,
        *,
        tenant_id: str,
        project_id: str,
        query: dict[str, str],
    ) -> dict:
        self.read_calls += 1
        return {
            "outcome": "OK",
            "reason_code": None,
            "object_version": SHA_A,
            "changed": False,
            "data": {
                "action": route.action,
                "tenant_id": tenant_id,
                "project_id": project_id,
                "query": query,
            },
            "technical_evidence": [],
        }


class CrashOnce:
    def __init__(self, stage: str) -> None:
        self.stage = stage
        self.observed: list[str] = []

    def __call__(self, stage: str) -> None:
        self.observed.append(stage)
        if stage == self.stage:
            self.stage = ""
            raise RuntimeError("injected crash with secret implementation detail")


def _request(
    *,
    key: str = "operator-request-0001",
    expected_version: str = "ABSENT",
) -> dict[str, object]:
    return {
        "schema_version": "hive.operator-request.v1",
        "request_id": str(uuid4()),
        "tenant_id": "local-user",
        "project_id": "HiveMind",
        "action": "capture.preview",
        "expected_version": expected_version,
        "idempotency_key": key,
        "input": {"title": "Replay safe"},
    }


def _api(
    tmp_path: Path,
    service: FakeOperatorService,
    *,
    fault_hook=None,
) -> tuple[OperatorAPI, Path]:
    vault = tmp_path / "hive"
    HiveWorkspace.create(vault)
    return (
        OperatorAPI(
            vault,
            service,
            tenant_id="local-user",
            project_ids={"HiveMind"},
            fault_hook=fault_hook,
        ),
        vault,
    )


def _dispatch(
    api: OperatorAPI,
    document: dict[str, object],
    *,
    path: str = "/api/v1/capture/preview",
    session_digest: str = SESSION_DIGEST,
    header_key: str | None = None,
    header_version: str | None = None,
):
    return api.dispatch_mutation(
        "POST",
        path,
        document,
        session_digest=session_digest,
        idempotency_key=header_key or str(document.get("idempotency_key", "")),
        expected_version=(
            header_version
            if header_version is not None
            else str(document.get("expected_version", ""))
        ),
    )


def _document(result) -> dict:
    return result.response.as_dict()


def test_success_record_binds_scope_session_request_version_and_result(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    api, _ = _api(tmp_path, service)
    request = _request()

    first = _dispatch(api, request)

    assert first.status == 200
    assert _document(first)["request_id"] == request["request_id"]
    assert _document(first)["outcome"] == "APPLIED"
    assert _document(first)["changed"] is True
    assert service.mutate_calls == 1
    records = list(api.ledger_root.glob("*.json"))
    assert len(records) == 1
    assert stat.S_IMODE(records[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(next(api.results_root.glob("*.json")).stat().st_mode) == 0o600
    for directory in (
        api.runtime_root,
        api.ledger_root,
        api.locks_root,
        api.object_locks_root,
        api.results_root,
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert record["state"] == "COMPLETE"
    assert record["session_digest"] == SESSION_DIGEST
    assert record["path"] == "/api/v1/capture/preview"
    assert record["action"] == "capture.preview"
    assert record["tenant_id"] == "local-user"
    assert record["project_id"] == "HiveMind"
    assert record["expected_version"] == "ABSENT"
    assert record["request_digest"]
    assert record["result_digest"]
    persisted = "".join(
        path.read_text(encoding="utf-8")
        for path in api.runtime_root.rglob("*.json")
    )
    assert SESSION_ID not in persisted


def test_exact_completed_and_concurrent_replay_never_repeat_mutation(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    service.delay = 0.1
    api, _ = _api(tmp_path, service)
    request = _request()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _dispatch(api, request), range(2)))

    assert sorted(_document(result)["changed"] for result in results) == [False, True]
    assert all(result.status == 200 for result in results)
    assert service.mutate_calls == 1

    replay = _dispatch(api, request)
    assert replay.status == 200
    assert _document(replay)["changed"] is False
    assert service.mutate_calls == 1


def test_object_lock_serializes_different_keys_against_one_version(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    service.delay = 0.1
    api, _ = _api(tmp_path, service)
    requests = [
        _request(key="operator-request-0001"),
        _request(key="operator-request-0002"),
    ]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda request: _dispatch(api, request), requests))

    assert sorted(result.status for result in results) == [200, 412]
    assert service.mutate_calls == 1


def test_replay_key_refuses_different_bytes_session_or_tampered_result(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    api, _ = _api(tmp_path, service)
    request = _request()
    assert _dispatch(api, request).status == 200

    changed = copy.deepcopy(request)
    changed["input"] = {"title": "different bytes"}
    conflict = _dispatch(api, changed)
    assert conflict.status == 409
    assert _document(conflict)["reason_code"] == "OPERATOR_REPLAY_CONFLICT"

    other_session = _dispatch(api, request, session_digest="c" * 64)
    assert other_session.status == 409
    assert _document(other_session)["reason_code"] == "OPERATOR_REPLAY_CONFLICT"
    assert service.mutate_calls == 1

    result_path = next(api.results_root.glob("*.json"))
    result_path.write_text('{"tampered":true}\n', encoding="utf-8")
    tampered = _dispatch(api, request)
    assert tampered.status == 409
    assert _document(tampered)["reason_code"] == "OPERATOR_REPLAY_INVALID"
    assert service.mutate_calls == 1


def test_scope_action_version_and_header_bindings_fail_before_domain(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    service.current = SHA_A
    api, _ = _api(tmp_path, service)

    stale = _dispatch(api, _request(expected_version=SHA_B))
    assert stale.status == 412
    assert _document(stale)["reason_code"] == "OPERATOR_VERSION_STALE"

    mismatch = _dispatch(
        api,
        _request(expected_version=SHA_A),
        header_version="ABSENT",
    )
    assert mismatch.status == 400
    assert _document(mismatch)["reason_code"] == "OPERATOR_HEADER_BODY_MISMATCH"

    invalid_precondition = _dispatch(
        api,
        _request(expected_version=SHA_A),
        header_version="*",
    )
    assert invalid_precondition.status == 400

    wrong_action = _request(expected_version=SHA_A)
    wrong_action["action"] = "memory.promote"
    action_result = _dispatch(api, wrong_action)
    assert action_result.status == 400
    assert _document(action_result)["reason_code"] == "OPERATOR_ACTION_ROUTE_MISMATCH"

    wrong_project = _request(expected_version=SHA_A)
    wrong_project["project_id"] = "OtherProject"
    scoped = _dispatch(api, wrong_project)
    assert scoped.status == 403
    assert _document(scoped)["reason_code"] == "OPERATOR_SCOPE_DENIED"

    invalid_session = _dispatch(
        api,
        _request(expected_version=SHA_A),
        session_digest="invalid",
    )
    assert invalid_session.status == 400
    assert service.mutate_calls == 0


def test_unknown_route_query_and_domain_faults_map_to_closed_responses(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    api, _ = _api(tmp_path, service)
    request = _request()

    unknown = _dispatch(api, request, path="/api/v1/arbitrary")
    assert unknown.status == 404
    assert _document(unknown)["reason_code"] == "OPERATOR_ROUTE_UNKNOWN"

    invalid_body = api.dispatch_mutation(
        "POST",
        "/api/v1/capture/preview",
        ["not", "an", "object"],
        session_digest=SESSION_DIGEST,
        idempotency_key="operator-request-0001",
        expected_version="ABSENT",
    )
    assert invalid_body.status == 400
    assert _document(invalid_body)["reason_code"] == "OPERATOR_DOCUMENT_INVALID"

    bad_query = api.dispatch_read(
        "GET",
        "/api/v1/home",
        tenant_id="local-user",
        project_id="HiveMind",
        query={"unexpected": "value"},
    )
    assert bad_query.status == 400
    assert _document(bad_query)["reason_code"] == "OPERATOR_QUERY_DENIED"
    assert service.read_calls == 0

    good_read = api.dispatch_read(
        "GET",
        "/api/v1/home",
        tenant_id="local-user",
        project_id="HiveMind",
        query={"project_id": "HiveMind"},
    )
    assert good_read.status == 200
    assert _document(good_read)["data"]["action"] == "home.read"

    approval_service = FakeOperatorService()
    approval_service.error = ProtocolError(
        "ADAPTER_APPROVAL_REQUIRED",
        "Authorization: Bearer secret-value-that-must-not-echo",
    )
    approval_api, _ = _api(tmp_path / "approval", approval_service)
    approval = _dispatch(approval_api, _request())
    assert approval.status == 403
    encoded = json.dumps(_document(approval))
    assert _document(approval)["reason_code"] == "ADAPTER_APPROVAL_REQUIRED"
    assert "secret-value" not in encoded
    assert "Authorization" not in encoded

    fault_service = FakeOperatorService()
    fault_service.error = RuntimeError("raw internal traceback secret")
    fault_api, _ = _api(tmp_path / "fault", fault_service)
    fault = _dispatch(fault_api, _request())
    assert fault.status == 500
    assert _document(fault)["reason_code"] == "OPERATOR_INTERNAL_ERROR"
    assert "traceback" not in json.dumps(_document(fault))


@pytest.mark.parametrize(
    ("stage", "expected_changed", "expected_recover_calls"),
    [
        ("after_prepare", True, 0),
        ("after_domain_result", False, 1),
        ("after_result_persist", False, 0),
    ],
)
def test_crash_windows_recover_without_duplicate_domain_mutation(
    tmp_path: Path,
    stage: str,
    expected_changed: bool,
    expected_recover_calls: int,
) -> None:
    service = FakeOperatorService()
    crash = CrashOnce(stage)
    api, _ = _api(tmp_path, service, fault_hook=crash)
    request = _request()

    interrupted = _dispatch(api, request)
    assert interrupted.status == 500
    assert _document(interrupted)["reason_code"] == "OPERATOR_INTERNAL_ERROR"

    recovered = _dispatch(api, request)
    assert recovered.status == 200
    assert _document(recovered)["changed"] is expected_changed
    assert service.mutate_calls == 1
    assert service.recover_calls == expected_recover_calls
    record = json.loads(
        next(api.ledger_root.glob("*.json")).read_text(encoding="utf-8")
    )
    assert record["state"] == "COMPLETE"


def test_ambiguous_effect_without_exact_domain_result_stays_pending(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    service.effect_without_recovery = True
    api, _ = _api(tmp_path, service)
    request = _request()

    first = _dispatch(api, request)
    assert first.status == 500
    retry = _dispatch(api, request)
    assert retry.status == 409
    assert _document(retry)["reason_code"] == "OPERATOR_EFFECT_STATE_PENDING"
    assert service.mutate_calls == 1
    assert service.recover_calls == 1


def test_pending_recovery_refuses_a_result_with_changed_operation_binding(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    crash = CrashOnce("after_domain_result")
    api, _ = _api(tmp_path, service, fault_hook=crash)
    request = _request()
    assert _dispatch(api, request).status == 500
    operation_key = next(iter(service.results))
    service.results[operation_key]["operation_key"] = "d" * 64

    refused = _dispatch(api, request)
    assert refused.status == 400
    assert _document(refused)["reason_code"] == "OPERATOR_DOMAIN_RESULT_MISMATCH"
    assert service.mutate_calls == 1


@pytest.mark.parametrize("target", ["runtime", "ledger", "locks", "results", "record"])
def test_symlinked_replay_boundaries_fail_before_domain_mutation(
    tmp_path: Path,
    target: str,
) -> None:
    service = FakeOperatorService()
    api, vault = _api(tmp_path, service)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    replay_root = vault / ".hive" / "runtime" / "operator-shell" / "api-replay"

    if target == "runtime":
        (vault / ".hive" / "runtime").symlink_to(
            outside,
            target_is_directory=True,
        )
    else:
        replay_root.mkdir(parents=True)
        for directory in ("ledger", "locks", "results"):
            path = replay_root / directory
            if directory == target:
                path.symlink_to(outside, target_is_directory=True)
            else:
                path.mkdir()
        if target == "record":
            record_id = hashlib.sha256(
                b"operator-request-0001"
            ).hexdigest()
            record = replay_root / "ledger" / f"{record_id}.json"
            record.symlink_to(sentinel)

    result = _dispatch(api, _request())
    assert result.status in {400, 403, 409}
    assert _document(result)["reason_code"] == "OPERATOR_RUNTIME_BOUNDARY"
    assert service.mutate_calls == 0
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_real_http_dispatch_binds_session_headers_body_and_exact_replay(
    tmp_path: Path,
) -> None:
    service = FakeOperatorService()
    api, vault = _api(tmp_path, service)
    workspace = HiveWorkspace.open(vault)
    server = make_server(
        workspace,
        "127.0.0.1",
        0,
        operator_api=api,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    browser = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    try:
        with browser.open(
            urllib.request.Request(
                f"http://127.0.0.1:{port}{server.launch_path}",
                headers={"Sec-Fetch-Site": "none"},
            ),
            timeout=5,
        ):
            pass
        with browser.open(
            urllib.request.Request(
                f"http://127.0.0.1:{port}/api/v1/session",
                headers={"Sec-Fetch-Site": "same-origin"},
            ),
            timeout=5,
        ) as response:
            csrf = json.loads(response.read().decode("utf-8"))["data"][
                "csrf_proof"
            ]

        document = _request()
        body = json.dumps(document).encode("utf-8")

        def invoke() -> dict:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/v1/capture/preview",
                data=body,
                method="POST",
                headers={
                    "Origin": f"http://127.0.0.1:{port}",
                    "Sec-Fetch-Site": "same-origin",
                    "Content-Type": "application/json",
                    "X-Hive-CSRF": csrf,
                    "X-Hive-Idempotency-Key": "operator-request-0001",
                    "If-Match": "ABSENT",
                },
            )
            with browser.open(request, timeout=5) as response:
                assert response.status == 200
                return json.loads(response.read().decode("utf-8"))

        first = invoke()
        replay = invoke()
        assert first["changed"] is True
        assert replay["changed"] is False
        assert first["request_id"] == document["request_id"]
        assert service.mutate_calls == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
