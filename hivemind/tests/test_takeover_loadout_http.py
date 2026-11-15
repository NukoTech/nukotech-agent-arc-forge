"""Exercise attended loadout uploads and signed lifecycle through the real HTTP boundary."""

import base64
import hashlib
import http.cookiejar
import io
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request
from uuid import uuid4
import zipfile

import pytest

from hive_protocol.core import canonical_bytes
from hive_protocol.product.server import make_server
from hive_protocol.product.workspace import HiveWorkspace


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _arc_files(version="1.0.0", extra_text="") -> list[dict]:
    """An independent minimal Arc interchange package, containing only fixture prose."""
    component_bytes = f"# Review checklist {version}\nRead the supplied source before writing a summary.\n{extra_text}".encode()
    component = {"id": "review-checklist", "version": version, "type": "skill", "path": "components/checklist.md",
        "sha256": _sha(component_bytes), "license": "MIT", "provenance": {"source": "local-test-fixture", "owner": "test-suite"},
        "capabilities": ["read.context"], "side_effects": [], "stop_conditions": ["USER_STOP"],
        "rollback": ["REMOVE_OWNED_CONTEXT"], "dependencies": [], "conflicts": []}
    identity = {"id": "review-operator", "version": version}
    recipe = {"schema": "nuko.agent_arc.recipe.v1", **identity, "requested_capabilities": ["read.context"],
        "side_effects": [], "authority_profile": "attended", "stop_conditions": ["USER_STOP"],
        "components": [{key: component[key] for key in ("id", "version", "type", "sha256")}]}
    registry = {"schema": "nuko.agent_arc.registry.v1", "registry_version": "1.0.0", "components": [component]}
    authorization = {"schema": "nuko.agent_arc.authorization.v1", "id": "fixture-authorization", "subject": identity["id"],
        "allowed_capabilities": ["read.context"], "allowed_side_effects": [], "prohibited_effects": ["execute.command"]}
    architecture = {"schema": "nuko.agent_arc.architecture_manifest.v1", "composer_version": "0.3.0-alpha.1",
        "recipe": identity, "registry_version": "1.0.0", "components": [component],
        "requested_capabilities": ["read.context"], "side_effects": [], "authority_profile": "attended", "stop_conditions": ["USER_STOP"]}
    architecture_bytes = canonical_bytes(architecture) + b"\n"
    security_context = {"recipe": {**identity, "requested_capabilities": ["read.context"], "side_effects": []},
        "authorization": {key: authorization[key] for key in ("id", "subject", "allowed_capabilities", "allowed_side_effects", "prohibited_effects")},
        "components": [component]}
    decisions = []
    for stage in ("pre_compose", "pre_package"):
        context = dict(security_context)
        if stage == "pre_package":
            context["architecture_manifest_sha256"] = _sha(architecture_bytes)
        decisions.append({"stage": stage, "decision": "allow", "evidence_hash": _sha(canonical_bytes({"stage": stage, "context": context}))})
    receipt = {"schema": "nuko.agent_arc.composition_receipt.v1", "status": "COMPOSED", "composer_version": "0.3.0-alpha.1",
        "recipe": identity, "registry_version": "1.0.0", "authorization_subject": identity["id"], "authorization_id": authorization["id"],
        "architecture_manifest_sha256": _sha(architecture_bytes), "component_hashes": [component["sha256"]], "security_decisions": decisions}
    entries = {"architecture-manifest.json": architecture_bytes, "composition-receipt.json": canonical_bytes(receipt) + b"\n", "components/checklist.md": component_bytes}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    files = {"package": buffer.getvalue(), "checksum_manifest": "".join(f"{_sha(content)}  {name}\n" for name, content in entries.items()).encode(),
        "recipe": json.dumps(recipe).encode(), "registry": json.dumps(registry).encode(), "arc_authorization": json.dumps(authorization).encode()}
    return [{"role": role, "sha256": _sha(content), "data_b64": base64.b64encode(content).decode()} for role, content in files.items()]


class Browser:
    def __init__(self, server):
        self.base = f"http://127.0.0.1:{server.server_address[1]}"
        self.client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        with self.client.open(urllib.request.Request(self.base + server.launch_path, headers={"Sec-Fetch-Site": "none"})):
            pass
        self.csrf = self.get("/api/v1/session")["data"]["csrf_proof"]

    def get(self, path):
        with self.client.open(urllib.request.Request(self.base + path, headers={"Sec-Fetch-Site": "same-origin"})) as response:
            return json.load(response)

    def request(self, action, data, expected="ABSENT"):
        return {"schema_version": "hive.operator-request.v1", "request_id": str(uuid4()), "tenant_id": "local-user", "project_id": "HiveMind",
                "action": action, "expected_version": expected, "idempotency_key": f"test:{uuid4()}", "input": data}

    def post(self, request, *, csrf=True):
        headers = {"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "Origin": self.base,
                   "If-Match": request["expected_version"], "X-Hive-Idempotency-Key": request["idempotency_key"]}
        if csrf:
            headers["X-Hive-CSRF"] = self.csrf
        try:
            response = self.client.open(urllib.request.Request(self.base + "/api/v1/" + request["action"].replace(".", "/"),
                data=json.dumps(request).encode(), headers=headers))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def ok(self, action, data, expected="ABSENT"):
        status, result = self.post(self.request(action, data, expected))
        assert status == 200, str(result)
        return result


@pytest.fixture
def browser(tmp_path: Path):
    workspace = HiveWorkspace.create(tmp_path / "hive")
    server = make_server(workspace, "127.0.0.1", 0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield Browser(server), workspace
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def _plan(browser: Browser, operation: str, stage=None, version=None):
    return browser.ok("loadouts.plan", {"loadout_id": "review-kit", "operation": operation,
        "stage_id": stage["data"]["stage_id"] if stage else None, "stage_digest": stage["object_version"] if stage else None,
        "version_digest": version, "authorization_ref": "attended-test-instruction", "reason": "Test the exact local lifecycle"})


def _approve(browser: Browser, plan):
    operation = plan["data"]["plan"]["operation"]
    return browser.ok("loadouts.approve", {"plan_digest": plan["object_version"], "confirmation": f"APPROVE {operation.upper()} review-kit"}, plan["object_version"])


def _apply_request(browser: Browser, plan, approval):
    operation = plan["data"]["plan"]["operation"]
    return browser.request("loadouts.apply", {"plan_digest": plan["object_version"], "approval_digest": approval["object_version"],
        "confirmation": f"APPLY {operation.upper()} review-kit"}, approval["object_version"])


def _snapshot(root: Path):
    return {path.relative_to(root).as_posix(): _sha(path.read_bytes()) for path in root.rglob("*") if path.is_file()}


def test_attended_http_loadout_admit_upgrade_rollback_revoke_uninstall(browser) -> None:
    browser, workspace = browser
    before = _snapshot(workspace.root)
    assert browser.get("/api/v1/loadouts?project_id=HiveMind")["data"]["loadouts"] == []
    assert before == _snapshot(workspace.root)
    pins = []
    for version in ("1.0.0", "1.0.1"):
        stage = browser.ok("loadouts.stage", {"files": _arc_files(version)})
        plan = _plan(browser, "admit", stage)
        approval = _approve(browser, plan)
        request = _apply_request(browser, plan, approval)
        status, applied = browser.post(request)
        assert status == 200, applied
        assert applied["data"]["receipt"]["grants_authority"] is False
        pins.append(applied["data"]["receipt"]["active_version_digest"])
        status, replay = browser.post(request)
        assert status == 200 and replay["changed"] is False
        assert replay["data"]["receipt"] == applied["data"]["receipt"]
    before = _snapshot(workspace.root)
    installed = browser.get("/api/v1/loadouts?project_id=HiveMind")["data"]["loadouts"]
    assert installed[0]["active_version_digest"] == pins[1]
    assert installed[0]["target"]["project_id"] == "HiveMind"
    assert before == _snapshot(workspace.root)
    plan = _plan(browser, "rollback", version=pins[0])
    status, applied = browser.post(_apply_request(browser, plan, _approve(browser, plan)))
    assert status == 200, applied
    assert applied["data"]["receipt"]["active_version_digest"] == pins[0]
    for operation in ("revoke", "uninstall"):
        plan = _plan(browser, operation)
        status, result = browser.post(_apply_request(browser, plan, _approve(browser, plan)))
        assert status == 200, str(result)
    installed = browser.get("/api/v1/loadouts?project_id=HiveMind")["data"]["loadouts"][0]
    assert installed["status"] == "UNINSTALLED"
    assert pins[0] in installed["revoked_versions"]


def test_loadout_upload_and_mutation_boundaries(browser) -> None:
    browser, workspace = browser
    files = _arc_files()
    request = browser.request("loadouts.stage", {"files": files})
    status, result = browser.post(request, csrf=False)
    assert status == 400 and result["reason_code"] == "WEB_CSRF_REQUIRED"
    assert not (workspace.runtime / "operator-shell/loadouts/uploads").exists()
    files[0]["sha256"] = "0" * 64
    status, result = browser.post(browser.request("loadouts.stage", {"files": files}))
    assert status == 400 and result["reason_code"] == "LOADOUT_UPLOAD_HASH_MISMATCH"
    files = _arc_files()
    files[0]["path"] = "/untrusted/local/path"
    status, result = browser.post(browser.request("loadouts.stage", {"files": files}))
    assert status == 400 and result["reason_code"] == "LOADOUT_UPLOAD_INVALID"
    assert not (workspace.runtime / "operator-shell/loadouts/uploads").exists()
    stage = browser.ok("loadouts.stage", {"files": _arc_files()})
    plan = _plan(browser, "admit", stage)
    bad = browser.request("loadouts.approve", {"plan_digest": plan["object_version"], "confirmation": "CONFIRM ACTION"}, plan["object_version"])
    status, result = browser.post(bad)
    assert status == 403 and result["reason_code"] == "LOADOUT_APPROVAL_INVALID"
    approval = _approve(browser, plan)
    (workspace.runtime / "operator-shell/loadouts/uploads" / stage["data"]["stage_id"] / "recipe").write_text("changed")
    status, result = browser.post(_apply_request(browser, plan, approval))
    assert status == 400 and result["reason_code"] == "LOADOUT_STAGE_CHANGED"
    assert browser.get("/api/v1/loadouts?project_id=HiveMind")["data"]["loadouts"] == []


def test_loadout_stage_accepts_bounded_package_larger_than_default_json_limit(browser) -> None:
    browser, _ = browser
    files = _arc_files(extra_text="Additional test evidence.\n" * 50000)
    assert len(json.dumps(files).encode()) > 1024 * 1024
    stage = browser.ok("loadouts.stage", {"files": files})
    assert stage["data"]["files"]["package"]["size_bytes"] > 1024 * 1024
    assert _plan(browser, "admit", stage)["data"]["plan"]["payload"]["manifest"]["execution_mode"] == "DECLARATIVE_ONLY"
