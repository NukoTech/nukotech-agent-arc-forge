#!/usr/bin/env python3
"""Verify the installed M4 application through its attended HTTP boundary only."""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import signal
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


PROJECT = "HiveMind"
TENANT = "local-user"
SHA_A = "a" * 64
SHA_B = "b" * 64


class VerificationError(RuntimeError):
    """One installed-boundary invariant was not demonstrated."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _digest(document: dict[str, Any]) -> str:
    payload = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _Process:
    def __init__(
        self,
        launch_command: list[str],
        vault: Path,
        environment: dict[str, str] | None,
    ) -> None:
        env = dict(environment or os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        read_fd, write_fd = os.pipe()
        try:
            self.child = subprocess.Popen(
                [
                    *launch_command,
                    "app",
                    "--vault",
                    str(vault),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "0",
                    "--launch-handoff-fd",
                    str(write_fd),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                pass_fds=(write_fd,),
            )
        except BaseException:
            os.close(read_fd)
            raise
        finally:
            os.close(write_fd)
        _require(self.child.stdout is not None, "launcher stdout was unavailable")
        line = self.child.stdout.readline()
        with os.fdopen(read_fd, "r", encoding="utf-8") as handoff:
            self.launch_url = handoff.readline().strip()
        if not line:
            diagnostic = ""
            if self.child.stderr is not None:
                diagnostic = self.child.stderr.read(2048)
            raise VerificationError(f"launcher did not become ready: {diagnostic}")
        ready = json.loads(line)
        _require(ready.get("outcome") == "RUNNING", "launcher did not report RUNNING")
        _require(ready.get("pid") == self.child.pid, "launcher PID was not exact")
        self.base_url = str(ready["url"]).removesuffix("/app")
        parsed = urllib.parse.urlsplit(self.base_url)
        _require(parsed.scheme == "http", "launcher URL was not local HTTP")
        _require(parsed.hostname == "127.0.0.1", "launcher escaped loopback")
        _require(bool(parsed.port), "launcher did not select a port")
        _require(not parsed.query and not parsed.fragment, "launcher URL carried hidden state")
        _require("token" not in json.dumps(ready).lower(), "launcher disclosed a token")
        launch = urllib.parse.urlsplit(self.launch_url)
        _require(launch.scheme == "http", "browser handoff was not local HTTP")
        _require(launch.hostname == "127.0.0.1", "browser handoff escaped loopback")
        _require(launch.port == parsed.port, "browser handoff changed listener port")
        _require(
            launch.path.startswith("/_hive/launch/")
            and len(launch.path.removeprefix("/_hive/launch/")) >= 32,
            "browser handoff lacked one-time launch material",
        )
        _require(
            not launch.query and not launch.fragment,
            "browser handoff used query or fragment credentials",
        )

    def stop(self) -> None:
        if self.child.poll() is None:
            self.child.send_signal(signal.SIGINT)
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired as exc:
                self.child.terminate()
                self.child.wait(timeout=5)
                raise VerificationError("launcher did not stop on interruption") from exc
        _require(self.child.returncode == 0, "launcher stopped unsuccessfully")

    def __del__(self) -> None:
        child = getattr(self, "child", None)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)


class _Client:
    def __init__(self, base_url: str, launch_url: str) -> None:
        self.base_url = base_url
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        navigation = urllib.request.Request(
            launch_url,
            headers={"Sec-Fetch-Site": "none"},
            method="GET",
        )
        with self.opener.open(navigation, timeout=10) as response:
            page = response.read().decode("utf-8")
            _require(
                response.geturl() == f"{base_url}/app",
                "browser handoff did not clear launch material",
            )
        _require("HiveMind" in page, "application did not render the project")
        _require(launch_url not in page, "application rendered launch material")
        _require(self.cookies, "application did not issue a browser session")
        session = self.get("/api/v1/session", project=False)
        _require(session["data"]["authenticated"] is True, "session was not authenticated")
        self.csrf = str(session["data"]["csrf_proof"])

    @property
    def cookies(self) -> dict[str, str]:
        return {cookie.name: cookie.value for cookie in self.jar}

    def get(
        self,
        path: str,
        *,
        query: dict[str, str] | None = None,
        project: bool = True,
    ) -> dict[str, Any]:
        values = dict(query or {})
        if project:
            values.setdefault("project_id", PROJECT)
        suffix = "" if not values else "?" + urllib.parse.urlencode(values)
        request = urllib.request.Request(
            f"{self.base_url}{path}{suffix}",
            headers={"Sec-Fetch-Site": "same-origin"},
            method="GET",
        )
        with self.opener.open(request, timeout=10) as response:
            document = json.loads(response.read())
        _require(document.get("outcome") == "OK", f"read failed: {path}: {document}")
        return document

    def post(
        self,
        path: str,
        action: str,
        body: dict[str, Any],
        expected: str,
        *,
        key: str | None = None,
        request_id: str | None = None,
        allow_refusal: bool = False,
    ) -> dict[str, Any]:
        idempotency_key = key or f"m4:{uuid4()}"
        document = {
            "schema_version": "hive.operator-request.v1",
            "request_id": request_id or str(uuid4()),
            "tenant_id": TENANT,
            "project_id": PROJECT,
            "action": action,
            "expected_version": expected,
            "idempotency_key": idempotency_key,
            "input": body,
        }
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(document, separators=(",", ":")).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Origin": self.base_url,
                "Sec-Fetch-Site": "same-origin",
                "X-Hive-CSRF": self.csrf,
                "X-Hive-Idempotency-Key": idempotency_key,
                "If-Match": expected,
            },
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                result = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            result = json.loads(exc.read())
            if not allow_refusal:
                raise VerificationError(f"mutation failed: {action}: {result}") from exc
        if not allow_refusal:
            _require(
                result.get("outcome") in {"APPLIED", "OK"},
                f"mutation did not succeed: {action}: {result}",
            )
        return result


def _register(client: _Client, agent_id: str, capabilities: list[str]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    scope = {
        "persona": f"Director-{agent_id}",
        "agent_id": agent_id,
        "capabilities": sorted(capabilities),
        "machine_id": f"machine:{agent_id}",
        "surface_id": f"surface:{agent_id}",
        "project_ids": [PROJECT],
        "app_actor": f"app:{agent_id}",
    }
    client.post(
        "/api/v1/agents/capabilities/authorize",
        "agents.capabilities.authorize",
        {
            **scope,
            "expires_at": (now + timedelta(hours=8)).isoformat(),
            "attended_confirmation": True,
        },
        "ABSENT",
    )
    return client.post(
        "/api/v1/agents/register",
        "agents.register",
        scope,
        "ABSENT",
    )


def _step(
    step_id: str,
    capability: str,
    machine_id: str,
    dependencies: list[str],
    approval: bool,
) -> dict[str, Any]:
    output_name = {"research": "raw", "analyze": "analysis", "publish": "final"}[step_id]
    inputs = []
    if dependencies:
        source = dependencies[-1]
        inputs = [{
            "name": f"{source}_input",
            "type": "application/json",
            "source_step_id": source,
            "source_output": {"research": "raw", "analyze": "analysis"}[source],
            "required": True,
        }]
    return {
        "step_id": step_id,
        "kind": "TASK",
        "dependencies": dependencies,
        "inputs": inputs,
        "outputs": [{"name": output_name, "type": "application/json"}],
        "required_capabilities": [capability],
        "required_trust": "ATTENDED",
        "target": {"project_id": PROJECT, "machine_id": machine_id, "surface_id": None},
        "approval": {"required": approval, "risk_class": "HIGH" if approval else "LOW"},
        "retry": {"max_attempts": 3, "timeout_seconds": 300},
        "resources": {"max_tokens": 2000, "max_cost_microunits": 10000, "max_memory_mb": 512},
        "ownership": {
            "branches": [f"workflows/{step_id}"],
            "files": [f"research/{step_id}.json"],
        },
        "rollback": {"mode": "GIT_CHECKPOINT", "compensation_step_id": None},
    }


def _readiness(
    client: _Client,
    run_id: str,
    step_id: str,
    attempt: int,
    machine_id: str,
    expected: str,
    *,
    source_commit: str = SHA_A,
    approvals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return client.post(
        "/api/v1/workflows/readiness",
        "workflows.readiness",
        {
            "run_id": run_id,
            "step_id": step_id,
            "attempt": attempt,
            "current_source_commit": source_commit,
            "current_machine_id": machine_id,
            "task_sha256": hashlib.sha256(
                f"{run_id}:{step_id}:{attempt}".encode("utf-8")
            ).hexdigest(),
            "existing_task_sha256s": [],
            "required_evidence_refs": [],
            "available_evidence_refs": [],
            "approvals": approvals or [],
            "explicit_agent_id": None,
        },
        expected,
    )


def _approve_step(
    client: _Client,
    run_id: str,
    readiness_document: dict[str, Any],
    label: str,
) -> tuple[dict[str, Any], str]:
    readiness = readiness_document["data"]["readiness"]
    previewed = client.post(
        "/api/v1/workflows/approvals/preview",
        "workflows.approvals.preview",
        {
            "run_id": run_id,
            "readiness": readiness,
            "action": f"run attended {label}",
            "destination": f"research/{label}.json",
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=10)
            ).isoformat().replace("+00:00", "Z"),
        },
        readiness_document["object_version"],
    )
    preview = previewed["data"]["approval_preview"]
    approved = client.post(
        "/api/v1/workflows/approvals/approve",
        "workflows.approvals.approve",
        {
            "run_id": run_id,
            "preview": preview,
            "preview_operation_key": previewed["data"]["preview_operation_key"],
            "binding": {"kind": "STEP_APPROVAL", "readiness": readiness},
            "authorization_ref": f"attended:{label}",
            "approval_id": str(uuid4()),
        },
        previewed["object_version"],
    )
    pair = {"preview": preview, "approval": approved["data"]["approval"]["approval"]}
    return pair, approved["object_version"]


def _claim(
    client: _Client,
    run_id: str,
    readiness_document: dict[str, Any],
    agent_id: str,
    *,
    approvals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return client.post(
        "/api/v1/workflows/claims/create",
        "workflows.claims.create",
        {
            "run_id": run_id,
            "readiness": readiness_document["data"]["readiness"],
            "agent_id": agent_id,
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat().replace("+00:00", "Z"),
            "event_id": str(uuid4()),
            "approvals": approvals or [],
        },
        readiness_document["object_version"],
    )


def _start_session(
    client: _Client,
    run_id: str,
    claim_document: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    claim = claim_document["data"]["claim"]
    session_id = str(uuid4())
    started = client.post(
        "/api/v1/workflows/sessions/start",
        "workflows.sessions.start",
        {
            "run_id": run_id,
            "claim_event_id": claim["event"]["event_id"],
            "session_id": session_id,
            "total_units": 1,
            "current_source_commit": SHA_A,
            "current_input_sha256": claim["claim"]["input_sha256"],
            "event_id": str(uuid4()),
        },
        claim_document["object_version"],
    )
    return session_id, started


def _record_session(
    client: _Client,
    run_id: str,
    session_id: str,
    claim_document: dict[str, Any],
    expected: str,
    *,
    event_type: str,
    state: str,
    output_name: str | None,
) -> dict[str, Any]:
    claim = claim_document["data"]["claim"]
    completed = 1 if state == "COMPLETED" else 0
    outputs = []
    if output_name is not None:
        outputs = [{
            "name": output_name,
            "type": "application/json",
            "sha256": hashlib.sha256(f"{run_id}:{output_name}".encode()).hexdigest(),
            "evidence_refs": [f"evidence:{output_name}"],
        }]
    return client.post(
        "/api/v1/workflows/sessions/record",
        "workflows.sessions.record",
        {
            "run_id": run_id,
            "session_id": session_id,
            "event_type": event_type,
            "state": state,
            "progress": {"completed_units": completed, "total_units": 1},
            "resources": {
                "tokens_used": completed * 25,
                "cost_microunits": completed * 50,
                "peak_memory_mb": completed * 32,
            },
            "outputs": outputs,
            "current_source_commit": SHA_A,
            "current_input_sha256": claim["claim"]["input_sha256"],
            "event_id": str(uuid4()),
        },
        expected,
    )


def _canonical_state(client: _Client) -> dict[str, Any]:
    return {
        lane: client.get(f"/api/v1/{lane}")["data"]
        for lane in ("capture", "research", "memory", "knowledge", "workflows", "agents")
    }


def run_fixture(
    launch_command: list[str],
    vault: Path,
    work_root: Path,
    *,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Exercise one fresh foreground application, then reconstruct in another."""

    vault = Path(vault).resolve()
    work_root = Path(work_root).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    sentinels = {
        vault / "sources" / "m4-unrelated.sentinel": b"source sentinel\n",
        vault / "m4-unrelated.sentinel": b"root sentinel\n",
    }
    for path, payload in sentinels.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    first = _Process(launch_command, vault, environment)
    first_client = _Client(first.base_url, first.launch_url)
    first_cookie = dict(first_client.cookies)
    raw_text = "The installed HTTP launch color is amber.\n"
    preview = first_client.post(
        "/api/v1/capture/preview",
        "capture.preview",
        {
            "kind": "text",
            "filename": "m4-installed-evidence.md",
            "title": "Installed M4 evidence",
            "channel": "MARKDOWN",
            "media_type": "text/markdown",
            "privacy_class": "PROJECT_PRIVATE",
            "sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
            "text": raw_text,
        },
        "ABSENT",
    )
    _require(preview["data"]["requires_approval"] is True, "capture approval was inferred")
    admitted = first_client.post(
        "/api/v1/capture/admit",
        "capture.admit",
        {
            "preview_id": preview["data"]["preview_id"],
            "preview_digest": preview["object_version"],
        },
        preview["object_version"],
    )
    source_id = admitted["data"]["source_ids"][0]

    first_client.post(
        "/api/v1/research/workspaces/create",
        "research.workspaces.create",
        {"workspace_id": "research:m4-installed", "name": "Installed M4 research", "privacy_class": "PROJECT_PRIVATE"},
        "ABSENT",
    )
    added = first_client.post(
        "/api/v1/research/sources/add",
        "research.sources.add",
        {
            "workspace_id": "research:m4-installed",
            "source_id": source_id,
            "retrieval_policy": {"exact_first": True, "semantic_allowed": False, "max_results": 10, "max_quote_bytes": 2048},
        },
        "ABSENT",
    )
    source_set = added["object_version"]
    searched = first_client.post(
        "/api/v1/research/search",
        "research.search",
        {"workspace_id": "research:m4-installed", "source_set_digest": source_set, "query": "launch color", "limit": 5},
        source_set,
    )
    _require(bool(searched["data"]["citations"]), "exact research had no citation")
    asked = first_client.post(
        "/api/v1/research/ask",
        "research.ask",
        {"workspace_id": "research:m4-installed", "source_set_digest": source_set, "question": "What is the launch color?", "limit": 5},
        source_set,
    )
    _require(asked["data"]["provider_called"] is False, "research attempted a provider")
    first_client.post(
        "/api/v1/research/artifacts/create",
        "research.artifacts.create",
        {"workspace_id": "research:m4-installed", "source_set_digest": source_set, "artifact_type": "CITED_ANSWER", "title": "Installed answer", "research_result": asked["data"]},
        source_set,
    )
    first_client.post(
        "/api/v1/research/export",
        "research.export",
        {"workspace_id": "research:m4-installed", "source_set_digest": source_set, "filename": "m4-installed-research.tar.gz", "preview_digest": source_set},
        source_set,
    )

    citation = searched["data"]["citations"][0]
    now = _utc()
    event = {
        "schema_version": "hive.cognition-event.v1",
        "event_id": str(uuid4()),
        "tenant_id": TENANT,
        "project_id": PROJECT,
        "event_type": "PROJECT_EVENT",
        "privacy_class": "PROJECT_PRIVATE",
        "experience_scope": {"kind": "DOMAIN", "owner_id": PROJECT},
        "title": "Installed M4 memory proposal",
        "text": "",
        "structured_claims": [{
            "candidate_type": "DECISION",
            "subject_id": "project:HiveMind",
            "key": "m4.installed.decision",
            "value": "Review remains separate from promotion.",
            "narrative": "Review remains separate from promotion.",
            "proposed_action": "CREATE",
            "supersedes": None,
            "revokes": None,
        }],
        "evidence": [{
            "source_id": citation["source_id"],
            "anchor_id": citation["anchor_id"],
            "source_sha256": citation["source_sha256"],
            "normalized_sha256": citation["normalized_sha256"],
        }],
        "source_ref": f"operator-shell:{uuid4().hex}",
        "source_sha256": citation["source_sha256"],
        "occurred_at": now,
        "recorded_at": now,
    }
    proposed = first_client.post("/api/v1/memory/propose", "memory.propose", {"event": event}, "ABSENT")
    candidate = proposed["data"]["candidates"][0]
    candidate_sha = proposed["data"]["candidate_sha256"][0]
    reviewed = first_client.post(
        "/api/v1/memory/review",
        "memory.review",
        {"candidate_id": candidate["candidate_id"], "candidate_sha256": candidate_sha, "outcome": "APPROVED", "actor_id": "Owner", "authorization_ref": "attended:m4-installed", "corrections": []},
        candidate_sha,
    )
    promote_key = f"m4:{uuid4()}"
    promote_request_id = str(uuid4())
    promote_body = {"candidate_id": candidate["candidate_id"], "candidate_sha256": candidate_sha, "decision_id": reviewed["data"]["decision_id"], "decision_sha256": reviewed["object_version"]}
    promoted = first_client.post("/api/v1/memory/promote", "memory.promote", promote_body, reviewed["object_version"], key=promote_key, request_id=promote_request_id)
    replay = first_client.post("/api/v1/memory/promote", "memory.promote", promote_body, reviewed["object_version"], key=promote_key, request_id=promote_request_id)
    _require(promoted["changed"] is True and replay["changed"] is False, "promotion replay changed state")

    note = "---\ntype: moc\n---\n# Installed M4\n\n#local\n"
    note_preview = first_client.post(
        "/api/v1/knowledge/notes/preview",
        "knowledge.notes.preview",
        {"relative_path": "Installed M4.md", "content": note, "expected_sha256": None},
        "ABSENT",
    )
    first_client.post(
        "/api/v1/knowledge/notes/apply",
        "knowledge.notes.apply",
        {"preview_id": note_preview["data"]["preview_id"], "preview_sha256": note_preview["object_version"], "content": note, "approval_id": None, "approval_sha256": None},
        note_preview["object_version"],
    )
    graph_expected = first_client.get("/api/v1/knowledge")["data"][
        "action_versions"
    ]["knowledge.graph.rebuild"]
    graph = first_client.post(
        "/api/v1/knowledge/graph/rebuild",
        "knowledge.graph.rebuild",
        {"project_id": PROJECT, "relation": None, "tag": "local", "trust_state": None, "lifecycle_state": None, "node_id": None, "direction": None},
        graph_expected,
    )
    _require(bool(graph["data"]["nodes"]), "knowledge graph was empty")

    _register(first_client, "researcher", ["vault:search"])
    _register(first_client, "analyst", ["vault:search", "workflow:report"])
    first_client.post(
        "/api/v1/agents/tasks/submit",
        "agents.tasks.submit",
        {
            "creator_agent_id": "analyst",
            "assignee_agent_id": "researcher",
            "task_id": str(uuid4()),
            "operation": "research.request",
            "capability": "vault:search",
            "payload": {"request_kind": "SEARCH", "summary": "Find exact installed evidence without executing it."},
            "source_refs": [],
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        },
        "ABSENT",
    )

    definition = {
        "schema_version": "hive.workflow-definition.v1",
        "workflow_id": "workflow:m4-installed",
        "version": 1,
        "tenant_id": TENANT,
        "project_id": PROJECT,
        "title": "Installed protected workflow",
        "description": "Three attended steps with explicit protection.",
        "parent_digest": None,
        "steps": [
            _step("research", "vault:search", "machine:researcher", [], False),
            _step("analyze", "workflow:report", "machine:analyst", ["research"], True),
            _step("publish", "workflow:report", "machine:analyst", ["analyze"], False),
        ],
        "metadata": {"tags": ["installed", "m4"]},
    }
    definition_preview = first_client.post("/api/v1/workflows/definitions/preview", "workflows.definitions.preview", {"definition": definition}, "ABSENT")
    _require(definition_preview["data"]["execution_started"] is False, "workflow preview executed work")
    first_client.post("/api/v1/workflows/definitions/publish", "workflows.definitions.publish", {"definition": definition}, "ABSENT")
    run_id = str(uuid4())
    launched = first_client.post(
        "/api/v1/workflows/runs/launch",
        "workflows.runs.launch",
        {"workflow_id": "workflow:m4-installed", "version": 1, "run_id": run_id, "source_commit": SHA_A, "input_manifest_sha256": SHA_B, "event_id": str(uuid4()), "stale_after_seconds": 30, "max_concurrent_claims": 2},
        "ABSENT",
    )

    conflict_view = _readiness(
        first_client,
        run_id,
        "research",
        1,
        "machine:researcher",
        launched["object_version"],
        source_commit=SHA_B,
    )
    conflict_codes = {
        item["code"] for item in conflict_view["data"]["readiness"]["blockers"]
    }
    _require("STALE_SOURCE_COMMIT" in conflict_codes, "workflow conflict was not visible")
    recorded_conflict = first_client.post(
        "/api/v1/workflows/conflicts/record",
        "workflows.conflicts.record",
        {
            "run_id": run_id,
            "readiness": conflict_view["data"]["readiness"],
            "event_id": str(uuid4()),
            "attended_confirmation": True,
            "approvals": [],
        },
        conflict_view["object_version"],
    )

    research_ready = _readiness(
        first_client,
        run_id,
        "research",
        1,
        "machine:researcher",
        recorded_conflict["object_version"],
    )
    _require(research_ready["data"]["readiness"]["ready"] is True, "research was not ready")
    research_claim = _claim(first_client, run_id, research_ready, "researcher")
    research_session, research_started = _start_session(
        first_client, run_id, research_claim
    )
    research_completed = _record_session(
        first_client,
        run_id,
        research_session,
        research_claim,
        research_started["object_version"],
        event_type="STEP_COMPLETED",
        state="COMPLETED",
        output_name="raw",
    )

    analyze_blocked = _readiness(
        first_client,
        run_id,
        "analyze",
        1,
        "machine:analyst",
        research_completed["object_version"],
    )
    _require(
        "APPROVAL_REQUIRED"
        in {item["code"] for item in analyze_blocked["data"]["readiness"]["blockers"]},
        "protected step inferred approval",
    )
    approval_one, approval_one_version = _approve_step(
        first_client, run_id, analyze_blocked, "analyze-attempt-one"
    )
    analyze_ready_one = _readiness(
        first_client,
        run_id,
        "analyze",
        1,
        "machine:analyst",
        approval_one_version,
        approvals=[approval_one],
    )
    analyze_claim_one = _claim(
        first_client,
        run_id,
        analyze_ready_one,
        "analyst",
        approvals=[approval_one],
    )
    analyze_session_one, analyze_started_one = _start_session(
        first_client, run_id, analyze_claim_one
    )
    analyze_failed = _record_session(
        first_client,
        run_id,
        analyze_session_one,
        analyze_claim_one,
        analyze_started_one["object_version"],
        event_type="STEP_FAILED",
        state="FAILED",
        output_name=None,
    )
    retry_two = first_client.post(
        "/api/v1/workflows/retries/create",
        "workflows.retries.create",
        {"run_id": run_id, "step_id": "analyze", "failed_attempt": 1, "event_id": str(uuid4())},
        analyze_failed["object_version"],
    )
    _require(retry_two["data"]["retry"]["new_attempt"] == 2, "first retry was not exact")

    analyze_blocked_two = _readiness(
        first_client,
        run_id,
        "analyze",
        2,
        "machine:analyst",
        retry_two["object_version"],
    )
    approval_two, approval_two_version = _approve_step(
        first_client, run_id, analyze_blocked_two, "analyze-attempt-two"
    )
    analyze_ready_two = _readiness(
        first_client,
        run_id,
        "analyze",
        2,
        "machine:analyst",
        approval_two_version,
        approvals=[approval_two],
    )
    analyze_claim_two = _claim(
        first_client,
        run_id,
        analyze_ready_two,
        "analyst",
        approvals=[approval_two],
    )
    analyze_session_two, analyze_started_two = _start_session(
        first_client, run_id, analyze_claim_two
    )
    time.sleep(30.2)
    stale_previewed = first_client.post(
        "/api/v1/workflows/stale/preview",
        "workflows.stale.preview",
        {
            "run_id": run_id,
            "session_id": analyze_session_two,
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(minutes=10)
            ).isoformat().replace("+00:00", "Z"),
        },
        analyze_started_two["object_version"],
    )
    stale_preview = stale_previewed["data"]["stale_preview"]
    stale_approved = first_client.post(
        "/api/v1/workflows/approvals/approve",
        "workflows.approvals.approve",
        {
            "run_id": run_id,
            "preview": stale_preview,
            "preview_operation_key": stale_previewed["data"]["preview_operation_key"],
            "binding": {"kind": "STALE_RELEASE", "session_id": analyze_session_two},
            "authorization_ref": "attended:m4-stale-release",
            "approval_id": str(uuid4()),
        },
        stale_previewed["object_version"],
    )
    stale_released = first_client.post(
        "/api/v1/workflows/stale/apply",
        "workflows.stale.apply",
        {
            "run_id": run_id,
            "session_id": analyze_session_two,
            "preview": stale_preview,
            "approval": stale_approved["data"]["approval"]["approval"],
            "abandonment_event_id": str(uuid4()),
            "release_event_id": str(uuid4()),
        },
        stale_approved["object_version"],
    )
    retry_three = first_client.post(
        "/api/v1/workflows/retries/create",
        "workflows.retries.create",
        {"run_id": run_id, "step_id": "analyze", "failed_attempt": 2, "event_id": str(uuid4())},
        stale_released["object_version"],
    )
    _require(retry_three["data"]["retry"]["new_attempt"] == 3, "stale retry was not exact")

    analyze_blocked_three = _readiness(
        first_client,
        run_id,
        "analyze",
        3,
        "machine:analyst",
        retry_three["object_version"],
    )
    approval_three, approval_three_version = _approve_step(
        first_client, run_id, analyze_blocked_three, "analyze-attempt-three"
    )
    analyze_ready_three = _readiness(
        first_client,
        run_id,
        "analyze",
        3,
        "machine:analyst",
        approval_three_version,
        approvals=[approval_three],
    )
    analyze_claim_three = _claim(
        first_client,
        run_id,
        analyze_ready_three,
        "analyst",
        approvals=[approval_three],
    )
    analyze_session_three, analyze_started_three = _start_session(
        first_client, run_id, analyze_claim_three
    )
    analyze_completed = _record_session(
        first_client,
        run_id,
        analyze_session_three,
        analyze_claim_three,
        analyze_started_three["object_version"],
        event_type="STEP_COMPLETED",
        state="COMPLETED",
        output_name="analysis",
    )

    publish_ready = _readiness(
        first_client,
        run_id,
        "publish",
        1,
        "machine:analyst",
        analyze_completed["object_version"],
    )
    _require(publish_ready["data"]["readiness"]["ready"] is True, "publish was not ready")
    publish_claim = _claim(first_client, run_id, publish_ready, "analyst")
    publish_session, publish_started = _start_session(
        first_client, run_id, publish_claim
    )
    publish_completed = _record_session(
        first_client,
        run_id,
        publish_session,
        publish_claim,
        publish_started["object_version"],
        event_type="STEP_COMPLETED",
        state="COMPLETED",
        output_name="final",
    )
    complete_key = f"m4:{uuid4()}"
    complete_request_id = str(uuid4())
    complete_body = {"run_id": run_id, "event_id": str(uuid4()), "attended_confirmation": True}
    completed_run = first_client.post(
        "/api/v1/workflows/runs/complete",
        "workflows.runs.complete",
        complete_body,
        publish_completed["object_version"],
        key=complete_key,
        request_id=complete_request_id,
    )
    completed_replay = first_client.post(
        "/api/v1/workflows/runs/complete",
        "workflows.runs.complete",
        complete_body,
        publish_completed["object_version"],
        key=complete_key,
        request_id=complete_request_id,
    )
    _require(completed_run["changed"] is True, "workflow did not complete")
    _require(completed_replay["changed"] is False, "workflow replay mutated state")
    workflow_projection_one = first_client.get("/api/v1/workflows")
    workflow_projection_two = first_client.get("/api/v1/workflows")
    _require(
        workflow_projection_one["object_version"]
        == workflow_projection_two["object_version"]
        and workflow_projection_one["data"] == workflow_projection_two["data"],
        "workflow replay read changed state",
    )
    selected_run = next(
        item for item in workflow_projection_one["data"]["workflows"]
        if item["run"]["run_id"] == run_id
    )
    _require(selected_run["projection"]["state"] == "COMPLETED", "workflow was not completed")

    receipts = first_client.get("/api/v1/receipts", query={"lane": "memory", "limit": "20"})
    _require(receipts["data"]["filters"]["lane"] == "memory", "receipt filter was lost")
    _require(bool(receipts["data"]["receipts"]), "receipt filter found no evidence")

    settings = first_client.get("/api/v1/settings")
    snapshot_version = settings["data"]["action_versions"]["settings.snapshot"]
    snapshot = first_client.post(
        "/api/v1/settings/snapshot",
        "settings.snapshot",
        {"message": "M4 installed rollback checkpoint"},
        snapshot_version,
    )
    checkpoint = snapshot["data"]["checkpoint"]
    config_version = first_client.get("/api/v1/settings")["data"]["action_versions"]["settings.provider.preview"]
    provider_preview = first_client.post(
        "/api/v1/settings/provider/preview",
        "settings.provider.preview",
        {"mode": "retrieval-only", "model": None},
        config_version,
    )
    first_client.post(
        "/api/v1/settings/provider/apply",
        "settings.provider.apply",
        {"preview": provider_preview["data"]["preview"]},
        _digest(provider_preview["data"]["preview"]),
    )
    current_state = first_client.get("/api/v1/settings")["data"]["action_versions"]["settings.snapshot"]
    rollback_key = f"m4:{uuid4()}"
    rollback_request_id = str(uuid4())
    rollback_body = {
        "checkpoint": checkpoint,
        "approval": {
            "checkpoint_sha256": _digest(checkpoint),
            "expected_current_version": current_state,
            "confirmation": f"ROLLBACK {checkpoint['commit']}",
        },
    }
    rolled_back = first_client.post("/api/v1/settings/rollback", "settings.rollback", rollback_body, current_state, key=rollback_key, request_id=rollback_request_id)
    rollback_replay = first_client.post("/api/v1/settings/rollback", "settings.rollback", rollback_body, current_state, key=rollback_key, request_id=rollback_request_id)
    _require(rolled_back["changed"] is True and rollback_replay["changed"] is False, "rollback replay changed state")

    portable_version = first_client.get("/api/v1/settings")["data"]["action_versions"]["settings.snapshot"]
    bundle = work_root / "m4-portable.tar.gz"
    exported = first_client.post(
        "/api/v1/settings/export",
        "settings.export",
        {"destination": str(bundle), "expected_state_version": portable_version},
        portable_version,
    )["data"]["export"]
    reopened_target = work_root / "reopened-hive"
    first_client.post(
        "/api/v1/settings/reopen",
        "settings.reopen",
        {"bundle": str(bundle), "bundle_sha256": exported["sha256"], "manifest_sha256": exported["manifest_sha256"], "target": str(reopened_target)},
        "ABSENT",
    )

    canonical_before = _canonical_state(first_client)
    static_js = first_client.opener.open(
        urllib.request.Request(f"{first.base_url}/static/app.js", headers={"Sec-Fetch-Site": "same-origin"}), timeout=10
    ).read().decode("utf-8")
    for forbidden_storage in ("localStorage", "sessionStorage", "indexedDB", "serviceWorker"):
        _require(forbidden_storage not in static_js, f"browser persistence found: {forbidden_storage}")
    first.stop()

    with tarfile.open(bundle, "r:gz") as archive:
        names = [member.name for member in archive.getmembers()]
    _require(not any("operator-shell" in name for name in names), "export included browser/API state")
    _require(
        not any(".hive/runtime/" in name for name in names),
        "export included process runtime state",
    )
    for path, payload in sentinels.items():
        _require(path.read_bytes() == payload, f"unrelated sentinel changed: {path.name}")
    prime_bytes = b"\n".join(path.read_bytes() for path in sorted((vault / "prime").rglob("*")) if path.is_file())
    _require(raw_text.encode("utf-8") not in prime_bytes, "raw capture entered PRIME")
    runtime = vault / ".hive" / "runtime"
    if runtime.exists():
        _require(not any(path.suffix in {".pid", ".sock", ".socket", ".service"} for path in runtime.rglob("*")), "shutdown left service residue")

    second = _Process(launch_command, vault, environment)
    second_client = _Client(second.base_url, second.launch_url)
    _require(first_cookie != second_client.cookies, "browser session did not rotate")
    canonical_after = _canonical_state(second_client)
    _require(canonical_after == canonical_before, "second process reconstructed different canonical state")
    second.stop()

    return {
        "outcome": "VERIFIED",
        "second_process": True,
        "browser_persistence": False,
        "execution_performed": False,
        "service_installed": False,
        "session_rotated": True,
        "capture": True,
        "research": True,
        "memory": True,
        "knowledge": True,
        "protected_three_step_workflow": True,
        "workflow_conflict": True,
        "workflow_failure": True,
        "workflow_retry": True,
        "workflow_stale_release": True,
        "workflow_completion": True,
        "workflow_replay_read_only": True,
        "rollback": True,
        "export_reopen": True,
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    result = run_fixture([args.launcher], args.vault, args.work_root)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except VerificationError as exc:
        print(json.dumps({"outcome": "REFUSED", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
