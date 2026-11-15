"""Attended browser bridge to signed declarative loadout lifecycle operations."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import re
from pathlib import Path
from typing import Any, Mapping

from hive_protocol.core import ProtocolError, document_digest, public_key_id, sign_document, verify_document
from hive_protocol.storage import atomic_write_bytes, atomic_write_json, ensure_owned_directory, read_json, require_no_symlink_components

from ..loadout_adapter import loadout_services, loadout_status
from ..shell_contracts import OperatorRequest, RouteContract
from ..workspace import HiveWorkspace


MAX_STAGE_BYTES = 16 * 1024 * 1024
STAGE_BODY_BYTES = 23 * 1024 * 1024
_SHA = re.compile(r"^[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ROLES = {"package": 16 * 1024 * 1024, "checksum_manifest": 128 * 1024,
          "recipe": 2 * 1024 * 1024, "registry": 2 * 1024 * 1024, "arc_authorization": 128 * 1024}
_ACTIONS = frozenset({"loadouts.stage", "loadouts.plan", "loadouts.approve", "loadouts.apply"})


class LoadoutLane:
    def __init__(self, workspace: HiveWorkspace, *, tenant_id: str, project_ids: frozenset[str], now: Any) -> None:
        self.workspace, self.root = workspace, workspace.root
        self.tenant_id, self.project_ids, self.now = tenant_id, project_ids, now
        self.runtime = workspace.runtime / "operator-shell" / "loadouts"

    @staticmethod
    def supports(action: str) -> bool:
        return action in _ACTIONS

    def _scope(self, request: OperatorRequest) -> None:
        scope = self.workspace.scope()
        if request.tenant_id != self.tenant_id or request.project_id not in self.project_ids or request.project_id != scope["project_id"]:
            raise ProtocolError("LOADOUT_SCOPE_DENIED", "loadout is outside the current local project")

    def _path(self, kind: str, identifier: str, *, create: bool = False) -> Path:
        if not isinstance(identifier, str) or _SHA.fullmatch(identifier) is None:
            raise ProtocolError("LOADOUT_BINDING_INVALID", "loadout binding must be an exact digest")
        directory = self.runtime / kind
        if create:
            ensure_owned_directory(self.root, directory, code="OPERATOR_RUNTIME_BOUNDARY", detail="loadout staging directory is unsafe")
        path = directory / f"{identifier}.json"
        require_no_symlink_components(self.root, path, code="OPERATOR_RUNTIME_BOUNDARY", detail="loadout staging path contains a symlink")
        return path

    def _manager(self):
        return loadout_services(self.root)

    def _read_record(self, kind: str, identifier: str, project_id: str) -> dict[str, Any]:
        path = self._path(kind, identifier)
        if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ProtocolError("LOADOUT_BINDING_MISSING", "exact staged loadout record is unavailable")
        record = read_json(path)
        manager = self._manager()
        verify_document(record, {public_key_id(manager.state_key.public_key()): manager.state_key.public_key()})
        if (set(record) != {"schema_version", "kind", "identifier", "tenant_id", "project_id", "document", "signature"}
                or record["schema_version"] != "hive.operator-loadout-record.v1" or record["kind"] != kind
                or record["identifier"] != identifier or record["tenant_id"] != self.tenant_id
                or record["project_id"] != project_id or not isinstance(record["document"], dict)):
            raise ProtocolError("LOADOUT_BINDING_INVALID", "staged loadout record changed identity or scope")
        return record["document"]

    def _save_record(self, kind: str, identifier: str, project_id: str, document: Mapping[str, Any]) -> None:
        path = self._path(kind, identifier, create=True)
        if path.exists():
            if self._read_record(kind, identifier, project_id) != document:
                raise ProtocolError("LOADOUT_BINDING_CONFLICT", "immutable staged loadout record is occupied")
            return
        record = sign_document({"schema_version": "hive.operator-loadout-record.v1", "kind": kind,
            "identifier": identifier, "tenant_id": self.tenant_id, "project_id": project_id,
            "document": copy.deepcopy(dict(document))}, self._manager().state_key)
        atomic_write_json(path, record, mode=0o600)

    def _stage_bytes(self, request: OperatorRequest) -> dict[str, bytes]:
        if set(request.input) != {"files"} or not isinstance(request.input["files"], list) or len(request.input["files"]) != len(_ROLES):
            raise ProtocolError("LOADOUT_UPLOAD_INVALID", "choose all five exact package files")
        files: dict[str, bytes] = {}
        total = 0
        for item in request.input["files"]:
            if not isinstance(item, dict) or set(item) != {"role", "sha256", "data_b64"}:
                raise ProtocolError("LOADOUT_UPLOAD_INVALID", "loadout uploads cannot contain filesystem paths")
            role = item["role"]
            if role not in _ROLES or role in files or not isinstance(item["data_b64"], str) or not isinstance(item["sha256"], str):
                raise ProtocolError("LOADOUT_UPLOAD_INVALID", "loadout upload roles and hashes must be exact")
            if len(item["data_b64"]) > ((_ROLES[role] + 2) // 3) * 4:
                raise ProtocolError("LOADOUT_UPLOAD_LIMIT", "loadout file exceeds its browser upload limit")
            try:
                payload = base64.b64decode(item["data_b64"], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ProtocolError("LOADOUT_UPLOAD_ENCODING", "loadout file encoding is invalid") from exc
            total += len(payload)
            if len(payload) > _ROLES[role] or total > MAX_STAGE_BYTES:
                raise ProtocolError("LOADOUT_UPLOAD_LIMIT", "five loadout files must total no more than 16 MiB")
            if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                raise ProtocolError("LOADOUT_UPLOAD_HASH_MISMATCH", "selected loadout bytes changed")
            files[role] = payload
        return files

    def _stage_source(self, stage_id: str, stage_digest: str, project_id: str) -> dict[str, Path]:
        stage = self._read_record("stages", stage_id, project_id)
        if document_digest(stage) != stage_digest or set(stage) != {"stage_id", "files"} or stage["stage_id"] != stage_id or set(stage["files"]) != set(_ROLES):
            raise ProtocolError("LOADOUT_STAGE_CHANGED", "loadout stage differs from the exact selected files")
        source = {}
        for role, metadata in stage["files"].items():
            path = self.runtime / "uploads" / stage_id / role
            require_no_symlink_components(self.root, path, code="OPERATOR_RUNTIME_BOUNDARY", detail="staged loadout file contains a symlink")
            if not path.is_file() or path.stat().st_size != metadata["size_bytes"] or path.stat().st_size > _ROLES[role]:
                raise ProtocolError("LOADOUT_STAGE_CHANGED", "staged loadout file changed")
            payload = path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != metadata["sha256"]:
                raise ProtocolError("LOADOUT_STAGE_CHANGED", "staged loadout bytes changed")
            source["authorization" if role == "arc_authorization" else role] = path
        return source

    def status(self, project_id: str) -> list[dict[str, Any]]:
        if project_id != self.workspace.scope()["project_id"]:
            return []
        state = self.root / ".hive" / "loadouts" / "state.json"
        require_no_symlink_components(self.root, state, code="LOADOUT_ROOT_BOUNDARY", detail="loadout state contains a symlink")
        return loadout_status(self.root) if state.exists() else []

    def object_key(self, route: RouteContract, request: OperatorRequest) -> str:
        return f"{request.project_id}:loadouts:{request.action}:{document_digest(request.input)}"

    def _plan_record(self, request: OperatorRequest) -> dict[str, Any]:
        record = self._read_record("plans", request.input.get("plan_digest"), request.project_id)
        if document_digest(record["plan"]) != request.input["plan_digest"]:
            raise ProtocolError("LOADOUT_BINDING_INVALID", "signed plan differs from selected digest")
        return record

    def _validate(self, request: OperatorRequest) -> None:
        self._scope(request)
        if request.action == "loadouts.stage":
            self._stage_bytes(request)
        elif request.action == "loadouts.plan":
            if set(request.input) != {"operation", "loadout_id", "stage_id", "stage_digest", "version_digest", "authorization_ref", "reason"}:
                raise ProtocolError("LOADOUT_PLAN_INVALID", "loadout planning inputs are not exact")
            if request.input["operation"] not in {"admit", "revoke", "rollback", "uninstall"} or not isinstance(request.input["loadout_id"], str) or _ID.fullmatch(request.input["loadout_id"]) is None:
                raise ProtocolError("LOADOUT_PLAN_INVALID", "loadout operation or name is invalid")
            if not isinstance(request.input["authorization_ref"], str) or not request.input["authorization_ref"].strip() or not isinstance(request.input["reason"], str) or not request.input["reason"].strip():
                raise ProtocolError("LOADOUT_PLAN_INVALID", "provide an authorization reference and reason")
            if request.input["operation"] == "admit":
                self._stage_source(request.input["stage_id"], request.input["stage_digest"], request.project_id)
            elif request.input["stage_id"] is not None or request.input["stage_digest"] is not None:
                raise ProtocolError("LOADOUT_PLAN_INVALID", "lifecycle changes do not accept new source files")
        else:
            fields = {"plan_digest", "confirmation"} | ({"approval_digest"} if request.action == "loadouts.apply" else set())
            if set(request.input) != fields:
                raise ProtocolError("LOADOUT_APPROVAL_INVALID", "loadout approval or application inputs are not exact")
            record = self._plan_record(request)
            plan = record["plan"]
            verb = "APPROVE" if request.action == "loadouts.approve" else "APPLY"
            if request.input["confirmation"] != f"{verb} {plan['operation'].upper()} {plan['loadout_id']}":
                raise ProtocolError("LOADOUT_APPROVAL_INVALID", "type the exact loadout action and name")
            if request.action == "loadouts.apply":
                approval = self._read_record("approvals", request.input["approval_digest"], request.project_id)
                if document_digest(approval) != request.input["approval_digest"] or approval.get("plan_digest") != request.input["plan_digest"]:
                    raise ProtocolError("LOADOUT_APPROVAL_INVALID", "approval differs from the exact selected loadout plan")

    def current_version(self, route: RouteContract, request: OperatorRequest) -> str:
        self._scope(request)
        path = self._path("commands", request.digest)
        if path.exists():
            return self._read_record("commands", request.digest, request.project_id)["object_version"]
        self._validate(request)
        if request.action in {"loadouts.stage", "loadouts.plan"}:
            return "ABSENT"
        return request.input["approval_digest"] if request.action == "loadouts.apply" else request.input["plan_digest"]

    def mutate(self, route: RouteContract, request: OperatorRequest, *, operation_key: str) -> Mapping[str, Any]:
        existing = self._path("commands", request.digest)
        if existing.exists():
            result = self._read_record("commands", request.digest, request.project_id)
            if result["operation_key"] != operation_key or result["request_digest"] != request.digest:
                raise ProtocolError("LOADOUT_REPLAY_CONFLICT", "loadout operation binding changed")
            return result
        self._validate(request)
        action = request.action
        if action == "loadouts.stage":
            files = self._stage_bytes(request)
            descriptors = {role: {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)} for role, data in files.items()}
            identifier = document_digest({"tenant_id": request.tenant_id, "project_id": request.project_id, "files": descriptors})
            directory = self.runtime / "uploads" / identifier
            ensure_owned_directory(self.root, directory, code="OPERATOR_RUNTIME_BOUNDARY", detail="loadout upload directory is unsafe")
            for role, data in files.items():
                path = directory / role
                require_no_symlink_components(self.root, path, code="OPERATOR_RUNTIME_BOUNDARY", detail="loadout upload path is unsafe")
                if path.exists():
                    if not path.is_file() or path.read_bytes() != data:
                        raise ProtocolError("LOADOUT_STAGE_CHANGED", "owned upload target is occupied")
                else:
                    atomic_write_bytes(path, data, mode=0o600)
            stage = {"stage_id": identifier, "files": descriptors}
            self._save_record("stages", identifier, request.project_id, stage)
            version = document_digest(stage)
            data, outcome, changed = {**stage, "stage_digest": version, "status": "Files staged for review"}, "OK", False
        elif action == "loadouts.plan":
            source = self._stage_source(request.input["stage_id"], request.input["stage_digest"], request.project_id) if request.input["operation"] == "admit" else None
            plan = self._manager().plan(request.input["operation"], request.input["loadout_id"], source=source,
                authorization_ref=request.input["authorization_ref"], version_digest=request.input["version_digest"], reason=request.input["reason"], adapter_references=[])
            version = document_digest(plan)
            self._save_record("plans", version, request.project_id, {"plan": plan, "stage_id": request.input["stage_id"], "stage_digest": request.input["stage_digest"]})
            data, outcome, changed = {"plan": plan, "plan_digest": version, "status": "Ready for separate approval"}, "OK", False
        elif action == "loadouts.approve":
            plan = self._plan_record(request)["plan"]
            approval = self._manager().approve(plan)
            version = document_digest(approval)
            self._save_record("approvals", version, request.project_id, approval)
            data, outcome, changed = {"approval": approval, "approval_digest": version, "plan_digest": request.input["plan_digest"], "status": "Approved; waiting for application"}, "OK", False
        else:
            record = self._plan_record(request)
            approval = self._read_record("approvals", request.input["approval_digest"], request.project_id)
            manager = self._manager()
            committed = request.input["plan_digest"] in manager._read_state()["completed"]
            source = self._stage_source(record["stage_id"], record["stage_digest"], request.project_id) if record["plan"]["operation"] == "admit" and not committed else None
            receipt = manager.apply(record["plan"], approval, source=source)
            version = document_digest(receipt)
            data, outcome, changed = {"receipt": receipt, "status": "Applied", "loadouts": self.status(request.project_id)}, "APPLIED", True
        result = {"operation_key": operation_key, "request_digest": request.digest, "outcome": outcome,
            "reason_code": None, "object_version": version, "changed": changed, "data": data,
            "technical_evidence": [{"kind": "loadout-record", "ref": f"loadout:{action}:{version}", "sha256": version}]}
        self._save_record("commands", request.digest, request.project_id, result)
        return result

    def recover(self, route: RouteContract, request: OperatorRequest, *, operation_key: str) -> Mapping[str, Any] | None:
        # Staging is content-addressed, plans/approvals have no installation effects,
        # and the native manager replays a committed application by signed plan digest.
        return self.mutate(route, request, operation_key=operation_key)
