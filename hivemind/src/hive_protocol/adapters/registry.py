"""Local adapter registry with platform checks and durable revocation state."""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from hive_protocol.adapters.base import HiveApplicationAdapter
from hive_protocol.adapters.manifest import AdapterManifest, load_manifest, manifest_digest
from hive_protocol.core import ProtocolError
from hive_protocol.storage import atomic_write_json, read_json, utc_now


@dataclass(frozen=True)
class RegisteredAdapter:
    adapter: HiveApplicationAdapter
    manifest: AdapterManifest
    manifest_digest: str
    compatible: bool


class AdapterRegistry:
    def __init__(
        self,
        runtime_root: Path,
        policy_root: Path,
        *,
        os_name: str,
        architecture: str,
        runtime: str,
        available_dependencies: Mapping[str, Mapping[str, str]] | None = None,
    ) -> None:
        for raw_root in (runtime_root.expanduser(), policy_root.expanduser()):
            for candidate in [raw_root, *raw_root.parents]:
                if candidate.is_symlink():
                    raise ProtocolError(
                        "ADAPTER_REGISTRY_ROOT_BOUNDARY",
                        "adapter registry paths may not contain symlinks",
                    )
        self.runtime_root = runtime_root.expanduser().resolve(strict=False)
        self.policy_root = policy_root.expanduser().resolve(strict=False)
        for directory in (self.runtime_root, self.policy_root):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if (
                directory.is_symlink()
                or directory.resolve() != directory
                or directory.stat().st_uid != os.geteuid()
            ):
                raise ProtocolError(
                    "ADAPTER_REGISTRY_ROOT_BOUNDARY",
                    "adapter registry directory is not owned and canonical",
                )
            os.chmod(directory, 0o700)
        self.registry_path = self.runtime_root / "registry.json"
        self.revocation_path = self.policy_root / "adapter-revocations.json"
        self.os_name = os_name
        self.architecture = architecture
        self.runtime = runtime
        self.available_dependencies = {
            name: dict(dependency)
            for name, dependency in (available_dependencies or {}).items()
        }
        self._entries: dict[str, RegisteredAdapter] = {}
        self._revocations = self._load_revocations()

    def _load_revocations(self) -> dict[str, dict[str, str]]:
        if not self.revocation_path.exists():
            return {}
        document = read_json(self.revocation_path)
        if document.get("schema_version") != "hive.adapter-revocations.v1":
            raise ProtocolError("ADAPTER_REVOCATIONS_INVALID", "unsupported revocation state")
        revocations = document.get("revocations")
        if not isinstance(revocations, dict):
            raise ProtocolError("ADAPTER_REVOCATIONS_INVALID", "revocations must be an object")
        return copy.deepcopy(revocations)

    def _is_compatible(self, manifest: AdapterManifest) -> bool:
        return any(
            platform == {
                "os": self.os_name,
                "architecture": self.architecture,
                "runtime": self.runtime,
            }
            for platform in manifest.platforms
        )

    def _write_registry(self) -> None:
        atomic_write_json(
            self.registry_path,
            {
                "schema_version": "hive.adapter-registry.v1",
                "adapters": [
                    {
                        "adapter_id": entry.manifest.adapter_id,
                        "version": entry.manifest.version,
                        "manifest_digest": entry.manifest_digest,
                        "compatible": entry.compatible,
                    }
                    for entry in sorted(
                        self._entries.values(), key=lambda item: item.manifest.adapter_id
                    )
                ],
            },
            mode=0o600,
        )

    def register(
        self, adapter: HiveApplicationAdapter, manifest_document: dict[str, Any]
    ) -> RegisteredAdapter:
        manifest = load_manifest(manifest_document)
        if manifest.adapter_id in self._entries:
            raise ProtocolError(
                "ADAPTER_ALREADY_REGISTERED",
                "adapter ID is already registered",
            )
        if not isinstance(adapter, HiveApplicationAdapter):
            raise ProtocolError(
                "ADAPTER_PROTOCOL_INVALID",
                "adapter does not implement the application adapter protocol",
            )
        compatible = self._is_compatible(manifest)
        if not compatible:
            raise ProtocolError(
                "ADAPTER_PLATFORM_INCOMPATIBLE",
                "adapter does not support this OS, architecture, and runtime",
            )
        for dependency in manifest.dependencies:
            available = self.available_dependencies.get(dependency["name"])
            if available != {
                "version": dependency["version"],
                "sha256": dependency["sha256"],
                "license": dependency["license"],
            }:
                raise ProtocolError(
                    "ADAPTER_DEPENDENCY_UNAVAILABLE",
                    "adapter dependency is missing or does not match its exact pin",
                )
        entry = RegisteredAdapter(
            adapter=adapter,
            manifest=manifest,
            manifest_digest=manifest_digest(manifest_document),
            compatible=compatible,
        )
        self._entries[manifest.adapter_id] = entry
        self._write_registry()
        return entry

    def require(self, adapter_id: str, version: str) -> RegisteredAdapter:
        entry = self.require_current(adapter_id)
        if entry.manifest.version != version:
            raise ProtocolError(
                "ADAPTER_VERSION_MISMATCH",
                "registered adapter version does not match the request",
            )
        return entry

    def require_current(self, adapter_id: str) -> RegisteredAdapter:
        """Return the exact registered adapter after revocation/platform checks."""
        entry = self._entries.get(adapter_id)
        if entry is None:
            raise ProtocolError("ADAPTER_NOT_REGISTERED", "adapter is not registered")
        if adapter_id in self._revocations:
            raise ProtocolError("ADAPTER_REVOKED", "adapter has been revoked")
        if not entry.compatible:
            raise ProtocolError(
                "ADAPTER_PLATFORM_INCOMPATIBLE",
                "adapter is not compatible with this runtime",
            )
        return entry

    def revoke(self, adapter_id: str, *, reason: str, authorization_ref: str) -> None:
        if adapter_id not in self._entries:
            raise ProtocolError("ADAPTER_NOT_REGISTERED", "adapter is not registered")
        if not reason or not authorization_ref:
            raise ProtocolError(
                "ADAPTER_REVOCATION_INVALID",
                "reason and authorization reference are required",
            )
        self._revocations[adapter_id] = {
            "reason": reason,
            "authorization_ref": authorization_ref,
            "revoked_at": utc_now(),
        }
        atomic_write_json(
            self.revocation_path,
            {
                "schema_version": "hive.adapter-revocations.v1",
                "revocations": self._revocations,
            },
            mode=0o600,
        )

    def is_revoked(self, adapter_id: str) -> bool:
        return adapter_id in self._revocations

    def list_status(self) -> list[dict[str, Any]]:
        status: list[dict[str, Any]] = []
        for adapter_id, entry in sorted(self._entries.items()):
            try:
                reported = entry.adapter.health()
                health = {
                    "status": str(reported.get("status", "UNKNOWN")),
                    "evidence": copy.deepcopy(reported.get("evidence", [])),
                }
            except Exception as exc:  # pragma: no cover - defensive adapter boundary
                health = {"status": "DEGRADED", "evidence": [], "reason": type(exc).__name__}
            status.append(
                {
                    "adapter_id": adapter_id,
                    "version": entry.manifest.version,
                    "manifest_digest": entry.manifest_digest,
                    "compatible": entry.compatible,
                    "revoked": adapter_id in self._revocations,
                    "health": health,
                }
            )
        return status
