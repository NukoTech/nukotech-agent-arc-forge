"""Product entry points for the local attended Forge admission bridge."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from hive_protocol.core import ProtocolError, load_private_key, load_public_key, public_key_id
from hive_protocol.adapters.manifest import load_manifest, manifest_digest
from hive_protocol.loadouts import LoadoutManager
from hive_protocol.loadouts.artifacts import json_object, read_bounded, refuse_windows
from hive_protocol.product.scope import ADAPTER_PROJECT_ID, TENANT_ID
from hive_protocol.product.agent_adapter import (
    ADAPTER_OPERATOR_IDENTITY, _platform_identity, _product_adapter_manifests, product_adapter_services,
)


class _ReadOnlyAdapterRegistry:
    def __init__(self, root: Path):
        self.root = root
        self.runtime = "python>=3.11"
        self.manifests = _product_adapter_manifests()

    def _load_revocations(self):
        path = self.root / ".hive/application-adapters/policy/adapter-revocations.json"
        if not path.exists() and not path.is_symlink():
            return {}
        document = json_object(read_bounded(path))
        if document.get("schema_version") != "hive.adapter-revocations.v1" or not isinstance(document.get("revocations"), dict):
            raise ProtocolError("ADAPTER_REVOCATIONS_INVALID", "adapter revocation state is invalid")
        return document["revocations"]

    def require(self, adapter_id, version):
        registry = json_object(read_bounded(self.root / ".hive/runtime/application-adapters/registry.json"))
        if registry.get("schema_version") != "hive.adapter-registry.v1" or not isinstance(registry.get("adapters"), list):
            raise ProtocolError("ADAPTER_REGISTRY_INVALID", "adapter registry is unavailable")
        document = self.manifests.get(adapter_id)
        if document is None:
            raise ProtocolError("ADAPTER_NOT_REGISTERED", "referenced adapter is not available in this runtime")
        manifest = load_manifest(document)
        expected = {"adapter_id": adapter_id, "version": version,
                    "manifest_digest": manifest_digest(document), "compatible": True}
        if manifest.version != version or expected not in registry["adapters"]:
            raise ProtocolError("ADAPTER_VERSION_MISMATCH", "registered adapter pin differs from the installed runtime")
        os_name, architecture = _platform_identity()
        if {"os": os_name, "architecture": architecture, "runtime": self.runtime} not in manifest.platforms:
            raise ProtocolError("ADAPTER_PLATFORM_INCOMPATIBLE", "referenced adapter is incompatible with this native host")
        if adapter_id in self._load_revocations():
            raise ProtocolError("ADAPTER_REVOKED", "referenced adapter was revoked")
        return SimpleNamespace(manifest=manifest, manifest_digest=expected["manifest_digest"])


def loadout_services(root: Path, *, read_only: bool = False) -> LoadoutManager:
    from hive_protocol.product.workspace import HiveWorkspace

    refuse_windows()
    # Bring your own key: every signature uses the operator's own local Ed25519
    # identities under <hive>/.hive/keys/application-adapters. None ship with
    # HiveMind or with an Arc package.
    raw = root.expanduser().absolute()
    workspace = HiveWorkspace.open(raw)
    # The attended bridge signs only for its configured authority scope
    # (HIVE_TENANT_ID / HIVE_PROJECT_ID, default local-user / HiveMind).
    # Refuse another configured Hive scope before creating keys, grants or
    # loadout state; configuration never migrates existing signed history.
    if workspace.scope() != {"tenant_id": TENANT_ID, "project_id": ADAPTER_PROJECT_ID}:
        raise ProtocolError(
            "LOADOUT_SCOPE_UNSUPPORTED",
            "this Hive's tenant/project scope differs from the configured attended authority",
        )
    # A legacy Hive without explicit scope fields follows the setting, so also
    # refuse when established signed loadout history names another project.
    # The signature is verified later; this read only refuses early.
    state_path = raw / ".hive" / "loadouts" / "state.json"
    if state_path.exists() or state_path.is_symlink():
        recorded = json_object(read_bounded(state_path)).get("target")
        if not isinstance(recorded, dict) or recorded.get("project_id") != ADAPTER_PROJECT_ID:
            raise ProtocolError(
                "LOADOUT_SCOPE_UNSUPPORTED",
                "established loadout history was signed for another configured project",
            )
    # An established signed loadout history must never bootstrap replacement
    # signing identities when any existing product key disappears.
    if (raw / ".hive" / "loadouts").exists():
        key_root = raw / ".hive" / "keys" / "application-adapters"
        for label in ("attended-request", "attended-approver", "runtime-result"):
            for suffix in ("private.pem", "public.pem"):
                path = key_root / f"{label}.{suffix}"
                if path.is_symlink() or not path.is_file():
                    raise ProtocolError("LOADOUT_SIGNING_KEY_MISSING", "existing loadout signing identity is unavailable")
    if read_only:
        key_root = raw / ".hive/keys/application-adapters"
        keys = []
        for label in ("attended-request", "attended-approver", "runtime-result"):
            private = load_private_key(key_root / f"{label}.private.pem")
            public = load_public_key(key_root / f"{label}.public.pem")
            if public_key_id(private.public_key()) != public_key_id(public):
                raise ProtocolError("LOADOUT_SIGNING_KEY_MISMATCH", "stored loadout key pair differs")
            keys.append(private)
        registry = _ReadOnlyAdapterRegistry(raw)
        request_key, approver_key, state_key = keys
    else:
        services = product_adapter_services(raw)
        registry = services.registry
        request_key, approver_key, state_key = services.request_key, services.approver_key, services.runtime_key
    os_name, architecture = _platform_identity()
    target = {key: ADAPTER_OPERATOR_IDENTITY[key] for key in
              ("persona_id", "surface_id", "machine_id", "project_id")}
    target.update(os=os_name, architecture=architecture, runtime=registry.runtime)
    return LoadoutManager(raw, target=target, registry=registry,
        request_key=request_key, approver_key=approver_key,
        state_key=state_key, approver_identity=ADAPTER_OPERATOR_IDENTITY, read_only=read_only)


def _source(source: Mapping[str, str] | None) -> dict[str, Path] | None:
    if source is None:
        return None
    expected = {"package", "checksum_manifest", "recipe", "registry", "authorization"}
    if (not isinstance(source, Mapping) or set(source) != expected or
            any(not isinstance(value, str) or not value for value in source.values())):
        raise ProtocolError("LOADOUT_SOURCE_INVALID", "five exact Arc artifact and input paths are required")
    return {name: Path(value).expanduser().absolute() for name, value in source.items()}


def plan_loadout(root: Path, *, operation: str, loadout_id: str, authorization_ref: str,
                 source: Mapping[str, str] | None = None,
                 adapter_references: list[dict[str, Any]] | None = None,
                 version_digest: str | None = None, reason: str = "attended operator request",
                 ttl_seconds: int = 900) -> dict[str, Any]:
    return loadout_services(root).plan(operation, loadout_id, authorization_ref=authorization_ref,
        source=_source(source), adapter_references=adapter_references,
        version_digest=version_digest, reason=reason, ttl_seconds=ttl_seconds)


def approve_loadout(root: Path, plan: Mapping[str, Any]) -> dict[str, Any]:
    return loadout_services(root).approve(plan)


def apply_loadout(root: Path, plan: Mapping[str, Any], approval: Mapping[str, Any], *,
                  source: Mapping[str, str] | None = None) -> dict[str, Any]:
    return loadout_services(root).apply(plan, approval, source=_source(source))


def loadout_status(root: Path) -> list[dict[str, Any]]:
    refuse_windows()
    state_path = root.expanduser().absolute() / ".hive/loadouts/state.json"
    if not state_path.exists() and not state_path.is_symlink():
        return []
    return loadout_services(root, read_only=True).status()


def read_loadout(root: Path, loadout_id: str) -> dict[str, str]:
    return loadout_services(root, read_only=True).read_active(loadout_id)


def read_loadout_context(root: Path, loadout_id: str) -> dict[str, Any]:
    return loadout_services(root, read_only=True).context_snapshot(loadout_id)


def verify_loadout_context(root: Path, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return loadout_services(root, read_only=True).verify_context(snapshot)
