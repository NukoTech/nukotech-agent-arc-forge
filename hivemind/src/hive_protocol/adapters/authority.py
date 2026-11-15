"""Independent, signer-bound attended grants for application adapters."""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hive_protocol.adapters.policy import InvocationContext
from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, sign_document, verify_document
from hive_protocol.storage import atomic_write_json, read_json


_SAFE_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_GRANT_FIELDS = {
    "schema_version",
    "signer_key_id",
    "identity",
    "project_id",
    "authorization_ref",
    "adapters",
    "signature",
}
_IDENTITY_FIELDS = {
    "persona_id",
    "surface_id",
    "machine_id",
    "project_id",
    "app_actor",
}
_ADAPTER_GRANT_FIELDS = {
    "capabilities",
    "permissions",
    "data_classifications",
    "network_destinations",
    "credential_references",
}


def _string_tuple(value: Any, *, field: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not all(isinstance(item, str) and item for item in value)
        or len(value) != len(set(value))
        or value != sorted(value)
    ):
        raise ProtocolError(
            "ADAPTER_AUTHORITY_GRANT_INVALID",
            f"authority grant field {field} must be a sorted unique string list",
        )
    return tuple(value)


@dataclass(frozen=True)
class AttendedGrant:
    signer_key_id: str
    identity: dict[str, str]
    project_id: str
    authorization_ref: str
    adapter_id: str
    capabilities: tuple[str, ...]
    permissions: tuple[str, ...]
    data_classifications: tuple[str, ...]
    network_destinations: tuple[str, ...]
    credential_references: tuple[str, ...]

    def invocation_context(self) -> InvocationContext:
        return InvocationContext(
            project_id=self.project_id,
            authorization_ref=self.authorization_ref,
            identity=copy.deepcopy(self.identity),
            granted_capabilities=frozenset(self.capabilities),
            granted_permissions=frozenset(self.permissions),
            allowed_data_classifications=frozenset(self.data_classifications),
            allowed_network_destinations=frozenset(self.network_destinations),
            available_credential_references=frozenset(self.credential_references),
        )


class AdapterAuthorityStore:
    """Resolve request signers through a policy document independent of requests."""

    def __init__(
        self,
        root: Path,
        trusted_policy_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        raw_root = root.expanduser()
        for candidate in [raw_root, *raw_root.parents]:
            if candidate.is_symlink():
                raise ProtocolError(
                    "ADAPTER_AUTHORITY_ROOT_BOUNDARY",
                    "adapter authority path may not contain symlinks",
                )
        self.root = raw_root.resolve(strict=False)
        self.trusted_policy_keys = dict(trusted_policy_keys)

    def _require_root(self) -> None:
        if self.root.is_symlink():
            raise ProtocolError(
                "ADAPTER_AUTHORITY_ROOT_BOUNDARY",
                "adapter authority root changed identity",
            )
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            self.root.is_symlink()
            or self.root.resolve() != self.root
            or self.root.stat().st_uid != os.geteuid()
        ):
            raise ProtocolError(
                "ADAPTER_AUTHORITY_ROOT_BOUNDARY",
                "adapter authority root is not owned and canonical",
            )
        os.chmod(self.root, 0o700)

    def _path(self, signer_key_id: str) -> Path:
        if not _SAFE_KEY_ID.fullmatch(signer_key_id):
            raise ProtocolError(
                "ADAPTER_AUTHORITY_GRANT_INVALID", "signer key ID is not path safe"
            )
        return self.root / f"{signer_key_id.replace(':', '-')}.json"

    def ensure_attended_grant(
        self,
        *,
        signer_key_id: str,
        identity: Mapping[str, str],
        project_id: str,
        authorization_ref: str,
        manifests: Mapping[str, Mapping[str, Any]],
        policy_signing_key: Ed25519PrivateKey,
    ) -> None:
        path = self._path(signer_key_id)
        self._require_root()
        adapter_grants: dict[str, dict[str, list[str]]] = {}
        for adapter_id, manifest in sorted(manifests.items()):
            adapter_grants[adapter_id] = {
                "capabilities": sorted(manifest["capability_ids"]),
                "permissions": sorted(manifest["required_permissions"]),
                "data_classifications": sorted(
                    manifest["accepted_data_classifications"]
                ),
                "network_destinations": sorted(manifest["network_destinations"]),
                "credential_references": sorted(manifest["credential_references"]),
            }
        document = {
            "schema_version": "hive.adapter-attended-grant.v1",
            "signer_key_id": signer_key_id,
            "identity": dict(identity),
            "project_id": project_id,
            "authorization_ref": authorization_ref,
            "adapters": adapter_grants,
        }
        reject_credential_values(document, location="adapter attended grant")
        if path.exists():
            existing = self._load_document(signer_key_id)
            existing_body = copy.deepcopy(existing)
            existing_body.pop("signature", None)
            if existing_body != document:
                raise ProtocolError(
                    "ADAPTER_AUTHORITY_GRANT_MISMATCH",
                    "existing attended authority differs from the requested exact scope",
                )
            return
        signed = sign_document(document, policy_signing_key)
        self._validate_document(signed, expected_signer_key_id=signer_key_id)
        atomic_write_json(path, signed, mode=0o600)

    def _load_document(self, signer_key_id: str) -> dict[str, Any]:
        path = self._path(signer_key_id)
        if not path.exists():
            raise ProtocolError(
                "ADAPTER_AUTHORITY_GRANT_MISSING",
                "the verified request signer has no attended authority grant",
            )
        document = read_json(path)
        self._validate_document(document, expected_signer_key_id=signer_key_id)
        return document

    def _validate_document(
        self, document: Mapping[str, Any], *, expected_signer_key_id: str
    ) -> None:
        try:
            reject_credential_values(
                document,
                location="adapter attended grant",
                verified_by=self.trusted_policy_keys,
            )
            if set(document) != _GRANT_FIELDS:
                raise ProtocolError(
                    "ADAPTER_AUTHORITY_GRANT_INVALID",
                    "authority grant has unknown or missing fields",
                )
            verify_document(document, self.trusted_policy_keys)
            if (
                document["schema_version"] != "hive.adapter-attended-grant.v1"
                or document["signer_key_id"] != expected_signer_key_id
                or not isinstance(document["project_id"], str)
                or not document["project_id"]
                or not isinstance(document["authorization_ref"], str)
                or not document["authorization_ref"]
            ):
                raise ProtocolError(
                    "ADAPTER_AUTHORITY_GRANT_INVALID",
                    "authority grant identity or scope is invalid",
                )
            identity = document["identity"]
            if (
                not isinstance(identity, dict)
                or set(identity) != _IDENTITY_FIELDS
                or not all(isinstance(value, str) and value for value in identity.values())
                or identity["project_id"] != document["project_id"]
            ):
                raise ProtocolError(
                    "ADAPTER_AUTHORITY_GRANT_INVALID",
                    "authority grant has an invalid separated identity",
                )
            adapters = document["adapters"]
            if not isinstance(adapters, dict) or not adapters:
                raise ProtocolError(
                    "ADAPTER_AUTHORITY_GRANT_INVALID",
                    "authority grant must name at least one adapter",
                )
            for adapter_id, value in adapters.items():
                if (
                    not isinstance(adapter_id, str)
                    or not adapter_id
                    or not isinstance(value, dict)
                    or set(value) != _ADAPTER_GRANT_FIELDS
                ):
                    raise ProtocolError(
                        "ADAPTER_AUTHORITY_GRANT_INVALID",
                        "authority grant adapter scope is invalid",
                    )
                for field in sorted(_ADAPTER_GRANT_FIELDS):
                    _string_tuple(value[field], field=field)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError(
                "ADAPTER_AUTHORITY_GRANT_INVALID",
                "authority grant failed exact validation",
            ) from exc
        except ProtocolError as exc:
            if exc.code in {
                "ADAPTER_AUTHORITY_GRANT_INVALID",
                "UNKNOWN_SIGNING_KEY",
                "SIGNATURE_INVALID",
                "MISSING_SIGNATURE",
                "UNSUPPORTED_SIGNATURE",
                "MISSING_SIGNATURE_VALUE",
            }:
                if exc.code == "ADAPTER_AUTHORITY_GRANT_INVALID":
                    raise
                raise ProtocolError(
                    "ADAPTER_AUTHORITY_GRANT_INVALID",
                    "authority grant signature is not trusted",
                ) from exc
            raise

    def resolve(self, signer_key_id: str, adapter_id: str) -> AttendedGrant:
        document = self._load_document(signer_key_id)
        raw = document["adapters"].get(adapter_id)
        if not isinstance(raw, dict):
            raise ProtocolError(
                "ADAPTER_AUTHORITY_GRANT_MISSING",
                "the verified signer is not granted the requested adapter",
            )
        return AttendedGrant(
            signer_key_id=signer_key_id,
            identity=copy.deepcopy(document["identity"]),
            project_id=document["project_id"],
            authorization_ref=document["authorization_ref"],
            adapter_id=adapter_id,
            capabilities=_string_tuple(raw["capabilities"], field="capabilities"),
            permissions=_string_tuple(raw["permissions"], field="permissions"),
            data_classifications=_string_tuple(
                raw["data_classifications"], field="data_classifications"
            ),
            network_destinations=_string_tuple(
                raw["network_destinations"], field="network_destinations"
            ),
            credential_references=_string_tuple(
                raw["credential_references"], field="credential_references"
            ),
        )
