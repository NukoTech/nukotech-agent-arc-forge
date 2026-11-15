"""Loading and canonical hashing for Hive application adapter manifests."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping

from hive_protocol.adapters.models import validate_adapter_document
from hive_protocol.core import ProtocolError, document_digest


@dataclass(frozen=True)
class AdapterManifest:
    schema_version: str
    adapter_id: str
    name: str
    version: str
    maintainer: str
    capability_ids: list[str]
    execution_mode: str
    platforms: list[dict[str, Any]]
    required_permissions: list[str]
    accepted_data_classifications: list[str]
    request_schema: str
    result_schema: str
    events: list[str]
    network_destinations: list[str]
    credential_references: list[str]
    dependencies: list[dict[str, Any]]
    health_check: dict[str, Any]
    export: dict[str, Any]
    revocation_check: dict[str, Any]
    rollback: dict[str, Any]
    uninstall: dict[str, Any]
    resource_limits: dict[str, Any]
    retention: dict[str, Any]
    offline_behavior: str
    signer_policy: dict[str, Any]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "AdapterManifest":
        if document.get("schema_version") != "hive.application-adapter-manifest.v1":
            raise ProtocolError(
                "ADAPTER_DOCUMENT_VERSION",
                "unsupported adapter document version",
            )
        return cls(**copy.deepcopy(dict(document)))

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(
            {
                "schema_version": self.schema_version,
                "adapter_id": self.adapter_id,
                "name": self.name,
                "version": self.version,
                "maintainer": self.maintainer,
                "capability_ids": self.capability_ids,
                "execution_mode": self.execution_mode,
                "platforms": self.platforms,
                "required_permissions": self.required_permissions,
                "accepted_data_classifications": self.accepted_data_classifications,
                "request_schema": self.request_schema,
                "result_schema": self.result_schema,
                "events": self.events,
                "network_destinations": self.network_destinations,
                "credential_references": self.credential_references,
                "dependencies": self.dependencies,
                "health_check": self.health_check,
                "export": self.export,
                "revocation_check": self.revocation_check,
                "rollback": self.rollback,
                "uninstall": self.uninstall,
                "resource_limits": self.resource_limits,
                "retention": self.retention,
                "offline_behavior": self.offline_behavior,
                "signer_policy": self.signer_policy,
            }
        )


def load_manifest(document: Mapping[str, Any]) -> AdapterManifest:
    validate_adapter_document("application-adapter-manifest.v1.schema.json", document)
    return AdapterManifest.from_dict(document)


def manifest_digest(document: Mapping[str, Any]) -> str:
    validate_adapter_document("application-adapter-manifest.v1.schema.json", document)
    return document_digest(document)
