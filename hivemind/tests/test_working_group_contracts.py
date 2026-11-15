from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError


SCHEMAS = Path(__file__).parents[1] / "contracts" / "drafts"


def _schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


class WorkingGroupContractTests(unittest.TestCase):
    def test_new_contracts_are_meta_valid(self) -> None:
        for name in (
            "working-group-message.v0.1.schema.json",
            "hive-application-adapter-manifest.v0.1.schema.json",
        ):
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(_schema(name))

    def test_message_requires_explicit_surface_machine_and_project(self) -> None:
        document = {
            "schema_version": "hive.working-group-message.v0.1",
            "message_id": "12345678-1234-4234-8234-123456789abc",
            "created_at": "2026-08-27T15:00:00Z",
            "expires_at": "2026-08-28T15:00:00Z",
            "nonce": "a" * 32,
            "sender": {"persona_id": "Builder", "surface_id": "BuildA", "machine_id": "hive-lab-host"},
            "recipient": {"persona_id": "Director", "surface_id": "LeadC", "machine_id": "node-c"},
            "project_id": "hivemind-working-group",
            "message_class": "HANDOFF",
            "state": "WRITTEN",
            "authority_ref": "Owner order 2026-08-27",
            "payload_ref": {"media_type": "application/json", "uri": "sha256:payload", "sha256": "b" * 64, "data_classification": "NON_PRIVATE"},
            "provenance": [{"ref": "git:commit", "sha256": "c" * 64}],
            "content_sha256": "d" * 64,
            "signature": {"algorithm": "Ed25519", "key_id": "ed25519:" + "e" * 24, "value": "A" * 86},
        }
        Draft202012Validator(_schema("working-group-message.v0.1.schema.json")).validate(document)
        del document["recipient"]["machine_id"]
        with self.assertRaises(ValidationError):
            Draft202012Validator(_schema("working-group-message.v0.1.schema.json")).validate(document)

    def test_adapter_manifest_rejects_inline_credential_values(self) -> None:
        manifest = {
            "schema_version": "hive.application-adapter-manifest.v0.1",
            "adapter_id": "nukotech.echo",
            "name": "Echo",
            "version": "0.1.0",
            "maintainer": "NukoTech",
            "capability_ids": ["test.echo"],
            "execution_mode": "NATIVE",
            "platforms": [{"os": "linux", "architecture": "aarch64", "runtime": "python3.12"}],
            "required_permissions": [],
            "accepted_data_classifications": ["NON_PRIVATE"],
            "request_schema": "hive.adapter-request.v0.1",
            "result_schema": "hive.adapter-result.v0.1",
            "events": [],
            "network_destinations": [],
            "credential_references": [],
            "dependencies": [],
            "health_check": {"entrypoint": "echo health", "timeout_seconds": 5},
            "rollback": {"entrypoint": "echo rollback", "timeout_seconds": 5},
            "uninstall": {"entrypoint": "echo uninstall", "timeout_seconds": 5},
            "retention": {"policy": "none", "delete_method": "not-applicable"},
            "offline_behavior": "SUPPORTED",
            "signer_policy": {"issuer": "NukoTech", "allowed_key_ids": ["ed25519:test"]},
        }
        validator = Draft202012Validator(_schema("hive-application-adapter-manifest.v0.1.schema.json"))
        validator.validate(manifest)
        manifest["credential_value"] = "forbidden"
        with self.assertRaises(ValidationError):
            validator.validate(manifest)


if __name__ == "__main__":
    unittest.main()
