"""Release repository identity is bound to the public repository and fails closed otherwise."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from hive_protocol.core import ProtocolError, load_private_key, sign_document
from hive_protocol.distribution import build_governance_release, stage_governance_release
from hive_protocol.release_identity import (
    bound_release_repository,
    require_matching_repository,
    require_release_repository,
)
from hive_protocol.storage import atomic_write_json, read_json
from hive_protocol.turn import _load_marker, consume_turn, prepare_turn, route_turn

from lab_identity import assigned_lab_identity

COMMIT = "b" * 40
TREE = "c" * 40
NAMESPACE = "HIVE-LAB-RELEASE-IDENTITY-TEST"


@pytest.fixture
def lab_env(tmp_path: Path):
    with patch.dict(
        os.environ,
        {
            "HIVE_PROCESS_NAMESPACE": NAMESPACE,
            "HIVE_LAB_CONTEXT": str(tmp_path / "absent-lab-context.json"),
        },
    ):
        with patch("hive_protocol.turn.socket.gethostname", return_value="hive-lab-host"):
            with patch("hive_protocol.turn.EXPECTED_IDENTITY", assigned_lab_identity()):
                yield tmp_path / "lab"


@pytest.mark.release_identity_unbound
@pytest.mark.parametrize("value", ["<REPO_SLUG>", "", "   ", None, "not-a-slug"])
def test_unbound_or_placeholder_release_identity_is_denied(value: str | None) -> None:
    with bound_release_repository(value):
        with pytest.raises(ProtocolError, match="RELEASE_IDENTITY_UNBOUND"):
            require_release_repository()


PUBLIC_RELEASE_REPOSITORY = "NukoTech/nukotech-agent-arc-forge"


@pytest.mark.release_identity_unbound
def test_checked_in_release_identity_is_bound_to_public_repository() -> None:
    assert require_release_repository() == PUBLIC_RELEASE_REPOSITORY


def test_mismatched_turn_and_release_identities_are_denied(
    lab_env: Path, bound_release_repository_value: str
) -> None:
    assert require_release_repository() == bound_release_repository_value
    prepared = prepare_turn(lab_env, COMMIT)
    run_dir = Path(str(prepared["run_dir"]))
    envelope_path = (
        run_dir
        / "mailbox"
        / "outbox"
        / _load_marker(run_dir)["sender_surface"]
        / f"{_load_marker(run_dir)['message_id']}.json"
    )
    envelope = read_json(envelope_path)
    envelope["provenance"]["repository"] = "example-org/unrelated-repo"
    atomic_write_json(
        envelope_path,
        sign_document(envelope, load_private_key(run_dir / "keys" / "issuer.private.pem")),
    )
    with pytest.raises(ProtocolError, match="RELEASE_IDENTITY_MISMATCH"):
        route_turn(run_dir)

    # A fresh run for the signed-release staging path.
    other = lab_env.parent / "lab-release"
    prepared = prepare_turn(other, COMMIT)
    run_dir = Path(str(prepared["run_dir"]))
    route_turn(run_dir)
    consume_turn(run_dir)
    marker = _load_marker(run_dir)
    build_governance_release(run_dir, marker, "0.2.0-lab.1", TREE, NAMESPACE)
    release_path = run_dir / "distribution" / "outbox" / "0.2.0-lab.1" / "release.json"
    release = read_json(release_path)
    release["repository"] = "example-org/unrelated-repo"
    atomic_write_json(
        release_path,
        sign_document(release, load_private_key(run_dir / "keys" / "issuer.private.pem")),
    )
    with pytest.raises(ProtocolError, match="RELEASE_IDENTITY_MISMATCH"):
        stage_governance_release(run_dir, marker, "0.2.0-lab.1", NAMESPACE)


def test_bound_release_identity_signs_and_verifies(
    lab_env: Path, bound_release_repository_value: str
) -> None:
    require_matching_repository(bound_release_repository_value)
    prepared = prepare_turn(lab_env, COMMIT)
    run_dir = Path(str(prepared["run_dir"]))
    marker = _load_marker(run_dir)
    envelope = read_json(
        run_dir
        / "mailbox"
        / "outbox"
        / marker["sender_surface"]
        / f"{marker['message_id']}.json"
    )
    assert envelope["provenance"]["repository"] == bound_release_repository_value
    route_turn(run_dir)
    consume_turn(run_dir)
    marker = _load_marker(run_dir)
    built = build_governance_release(run_dir, marker, "0.2.0-lab.1", TREE, NAMESPACE)
    assert built["outcome"] == "RELEASE_BUILT"
    release = read_json(run_dir / "distribution" / "outbox" / "0.2.0-lab.1" / "release.json")
    assert release["repository"] == bound_release_repository_value
    staged = stage_governance_release(run_dir, marker, "0.2.0-lab.1", NAMESPACE)
    assert staged["outcome"] == "STAGED_NOT_ACTIVATED"
