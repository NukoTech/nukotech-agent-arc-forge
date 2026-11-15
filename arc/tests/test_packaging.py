from __future__ import annotations

import hashlib
import importlib
import stat
import zipfile
from pathlib import Path

import pytest

from nukotech_agent_arc.composer import CompositionResult
from nukotech_agent_arc.models import ResolvedComponent
from nukotech_agent_arc.receipts import canonical_json_bytes


def _package():
    module = importlib.import_module("nukotech_agent_arc.package")
    assert hasattr(module, "build_package"), "build_package is not implemented"
    assert hasattr(module, "verify_package"), "verify_package is not implemented"
    return module


def _result(tmp_path: Path, payload: bytes = b"safe skill\n") -> CompositionResult:
    component_path = tmp_path / "components" / "safe-skill.txt"
    component_path.parent.mkdir()
    component_path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    component = ResolvedComponent(
        id="safe-skill",
        version="1.0.0",
        type="skill",
        declared_sha256=digest,
        actual_sha256=digest,
        path=component_path,
        license="MIT",
        provenance={"source": "first-party", "owner": "example"},
        dependencies=(),
        conflicts=(),
        capabilities=("draft_content",),
        side_effects=(),
        stop_conditions=("operator_stop",),
        rollback=("remove_candidate",),
    )
    architecture = {
        "schema": "nukotech.agent_arc.architecture_manifest.v1",
        "composer_version": "0.3.0-alpha.1",
        "recipe": {"id": "marketing-operator", "version": "1.0.0"},
        "registry_version": "0.3.0-alpha.1",
        "authority_profile": "draft-only",
        "requested_capabilities": ["draft_content"],
        "side_effects": [],
        "stop_conditions": ["operator_stop"],
        "components": [
            {
                "id": "safe-skill",
                "version": "1.0.0",
                "type": "skill",
                "sha256": digest,
                "path": "components/safe-skill.txt",
                "license": "MIT",
                "provenance": {"owner": "example", "source": "first-party"},
                "capabilities": ["draft_content"],
                "side_effects": [],
                "stop_conditions": ["operator_stop"],
                "rollback": ["remove_candidate"],
            }
        ],
    }
    receipt = {
        "schema": "nukotech.agent_arc.composition_receipt.v1",
        "status": "COMPOSED",
        "composer_version": "0.3.0-alpha.1",
        "recipe": {"id": "marketing-operator", "version": "1.0.0"},
        "registry_version": "0.3.0-alpha.1",
        "authorization_id": "example-operator-test",
        "authorization_subject": "marketing-operator",
        "architecture_manifest_sha256": hashlib.sha256(canonical_json_bytes(architecture)).hexdigest(),
        "component_hashes": [digest],
        "security_decisions": [],
    }
    return CompositionResult(
        status="COMPOSED",
        architecture_manifest=architecture,
        receipt=receipt,
        receipt_bytes=canonical_json_bytes(receipt),
        issues=(),
        security_decisions=(),
        components=(component,),
    )


def test_package_bytes_and_manifest_are_reproducible(tmp_path: Path) -> None:
    module = _package()
    result = _result(tmp_path)

    first = module.build_package(result, tmp_path / "first.zip")
    second = module.build_package(result, tmp_path / "second.zip")

    assert first.package_sha256 == second.package_sha256
    assert first.package_path.read_bytes() == second.package_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()


def test_archive_order_timestamp_and_permissions_are_normalized(tmp_path: Path) -> None:
    module = _package()
    package = module.build_package(_result(tmp_path), tmp_path / "arc.zip")

    with zipfile.ZipFile(package.package_path) as archive:
        infos = archive.infolist()

    assert [info.filename for info in infos] == sorted(info.filename for info in infos)
    assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in infos)
    assert all((info.external_attr >> 16) == 0o100644 for info in infos)


def test_undeclared_sibling_file_is_excluded(tmp_path: Path) -> None:
    module = _package()
    result = _result(tmp_path)
    (tmp_path / "components" / "undeclared.txt").write_text("not declared\n", encoding="utf-8")
    package = module.build_package(result, tmp_path / "arc.zip")

    with zipfile.ZipFile(package.package_path) as archive:
        names = archive.namelist()

    assert "components/undeclared.txt" not in names


def test_manifest_verifier_detects_archive_mutation(tmp_path: Path) -> None:
    module = _package()
    package = module.build_package(_result(tmp_path), tmp_path / "arc.zip")

    assert module.verify_package(package.package_path, package.manifest_path).ok is True
    with zipfile.ZipFile(package.package_path, "a") as archive:
        archive.writestr("unexpected.txt", "mutation")

    verification = module.verify_package(package.package_path, package.manifest_path)
    assert verification.ok is False
    assert "unexpected_archive_entry" in verification.issues


def test_path_traversal_in_declared_manifest_is_rejected(tmp_path: Path) -> None:
    module = _package()
    result = _result(tmp_path)
    result.architecture_manifest["components"][0]["path"] = "../escape.txt"

    with pytest.raises(module.PackagingError) as caught:
        module.build_package(result, tmp_path / "arc.zip")

    assert caught.value.code == "unsafe_archive_path"


def test_symlink_component_is_rejected(tmp_path: Path) -> None:
    module = _package()
    result = _result(tmp_path)
    real_path = result.components[0].path
    symlink = tmp_path / "components" / "linked.txt"
    symlink.symlink_to(real_path)
    object.__setattr__(result.components[0], "path", symlink)
    result.architecture_manifest["components"][0]["path"] = "components/linked.txt"

    with pytest.raises(module.PackagingError) as caught:
        module.build_package(result, tmp_path / "arc.zip")

    assert caught.value.code == "symlink_not_allowed"


def test_synthetic_credential_pattern_blocks_package_without_echoing_value(tmp_path: Path) -> None:
    module = _package()
    synthetic = b"token: sk-test-1234567890abcdefghijklmnop\n"
    result = _result(tmp_path, synthetic)

    with pytest.raises(module.PackagingError) as caught:
        module.build_package(result, tmp_path / "arc.zip")

    assert caught.value.code == "credential_pattern_detected"
    assert "sk-test" not in str(caught.value)


def test_verifier_rejects_oversized_member_before_hashing(tmp_path: Path) -> None:
    module = _package()
    payload = b"x" * (module.MAX_ENTRY_UNCOMPRESSED_BYTES + 1)
    package = tmp_path / "oversized.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("oversized.bin", payload)
    manifest = tmp_path / "oversized.MANIFEST.sha256"
    manifest.write_text(f"{hashlib.sha256(payload).hexdigest()}  oversized.bin\n", encoding="utf-8")

    result = module.verify_package(package, manifest)

    assert result.ok is False
    assert "archive_entry_too_large" in result.issues


def test_verifier_rejects_excessive_compression_ratio(tmp_path: Path) -> None:
    module = _package()
    payload = b"0" * 1_000_000
    package = tmp_path / "compressed.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("compressed.bin", payload)
    manifest = tmp_path / "compressed.MANIFEST.sha256"
    manifest.write_text(f"{hashlib.sha256(payload).hexdigest()}  compressed.bin\n", encoding="utf-8")

    result = module.verify_package(package, manifest)

    assert result.ok is False
    assert "excessive_compression_ratio" in result.issues


def test_verifier_rejects_package_without_required_agent_arc_records(tmp_path: Path) -> None:
    module = _package()
    payload = b"self-consistent but not an Agent Arc package\n"
    package = tmp_path / "incomplete.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("component.txt", payload)
    manifest = tmp_path / "incomplete.MANIFEST.sha256"
    manifest.write_text(f"{hashlib.sha256(payload).hexdigest()}  component.txt\n", encoding="utf-8")

    result = module.verify_package(package, manifest)

    assert result.ok is False
    assert "missing_required_archive_entry" in result.issues


def test_verifier_rejects_symlink_archive_member(tmp_path: Path) -> None:
    module = _package()
    payload = b"target.txt"
    package = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("linked.txt")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(info, payload)
    manifest = tmp_path / "symlink.MANIFEST.sha256"
    manifest.write_text(f"{hashlib.sha256(payload).hexdigest()}  linked.txt\n", encoding="utf-8")

    result = module.verify_package(package, manifest)

    assert result.ok is False
    assert "non_regular_archive_entry" in result.issues


def test_verifier_rejects_synthetic_credential_pattern(tmp_path: Path) -> None:
    module = _package()
    payload = b"token: sk-test-1234567890abcdefghijklmnop\n"
    package = tmp_path / "credential.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("component.txt", payload)
    manifest = tmp_path / "credential.MANIFEST.sha256"
    manifest.write_text(f"{hashlib.sha256(payload).hexdigest()}  component.txt\n", encoding="utf-8")

    result = module.verify_package(package, manifest)

    assert result.ok is False
    assert "credential_pattern_detected" in result.issues
