from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest

from nukotech_agent_arc.cli import main
from nukotech_agent_arc.receipts import canonical_json_bytes
from nukotech_agent_arc.signing import (
    SIGNATURE_SCHEMA,
    default_signature_path,
    key_id_for,
    sign_package,
)
from test_packaging import _package, _result


def test_signing_module_imports_without_loading_cryptography() -> None:
    import nukotech_agent_arc.signing as signing

    assert signing.SIGNATURE_ALGORITHM == "Ed25519"
    assert signing.SIGNATURE_SCHEMA == "nukotech.agent_arc.package_signature.v1"
    assert callable(signing.sign_package)
    assert callable(signing.verify_package_signature_issues)


@pytest.fixture
def signer(tmp_path: Path):
    pytest.importorskip("cryptography")
    from nukotech_agent_arc.signing import generate_private_key, private_key_pem_bytes, public_key_pem_bytes

    key = generate_private_key()
    private_path = tmp_path / "keys" / "signer.private.pem"
    public_path = tmp_path / "keys" / "signer.public.pem"
    private_path.parent.mkdir()
    private_path.write_bytes(private_key_pem_bytes(key))
    private_path.chmod(0o600)
    public_path.write_bytes(public_key_pem_bytes(key.public_key()))
    return key, private_path, public_path, key_id_for(key.public_key())


def _built_package(tmp_path: Path, payload: bytes = b"safe skill\n"):
    module = _package()
    receipt = module.build_package(_result(tmp_path, payload), tmp_path / "arc.zip")
    return module, receipt


def _rewrite_manifest_from_zip(package_path: Path, manifest_path: Path) -> None:
    with zipfile.ZipFile(package_path) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    lines = [f"{hashlib.sha256(entries[name]).hexdigest()}  {name}" for name in sorted(entries)]
    manifest_path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def _write_normalized_zip(package_path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, entries[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _replace_member(package_path: Path, member: str, data: bytes) -> None:
    with zipfile.ZipFile(package_path) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    entries[member] = data
    _write_normalized_zip(package_path, entries)


def test_unsigned_output_remains_reproducible_when_signing_is_unused(tmp_path: Path) -> None:
    module = _package()
    result = _result(tmp_path)
    first = module.build_package(result, tmp_path / "a.zip")
    second = module.build_package(result, tmp_path / "b.zip")
    assert first.package_path.read_bytes() == second.package_path.read_bytes()
    assert first.manifest_path.read_bytes() == second.manifest_path.read_bytes()
    assert not default_signature_path(first.package_path).exists()
    assert module.verify_package(first.package_path, first.manifest_path).ok is True


def test_sign_and_verify_with_generated_key(tmp_path: Path, signer) -> None:
    module, package = _built_package(tmp_path)
    _key, private_path, public_path, ident = signer
    signature_path = sign_package(package.package_path, package.manifest_path, private_path)
    document = json.loads(signature_path.read_text(encoding="utf-8"))
    assert document["schema"] == SIGNATURE_SCHEMA
    assert document["algorithm"] == "Ed25519"
    assert document["key_id"] == ident
    assert document["key_id"].startswith("ed25519:")
    assert len(document["key_id"].removeprefix("ed25519:")) == 64
    assert document["manifest_sha256"] == hashlib.sha256(package.manifest_path.read_bytes()).hexdigest()
    with zipfile.ZipFile(package.package_path) as archive:
        receipt_digest = hashlib.sha256(archive.read("composition-receipt.json")).hexdigest()
    assert document["receipt_sha256"] == receipt_digest
    result = module.verify_package(
        package.package_path,
        package.manifest_path,
        signature_path=signature_path,
        public_key_path=public_path,
        require_signature=True,
    )
    assert result.ok is True
    assert result.issues == ()


def test_signature_bytes_are_deterministic_for_the_same_key(tmp_path: Path, signer) -> None:
    module, package = _built_package(tmp_path)
    _key, private_path, _public_path, _ident = signer
    first = sign_package(package.package_path, package.manifest_path, private_path, tmp_path / "a.SIGNATURE.json")
    second = sign_package(package.package_path, package.manifest_path, private_path, tmp_path / "b.SIGNATURE.json")
    assert first.read_bytes() == second.read_bytes()


def test_modified_file_is_rejected_even_when_signature_is_valid(tmp_path: Path, signer) -> None:
    module, package = _built_package(tmp_path)
    _key, private_path, public_path, _ident = signer
    sign_package(package.package_path, package.manifest_path, private_path)
    _replace_member(package.package_path, "components/safe-skill.txt", b"mutated skill\n")
    result = module.verify_package(
        package.package_path,
        package.manifest_path,
        public_key_path=public_path,
        require_signature=True,
    )
    assert result.ok is False
    assert "archive_hash_mismatch" in result.issues


def test_rewritten_manifest_is_accepted_unsigned_but_rejected_when_signed(tmp_path: Path, signer) -> None:
    module, package = _built_package(tmp_path)
    _key, private_path, public_path, _ident = signer
    sign_package(package.package_path, package.manifest_path, private_path)
    _replace_member(package.package_path, "components/safe-skill.txt", b"mutated but relisted\n")
    _rewrite_manifest_from_zip(package.package_path, package.manifest_path)

    unsigned = module.verify_package(package.package_path, package.manifest_path)
    assert unsigned.ok is True

    signed = module.verify_package(
        package.package_path,
        package.manifest_path,
        public_key_path=public_path,
        require_signature=True,
    )
    assert signed.ok is False
    assert "signature_manifest_mismatch" in signed.issues


def test_swapped_signature_is_rejected(tmp_path: Path, signer) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    module, first = _built_package(one, b"first payload\n")
    _module, second = _built_package(two, b"second payload\n")
    _key, private_path, public_path, _ident = signer
    first_sig = sign_package(first.package_path, first.manifest_path, private_path, tmp_path / "one.SIGNATURE.json")
    second_sig = sign_package(second.package_path, second.manifest_path, private_path, tmp_path / "two.SIGNATURE.json")
    assert first_sig.read_bytes() != second_sig.read_bytes()

    result = module.verify_package(
        first.package_path,
        first.manifest_path,
        signature_path=second_sig,
        public_key_path=public_path,
        require_signature=True,
    )
    assert result.ok is False
    assert "signature_manifest_mismatch" in result.issues


def test_wrong_key_is_rejected(tmp_path: Path, signer) -> None:
    pytest.importorskip("cryptography")
    from nukotech_agent_arc.signing import generate_private_key, public_key_pem_bytes

    module, package = _built_package(tmp_path)
    _key, private_path, _public_path, _ident = signer
    sign_package(package.package_path, package.manifest_path, private_path)
    other_public = tmp_path / "keys" / "other.public.pem"
    other_public.write_bytes(public_key_pem_bytes(generate_private_key().public_key()))
    result = module.verify_package(
        package.package_path,
        package.manifest_path,
        public_key_path=other_public,
        require_signature=True,
    )
    assert result.ok is False
    assert "untrusted_signing_key" in result.issues


def test_missing_signature_fails_closed_when_required(tmp_path: Path, signer) -> None:
    module, package = _built_package(tmp_path)
    _key, _private_path, public_path, _ident = signer
    result = module.verify_package(
        package.package_path,
        package.manifest_path,
        public_key_path=public_path,
        require_signature=True,
    )
    assert result.ok is False
    assert "signature_missing" in result.issues


def test_require_signature_without_keys_fails_closed(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    module, package = _built_package(tmp_path)
    result = module.verify_package(
        package.package_path,
        package.manifest_path,
        require_signature=True,
    )
    assert result.ok is False
    assert "trusted_keys_required" in result.issues


def test_trusted_keys_json_accepts_matching_full_key_id(tmp_path: Path, signer) -> None:
    from nukotech_agent_arc.signing import public_key_pem_bytes

    module, package = _built_package(tmp_path)
    key, private_path, _public_path, ident = signer
    sign_package(package.package_path, package.manifest_path, private_path)
    trusted = tmp_path / "trusted-keys.json"
    trusted.write_bytes(
        canonical_json_bytes(
            {
                "schema": "nukotech.agent_arc.trusted_keys.v1",
                "keys": [
                    {
                        "key_id": ident,
                        "public_key_pem": public_key_pem_bytes(key.public_key()).decode("utf-8"),
                    }
                ],
            }
        )
    )
    result = module.verify_package(
        package.package_path,
        package.manifest_path,
        trusted_keys_path=trusted,
        require_signature=True,
    )
    assert result.ok is True


def test_trusted_keys_json_rejects_declared_key_id_that_does_not_match(tmp_path: Path, signer) -> None:
    from nukotech_agent_arc.signing import public_key_pem_bytes

    module, package = _built_package(tmp_path)
    key, private_path, _public_path, ident = signer
    sign_package(package.package_path, package.manifest_path, private_path)
    truncated = ident[: ident.index(":") + 1] + ident.split(":")[1][:24]
    trusted = tmp_path / "trusted-keys.json"
    trusted.write_bytes(
        canonical_json_bytes(
            {
                "schema": "nukotech.agent_arc.trusted_keys.v1",
                "keys": [
                    {
                        "key_id": truncated,
                        "public_key_pem": public_key_pem_bytes(key.public_key()).decode("utf-8"),
                    }
                ],
            }
        )
    )
    result = module.verify_package(
        package.package_path,
        package.manifest_path,
        trusted_keys_path=trusted,
        require_signature=True,
    )
    assert result.ok is False
    assert "trusted_keys_invalid" in result.issues
    assert len(ident.split(":")[1]) == 64
    assert len(truncated.split(":")[1]) == 24


def test_cli_sign_and_verify_package(tmp_path: Path, signer) -> None:
    _module, package = _built_package(tmp_path)
    _key, private_path, public_path, ident = signer
    signature_path = tmp_path / "cli.SIGNATURE.json"
    assert (
        main(
            [
                "sign",
                "--package",
                str(package.package_path),
                "--manifest",
                str(package.manifest_path),
                "--key",
                str(private_path),
                "--signature",
                str(signature_path),
            ]
        )
        == 0
    )
    assert signature_path.is_file()
    assert (
        main(
            [
                "verify-package",
                "--package",
                str(package.package_path),
                "--manifest",
                str(package.manifest_path),
                "--signature",
                str(signature_path),
                "--pubkey",
                str(public_path),
                "--require-signature",
            ]
        )
        == 0
    )
    # Unsigned verify remains available and succeeds for the same package.
    assert main(["verify-package", "--package", str(package.package_path), "--manifest", str(package.manifest_path)]) == 0
    assert json.loads(signature_path.read_text(encoding="utf-8"))["key_id"] == ident
