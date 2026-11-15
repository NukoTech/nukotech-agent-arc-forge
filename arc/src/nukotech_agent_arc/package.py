"""Deterministic declared-file package builder."""

from __future__ import annotations

import hashlib
import re
import stat
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .composer import CompositionResult
from .digests import digests_equal
from .receipts import canonical_json_bytes


_CREDENTIAL_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"),
    re.compile(rb"\bxapp-[A-Za-z0-9-]{12,}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
)

MAX_ARCHIVE_ENTRIES = 256
MAX_ENTRY_UNCOMPRESSED_BYTES = 8 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
_HASH_CHUNK_BYTES = 64 * 1024
_SCAN_OVERLAP_BYTES = 256
REQUIRED_PACKAGE_ENTRIES = frozenset({"architecture-manifest.json", "composition-receipt.json"})


class PackagingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class PackageReceipt:
    package_path: Path
    manifest_path: Path
    package_sha256: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    issues: tuple[str, ...]


def _safe_archive_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PackagingError("unsafe_archive_path", "declared archive path is unsafe")
    return path


def _scan_bytes(data: bytes) -> bool:
    return any(pattern.search(data) for pattern in _CREDENTIAL_PATTERNS)


def _hash_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[str, bool]:
    digest = hashlib.sha256()
    overlap = b""
    credential_pattern = False
    with archive.open(info, "r") as source:
        while True:
            chunk = source.read(_HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            window = overlap + chunk
            credential_pattern = credential_pattern or _scan_bytes(window)
            overlap = window[-_SCAN_OVERLAP_BYTES:]
    return digest.hexdigest(), credential_pattern


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def _manifest_bytes(entries: dict[str, bytes]) -> bytes:
    lines = [f"{hashlib.sha256(entries[name]).hexdigest()}  {name}" for name in sorted(entries)]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_package(result: CompositionResult, output: Path) -> PackageReceipt:
    """Build a byte-reproducible ZIP using only composition-declared files."""

    if result.status != "COMPOSED" or result.architecture_manifest is None:
        raise PackagingError("composition_not_successful", "only a composed result may be packaged")

    entries: dict[str, bytes] = {
        "architecture-manifest.json": canonical_json_bytes(result.architecture_manifest),
        "composition-receipt.json": result.receipt_bytes,
    }
    resolved = {(item.id, item.version, item.type): item for item in result.components}
    for declared in result.architecture_manifest.get("components") or ():
        archive_path = _safe_archive_path(str(declared.get("path", ""))).as_posix()
        identity = (str(declared.get("id", "")), str(declared.get("version", "")), str(declared.get("type", "")))
        component = resolved.get(identity)
        if component is None:
            raise PackagingError("undeclared_component_source", "manifest component lacks a resolved source")
        if component.path.is_symlink():
            raise PackagingError("symlink_not_allowed", "component source may not be a symbolic link")
        if not component.path.is_file():
            raise PackagingError("component_source_missing", "component source is not a regular file")
        data = component.path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        declared_hash = declared.get("sha256")
        if not digests_equal(actual, component.actual_sha256) or not digests_equal(actual, declared_hash):
            raise PackagingError("component_changed_after_composition", "component bytes changed after composition")
        if _scan_bytes(data):
            raise PackagingError("credential_pattern_detected", "credential pattern detected in declared component")
        if archive_path in entries:
            raise PackagingError("duplicate_archive_path", "duplicate archive path is prohibited")
        entries[archive_path] = data

    for data in entries.values():
        if _scan_bytes(data):
            raise PackagingError("credential_pattern_detected", "credential pattern detected in package input")

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(entries):
            archive.writestr(_zip_info(name), entries[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    manifest_path = destination.with_suffix(".MANIFEST.sha256")
    manifest_path.write_bytes(_manifest_bytes(entries))
    return PackageReceipt(
        package_path=destination,
        manifest_path=manifest_path,
        package_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
        files=tuple(sorted(entries)),
    )


def verify_package(
    package_path: Path,
    manifest_path: Path,
    *,
    signature_path: Path | None = None,
    public_key_path: Path | None = None,
    trusted_keys_path: Path | None = None,
    require_signature: bool = False,
) -> VerificationResult:
    """Verify archive file set and hashes against the adjacent manifest.

    Hash checks run on every call. Signature checks run when a signature
    path, a trusted key, or ``require_signature`` is provided. Unsigned
    verification keeps the original fail-open-on-signature behavior so
    existing unsigned packages stay verifiable. When a signature is
    required, a missing or invalid signature fails closed.
    """

    issues: list[str] = []
    expected: dict[str, str] = {}
    try:
        lines = Path(manifest_path).read_text(encoding="utf-8").splitlines()
        for line in lines:
            digest, separator, name = line.partition("  ")
            if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest):
                issues.append("invalid_manifest_line")
                continue
            try:
                safe_name = _safe_archive_path(name).as_posix()
            except PackagingError:
                issues.append("unsafe_manifest_path")
                continue
            if safe_name in expected:
                issues.append("duplicate_manifest_entry")
            expected[safe_name] = digest
    except (OSError, UnicodeError):
        return VerificationResult(ok=False, issues=("manifest_unreadable",))
    if not REQUIRED_PACKAGE_ENTRIES.issubset(expected):
        issues.append("missing_required_archive_entry")

    try:
        with zipfile.ZipFile(package_path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                issues.append("too_many_archive_entries")
            duplicates = [name for name, count in Counter(names).items() if count > 1]
            if duplicates:
                issues.append("duplicate_archive_entry")
            archive_names = set(names)
            if archive_names - set(expected):
                issues.append("unexpected_archive_entry")
            if set(expected) - archive_names:
                issues.append("missing_archive_entry")
            total_uncompressed = 0
            safe_to_hash: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                try:
                    _safe_archive_path(info.filename)
                except PackagingError:
                    issues.append("unsafe_archive_path")
                    continue
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                    issues.append("non_regular_archive_entry")
                    continue
                total_uncompressed += info.file_size
                if info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
                    issues.append("archive_entry_too_large")
                    continue
                if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    issues.append("archive_total_too_large")
                    continue
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > MAX_COMPRESSION_RATIO:
                    issues.append("excessive_compression_ratio")
                    continue
                safe_to_hash[info.filename] = info
            for name, digest in expected.items():
                info = safe_to_hash.get(name)
                if info is not None:
                    actual, credential_pattern = _hash_zip_member(archive, info)
                    if not digests_equal(actual, digest):
                        issues.append("archive_hash_mismatch")
                    if credential_pattern:
                        issues.append("credential_pattern_detected")
    except (OSError, zipfile.BadZipFile, EOFError, RuntimeError, zlib.error):
        issues.append("package_unreadable")

    if require_signature or signature_path is not None or public_key_path is not None or trusted_keys_path is not None:
        from .signing import verify_package_signature_issues

        issues.extend(
            verify_package_signature_issues(
                package_path,
                manifest_path,
                signature_path=signature_path,
                public_key_path=public_key_path,
                trusted_keys_path=trusted_keys_path,
                require_signature=require_signature,
            )
        )

    ordered = tuple(sorted(set(issues)))
    return VerificationResult(ok=not ordered, issues=ordered)
