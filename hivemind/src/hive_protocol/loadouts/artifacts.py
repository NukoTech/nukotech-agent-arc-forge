"""Verify Agent Arc interchange artifacts without importing their components."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any
import zipfile

import yaml

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError, canonical_bytes

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 256
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TYPES = {"governance_or_harness", "skill", "loop", "graph_or_memory_binding", "runtime_binding", "protocol"}
_LICENSES = {"MIT", "Apache-2.0", "BSD-3-Clause", "MPL-2.0", "Proprietary-NUKO"}


WINDOWS_DEFERRED_MESSAGE = "Windows support arrives in v1.1"


def running_on_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def refuse_windows() -> None:
    """Native Windows loadout storage is deferred; refuse before touching disk."""
    if running_on_windows():
        raise ProtocolError("LOADOUT_PLATFORM_UNSUPPORTED", WINDOWS_DEFERRED_MESSAGE)


def refuse(detail: str) -> None:
    raise ProtocolError("LOADOUT_ARTIFACT_INVALID", detail)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > 512:
        refuse("artifact path is invalid")
    path = PurePosixPath(value)
    if (path.is_absolute() or not path.parts or path.as_posix() != value or ".." in path.parts or
            any("\\" in part or ":" in part or any(ord(c) < 32 for c in part) for part in path.parts)):
        refuse("artifact path escapes its declared namespace")
    return value


def read_bounded(path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
    path = path.expanduser().absolute()
    refuse_windows()
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        refuse("artifact must be a regular file with no symlink path components")
    if path.stat().st_size > maximum:
        refuse("artifact exceeds its byte limit")
    with path.open("rb") as source:
        content = source.read(maximum + 1)
    if len(content) > maximum:
        refuse("artifact exceeds its byte limit")
    return content


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            refuse("duplicate JSON key")
        result[key] = value
    return result


def json_object(payload: bytes) -> dict[str, Any]:
    try:
        result = json.loads(payload, object_pairs_hook=_pairs,
                            parse_constant=lambda _: refuse("nonfinite JSON value"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("LOADOUT_ARTIFACT_INVALID", "artifact JSON is malformed") from exc
    if not isinstance(result, dict):
        refuse("artifact JSON must be an object")
    return result


class _StrictLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            refuse("duplicate or non-string YAML key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _yaml(payload: bytes) -> dict[str, Any]:
    try:
        if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken))
               for token in yaml.scan(payload)):
            refuse("YAML aliases, anchors and explicit tags are not accepted")
        # This loader subclasses SafeLoader; the only custom constructor rejects
        # duplicate mapping keys. Explicit tags and aliases were rejected above.
        result = yaml.load(payload, Loader=_StrictLoader)  # nosec B506
        if not isinstance(result, dict):
            refuse("Arc input must be an object")
        canonical_bytes(result)
        reject_credential_values(result, location="loadout source input")
        return result
    except (yaml.YAMLError, TypeError, ValueError, RecursionError) as exc:
        raise ProtocolError("LOADOUT_ARTIFACT_INVALID", "Arc input is malformed") from exc


def _strings(value: Any) -> set[str]:
    if (not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value)
            or len(set(value)) != len(value)):
        refuse("declarations must be arrays of unique nonempty strings")
    return set(value)


@dataclass(frozen=True)
class ArcPackage:
    manifest: dict[str, Any]
    files: dict[str, bytes]


def inspect_arc_package(package: Path, checksum_manifest: Path, *, recipe: Path,
                        registry: Path, authorization: Path) -> ArcPackage:
    """Validate exact bytes and original input/dependency closure, locally only."""
    package_bytes = read_bounded(package, MAX_ARCHIVE_BYTES)
    checksum_bytes = read_bounded(checksum_manifest, 128 * 1024)
    inputs = {"recipe": read_bounded(recipe, 2 * 1024 * 1024),
              "registry": read_bounded(registry, 2 * 1024 * 1024),
              "authorization": read_bounded(authorization, 128 * 1024)}
    expected: dict[str, str] = {}
    try:
        for line in checksum_bytes.decode("utf-8").splitlines():
            sha, separator, name = line.partition("  ")
            if not separator or not _HASH.fullmatch(sha) or name in expected:
                refuse("checksum manifest is malformed")
            expected[safe_path(name)] = sha
    except UnicodeError as exc:
        raise ProtocolError("LOADOUT_ARTIFACT_INVALID", "checksum manifest is not UTF-8") from exc
    if not {"architecture-manifest.json", "composition-receipt.json"} <= expected.keys():
        refuse("Arc package metadata is missing")
    files: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes)) as archive:
            entries = archive.infolist()
            if not 2 <= len(entries) <= MAX_ENTRIES:
                refuse("archive entry count is outside its limit")
            folded: set[str] = set()
            total = 0
            for entry in entries:
                name = safe_path(entry.filename)
                if name.casefold() in folded:
                    refuse("archive paths collide")
                folded.add(name.casefold())
                mode = entry.external_attr >> 16
                if (entry.is_dir() or (stat.S_IFMT(mode) and not stat.S_ISREG(mode)) or
                        entry.flag_bits & 1 or entry.file_size > MAX_FILE_BYTES or
                        entry.file_size / max(1, entry.compress_size) > 200):
                    refuse("archive entry is not a bounded regular unencrypted file")
                total += entry.file_size
                if total > MAX_ARCHIVE_BYTES or name not in expected:
                    refuse("archive contains undeclared or excessive content")
                with archive.open(entry) as source:
                    payload = source.read(MAX_FILE_BYTES + 1)
                if len(payload) != entry.file_size or digest(payload) != expected[name]:
                    refuse("archive content does not match its immutable pin")
                try:
                    text = payload.decode("utf-8")
                except UnicodeError as exc:
                    raise ProtocolError("LOADOUT_ARTIFACT_INVALID", "loadout components must be declarative UTF-8") from exc
                if "\x00" in text:
                    refuse("binary content cannot enter a declarative loadout")
                reject_credential_values(text, location="loadout component")
                files[name] = payload
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as exc:
        raise ProtocolError("LOADOUT_ARTIFACT_INVALID", "loadout archive is unreadable") from exc
    if set(files) != set(expected):
        refuse("archive file set differs from checksum manifest")
    architecture = json_object(files["architecture-manifest.json"])
    receipt = json_object(files["composition-receipt.json"])
    source_recipe, source_registry, source_authorization = (_yaml(inputs[key]) for key in ("recipe", "registry", "authorization"))
    if (architecture.get("schema") != "nuko.agent_arc.architecture_manifest.v1" or
            architecture.get("composer_version") != "0.3.0-alpha.1" or
            receipt.get("schema") != "nuko.agent_arc.composition_receipt.v1" or
            receipt.get("status") != "COMPOSED" or
            source_recipe.get("schema") != "nuko.agent_arc.recipe.v1" or
            source_registry.get("schema") != "nuko.agent_arc.registry.v1" or
            source_authorization.get("schema") != "nuko.agent_arc.authorization.v1"):
        refuse("unsupported Arc interchange version")
    identity = {"id": source_recipe.get("id"), "version": source_recipe.get("version")}
    if (not all(isinstance(x, str) and x for x in identity.values()) or
            architecture.get("recipe") != identity or receipt.get("recipe") != identity or
            architecture.get("registry_version") != source_registry.get("registry_version") or
            receipt.get("registry_version") != source_registry.get("registry_version") or
            architecture.get("composer_version") != receipt.get("composer_version") or
            source_authorization.get("subject") != identity["id"] or
            receipt.get("authorization_subject") != identity["id"] or
            receipt.get("authorization_id") != source_authorization.get("id") or
            receipt.get("architecture_manifest_sha256") != digest(canonical_bytes(architecture) + b"\n")):
        refuse("Arc receipt and original input bindings differ")
    requested = _strings(source_recipe.get("requested_capabilities"))
    effects = _strings(source_recipe.get("side_effects"))
    prohibited = _strings(source_authorization.get("prohibited_effects"))
    if (requested - _strings(source_authorization.get("allowed_capabilities")) or
            effects - _strings(source_authorization.get("allowed_side_effects")) or
            (requested | effects) & prohibited or
            _strings(architecture.get("requested_capabilities")) != requested or
            _strings(architecture.get("side_effects")) != effects or
            architecture.get("authority_profile") != source_recipe.get("authority_profile") or
            _strings(architecture.get("stop_conditions")) != _strings(source_recipe.get("stop_conditions"))):
        refuse("Arc declarations exceed or differ from their original authorization")
    decisions = receipt.get("security_decisions")
    if (not isinstance(decisions, list) or len(decisions) != 2 or
            {x.get("stage") for x in decisions if isinstance(x, dict)} != {"pre_compose", "pre_package"} or
            any(not isinstance(x, dict) or x.get("decision") != "allow" or
                not _HASH.fullmatch(str(x.get("evidence_hash", ""))) for x in decisions)):
        refuse("Arc composition security decisions are incomplete")
    source_components = source_registry.get("components")
    recipe_components = source_recipe.get("components")
    composed = architecture.get("components")
    if not all(isinstance(value, list) and 0 < len(value) <= MAX_ENTRIES for value in
               (source_components, recipe_components, composed)):
        refuse("Arc component lists are invalid")
    pinned = []
    ids: set[str] = set()
    paths: set[str] = set()
    for component in composed:
        if not isinstance(component, dict):
            refuse("Arc component is not an object")
        component_id, version, kind = (component.get(key) for key in ("id", "version", "type"))
        if (not isinstance(component_id, str) or not component_id or component_id in ids or
                not isinstance(version, str) or not version or kind not in _TYPES):
            refuse("Arc component identity is duplicate or invalid")
        ids.add(component_id)
        match = lambda item: isinstance(item, dict) and (item.get("id"), item.get("version"), item.get("type")) == (component_id, version, kind)
        registered = [item for item in source_components if match(item)]
        references = [item for item in recipe_components if match(item)]
        if len(registered) != 1 or len(references) != 1:
            refuse("component lacks one exact recipe and registry pin")
        original, reference = registered[0], references[0]
        name = safe_path(component.get("path"))
        if (not name.startswith("components/") or PurePosixPath(name).suffix.lower() not in {".md", ".txt", ".json", ".yaml", ".yml", ".toml"}
                or name in paths or name not in files):
            refuse("component is not an owned declarative component path")
        paths.add(name)
        if any(item.get("sha256") != digest(files[name]) for item in (component, original, reference)):
            refuse("component bytes differ from recipe, registry or composition pins")
        for field in ("path", "license", "provenance", "capabilities", "side_effects", "stop_conditions", "rollback"):
            if component.get(field) != original.get(field) and not (
                isinstance(component.get(field), list) and isinstance(original.get(field), list)
                and sorted(component[field]) == sorted(original[field])):
                refuse("composed component metadata differs from its source registry")
        if (original.get("license") not in _LICENSES or not isinstance(original.get("provenance"), dict) or
                not all(original["provenance"].get(key) for key in ("source", "owner")) or
                _strings(original.get("capabilities")) - requested or
                _strings(original.get("side_effects")) - effects or
                not _strings(original.get("stop_conditions")) or not _strings(original.get("rollback"))):
            refuse("component provenance, rights or policy declarations are incomplete")
        pinned.append({**component, "dependencies": sorted(_strings(original.get("dependencies"))),
                       "conflicts": sorted(_strings(original.get("conflicts")))})
    if len(recipe_components) != len(pinned) or len(composed) != len(pinned):
        refuse("recipe component closure differs from the composed package")
    for component in pinned:
        if set(component["dependencies"]) - ids or set(component["conflicts"]) & ids:
            refuse("component dependencies or conflicts are unresolved")
    if paths | {"architecture-manifest.json", "composition-receipt.json"} != files.keys():
        refuse("package contains files outside component closure")
    if sorted(receipt.get("component_hashes", [])) != sorted(x["sha256"] for x in pinned):
        refuse("composition receipt component hashes differ")
    security_context = {
        "recipe": {**identity, "requested_capabilities": sorted(requested), "side_effects": sorted(effects)},
        "authorization": {key: source_authorization[key] for key in
            ("id", "subject", "allowed_capabilities", "allowed_side_effects", "prohibited_effects")},
        "components": composed,
    }
    for decision in decisions:
        context = dict(security_context)
        if decision["stage"] == "pre_package":
            context["architecture_manifest_sha256"] = digest(canonical_bytes(architecture) + b"\n")
        if decision["evidence_hash"] != digest(canonical_bytes({"stage": decision["stage"], "context": context})):
            refuse("Arc security decision evidence differs from the exact original inputs")
    manifest = {"source": "nuko-agent-arc", "composer_version": architecture["composer_version"],
        "recipe": identity, "registry_version": architecture["registry_version"],
        "artifact_pins": {"package_sha256": digest(package_bytes), "checksum_manifest_sha256": digest(checksum_bytes),
            "architecture_manifest_sha256": digest(files["architecture-manifest.json"]),
            "composition_receipt_sha256": digest(files["composition-receipt.json"]),
            **{f"{key}_sha256": digest(value) for key, value in inputs.items()}},
        "components": sorted(pinned, key=lambda x: x["id"]), "declared_capabilities": sorted(requested),
        "declared_side_effects": sorted(effects), "execution_mode": "DECLARATIVE_ONLY", "grants_authority": False}
    files = {**files, **{f"source-inputs/{key}.yaml": value for key, value in inputs.items()},
             "source-inputs/MANIFEST.sha256": checksum_bytes}
    return ArcPackage(manifest=manifest, files=files)
