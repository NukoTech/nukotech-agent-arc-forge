"""Agent Arc command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .composer import CompositionRequest, compose
from .models import Recipe, Registry
from .package import PackagingError, build_package, verify_package
from .receipts import canonical_json_bytes
from .registry import resolve_components
from .signing import SigningError, sign_package
from .schema import validate_document
from .skill_import import SkillImportError, import_skill
from .yamlio import load_yaml_strict


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-arc", description="Deterministic agent architecture composer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate recipe, registry, and exact component bytes")
    validate.add_argument("--recipe", required=True, type=Path)
    validate.add_argument("--registry", required=True, type=Path)

    compose_parser = subparsers.add_parser("compose", help="compose and package a bounded architecture")
    compose_parser.add_argument("--recipe", required=True, type=Path)
    compose_parser.add_argument("--registry", required=True, type=Path)
    compose_parser.add_argument("--authorization", required=True, type=Path)
    compose_parser.add_argument("--component-root", required=True, type=Path)
    compose_parser.add_argument("--output", required=True, type=Path)

    verify = subparsers.add_parser("verify-package", help="verify package file set and hashes")
    verify.add_argument("--package", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--signature", type=Path, help="detached signature receipt (default: <package-stem>.SIGNATURE.json)")
    verify.add_argument("--pubkey", type=Path, help="trusted Ed25519 public key PEM")
    verify.add_argument("--trusted-keys", type=Path, help="PEM bundle or trusted-keys JSON file")
    verify.add_argument("--require-signature", action="store_true", help="fail closed unless a trusted signature verifies")

    sign = subparsers.add_parser(
        "sign",
        help="create a detached Ed25519 signature over the manifest and composition receipt",
    )
    sign.add_argument("--package", required=True, type=Path)
    sign.add_argument("--manifest", required=True, type=Path)
    sign.add_argument("--key", required=True, type=Path, help="Ed25519 PKCS8 private key PEM")
    sign.add_argument("--signature", type=Path, help="output path (default: <package-stem>.SIGNATURE.json)")

    skill = subparsers.add_parser("import-skill", help="print a registry component entry for a SKILL.md folder")
    skill.add_argument("skill_dir", type=Path)
    skill.add_argument("--type", default="skill", dest="component_type")
    skill.add_argument("--registry-root", type=Path, default=None)
    skill.add_argument("--capability", action="append", default=[], dest="capabilities")
    skill.add_argument("--license", default="MIT", dest="license_id")
    return parser


def _validate(recipe_path: Path, registry_path: Path) -> int:
    try:
        recipe_document = load_yaml_strict(recipe_path)
        registry_document = load_yaml_strict(registry_path)
        issues = validate_document(recipe_document, "recipe") + validate_document(registry_document, "registry")
        if not issues:
            resolution = resolve_components(
                Recipe.from_mapping(recipe_document),
                Registry.from_mapping(registry_document),
                registry_path.parent,
            )
            issues = resolution.issues
    except Exception:
        issues = (object(),)
    if issues:
        print("INVALID")
        return 2
    print("VALID")
    return 0


def _compose(arguments: argparse.Namespace) -> int:
    request = CompositionRequest(
        recipe_path=arguments.recipe,
        registry_path=arguments.registry,
        authorization_path=arguments.authorization,
        component_root=arguments.component_root,
    )
    result = compose(request)
    output = arguments.output
    output.mkdir(parents=True, exist_ok=True)
    if result.status == "REFUSED":
        receipt_path = output / "refusal-receipt.json"
        receipt_path.write_bytes(result.receipt_bytes)
        print("STATUS REFUSED")
        print(f"RECEIPT {receipt_path}")
        return 2

    architecture_path = output / "architecture-manifest.json"
    receipt_path = output / "composition-receipt.json"
    architecture_path.write_bytes(canonical_json_bytes(result.architecture_manifest))
    receipt_path.write_bytes(result.receipt_bytes)
    recipe = result.architecture_manifest["recipe"]
    package_path = output / f"{recipe['id']}-{recipe['version']}.zip"
    try:
        build_package(result, package_path)
    except PackagingError:
        print("STATUS NOT_WORKING")
        return 4
    print("STATUS COMPOSED")
    print(f"RECEIPT {receipt_path}")
    print(f"PACKAGE {package_path}")
    return 0


def _verify(arguments: argparse.Namespace) -> int:
    result = verify_package(
        arguments.package,
        arguments.manifest,
        signature_path=arguments.signature,
        public_key_path=arguments.pubkey,
        trusted_keys_path=arguments.trusted_keys,
        require_signature=arguments.require_signature,
    )
    if result.ok:
        print("VERIFIED")
        return 0
    print("NOT VERIFIED")
    return 3


def _sign(arguments: argparse.Namespace) -> int:
    try:
        destination = sign_package(
            arguments.package,
            arguments.manifest,
            arguments.key,
            signature_path=arguments.signature,
        )
        key_id = json.loads(destination.read_text(encoding="utf-8"))["key_id"]
    except (SigningError, OSError, ValueError, KeyError):
        print("NOT SIGNED")
        return 4
    print("SIGNED")
    print(f"SIGNATURE {destination}")
    print(f"KEY_ID {key_id}")
    return 0


def _import_skill(arguments: argparse.Namespace) -> int:
    import yaml

    try:
        entry = import_skill(
            arguments.skill_dir,
            component_type=arguments.component_type,
            registry_root=arguments.registry_root,
            capabilities=tuple(arguments.capabilities),
            license_id=arguments.license_id,
        )
    except (SkillImportError, OSError, ValueError) as error:
        print(f"STATUS REFUSED: {error}")
        return 2
    print(yaml.safe_dump([entry], sort_keys=False), end="")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "validate":
        return _validate(arguments.recipe, arguments.registry)
    if arguments.command == "compose":
        return _compose(arguments)
    if arguments.command == "verify-package":
        return _verify(arguments)
    if arguments.command == "sign":
        return _sign(arguments)
    if arguments.command == "import-skill":
        return _import_skill(arguments)
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
