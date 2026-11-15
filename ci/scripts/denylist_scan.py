#!/usr/bin/env python3
"""Fail the checkout if a denylist rule matches.

Rules are loaded from the DENYLIST_PATTERNS_B64 environment variable
(base64-encoded text), or from --patterns pointing at a file that
resolves outside the repository root. The check fails closed if rules
cannot be loaded. Output never includes a rule body; hits report only
a rule name, a relative path, and a line number.

Rule file format (preferred):
    NAME<TAB>CLASS<TAB>regex

CLASS is one of: content, path, host, userpath.
Only content-classed rules may be excepted via ci/denylist/allow.tsv.
Backward-compatible lines are still accepted:
    NAME<TAB>regex
    regex
Those unclassed lines load and match, but an allow.tsv entry for them
is refused (fail closed) until the rule is given a CLASS.

allow.tsv columns: path<TAB>rule<TAB>line_sha256<TAB>reason
- path is exact and repo-relative (no globs, no leading slash, no ..).
- line_sha256 is the SHA-256 hex digest of the UTF-8 line text with the
  line ending already stripped (the same string str.splitlines() yields).
  Trailing spaces and other whitespace are included in the hash.
- An entry suppresses only that rule, on the line whose hash matches,
  in that exact file. Path, host, and userpath rules cannot be excepted.
- Stale entries, malformed rows, hash mismatches, and wrong-rule rows
  fail the scan. Hits in allow.tsv itself cannot be excepted.

--hash-line path:line prints that line's sha256 and the names of rules
that hit it. It never prints the line text or a rule body.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import fork_secret_gate

ENV_VAR = "DENYLIST_PATTERNS_B64"
GENERIC_CONFIG_ERROR = "denylist: configuration is missing or invalid"
DEFAULT_ALLOW = Path("ci/denylist/allow.tsv")
ALLOW_HEADER = ("path", "rule", "line_sha256", "reason")
VALID_CLASSES = frozenset({"content", "path", "host", "userpath"})
EXCEPTABLE_CLASSES = frozenset({"content"})
NON_EXCEPTABLE_CLASSES = frozenset({"path", "host", "userpath"})

SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "_deps",
    "dist",
    "build",
    ".eggs",
}

# Known text suffixes. Scanning is not limited to this set: any tracked file
# that is valid UTF-8 and contains no NUL is scanned. Skip only real binaries.
TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".md",
    ".txt",
    ".toml",
    ".yml",
    ".yaml",
    ".json",
    ".csv",
    ".tsv",
    ".sh",
    ".cfg",
    ".ini",
    ".rst",
    ".html",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".css",
    ".svg",
    ".xml",
    ".lock",
    ".patch",
    ".base",
    ".sha256",
    ".gitleaksignore",
    ".gitkeep",
}

TEXT_NAMES = {
    "LICENSE",
    "Makefile",
    "Dockerfile",
    "NOTICE",
    "AUTHORS",
    "CONTRIBUTORS",
    "CODEOWNERS",
    ".gitignore",
    ".gitattributes",
    ".gitleaksignore",
    ".gitkeep",
}


@dataclass(frozen=True)
class Rule:
    name: str
    classification: str | None
    pattern: re.Pattern[str]

    @property
    def exceptable(self) -> bool:
        return self.classification in EXCEPTABLE_CLASSES


@dataclass(frozen=True)
class ExceptionEntry:
    path: str
    rule: str
    line_sha256: str
    lineno: int


@dataclass(frozen=True)
class Hit:
    path: str
    lineno: int
    rule: str
    line_sha256: str
    suppressed: bool = False


def find_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists():
            return candidate
    return start


def is_inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def decode_b64(raw: str) -> str:
    compact = "".join(raw.split())
    if not compact:
        raise ValueError("empty")
    return base64.b64decode(compact, validate=True).decode("utf-8")


def line_sha256(line: str) -> str:
    """SHA-256 hex of UTF-8 line text with the line ending already stripped.

    The hashed payload is the same string ``str.splitlines()`` yields:
    no trailing ``\\n``, ``\\r\\n``, or ``\\r``. Other whitespace,
    including trailing spaces, is included.
    """
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _valid_rule_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name))


def parse_rules(text: str) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        classification: str | None = None
        if "\t" not in raw:
            expr = raw
            name = ""
        else:
            fields = raw.split("\t")
            name = fields[0].strip()
            if len(fields) >= 3:
                maybe_class = fields[1].strip()
                if maybe_class in VALID_CLASSES:
                    classification = maybe_class
                    expr = "\t".join(fields[2:])
                else:
                    # Three or more columns but no valid CLASS: fail closed
                    # so a typo like "contents" cannot silently become an
                    # unclassed (and therefore un-exceptable) rule.
                    raise ValueError("bad format")
            else:
                expr = fields[1] if len(fields) > 1 else ""
        if not expr:
            raise ValueError("bad format")
        if not name:
            name = f"rule-{len(rules) + 1}"
        elif not _valid_rule_name(name):
            raise ValueError("bad format")
        if name in seen:
            raise ValueError("duplicate")
        seen.add(name)
        try:
            pattern = re.compile(expr)
        except re.error:
            raise ValueError("bad format") from None
        rules.append(Rule(name=name, classification=classification, pattern=pattern))
    if not rules:
        raise ValueError("empty")
    return rules


def is_text_file(path: Path) -> bool:
    """True when the file is UTF-8 text with no NUL bytes.

    Suffix lists are not exhaustive. A file with an unknown extension is
    still scanned when it decodes as UTF-8 and contains no NUL.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return False
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIR_NAMES for part in rel_parts):
            continue
        if not is_text_file(path):
            continue
        files.append(path)
    return files


def load_rules(root: Path, patterns_arg: Path | None) -> list[Rule]:
    if patterns_arg is not None:
        path = patterns_arg.expanduser().resolve()
        if is_inside(root, path):
            raise PermissionError("inside-root")
        text = path.read_text(encoding="utf-8")
        return parse_rules(text)

    raw = os.environ.get(ENV_VAR)
    if raw is None or raw.strip() == "":
        raise ValueError("missing")
    return parse_rules(decode_b64(raw))


def validate_exception_path(path: str) -> str:
    if not path or path.startswith("/") or "\\" in path:
        raise ValueError("bad path")
    if any(ch in path for ch in "*?["):
        raise ValueError("glob")
    if ".." in path:
        raise ValueError("bad path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("bad path")
    return path


def _is_header_row(fields: list[str]) -> bool:
    if len(fields) < 4:
        return False
    got = tuple(part.strip().lower() for part in fields[:4])
    return got == ALLOW_HEADER


class AllowListError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def load_allow(
    path: Path,
    rules: list[Rule],
    *,
    allow_rel: str,
) -> list[ExceptionEntry]:
    if not path.is_file():
        raise AllowListError(f"denylist: allow file is missing: {allow_rel}")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise AllowListError(f"denylist: allow file is unreadable: {allow_rel}") from exc

    by_name = {rule.name: rule for rule in rules}
    entries: list[ExceptionEntry] = []
    seen: set[tuple[str, str, str]] = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = raw.split("\t")
        # Tolerate a trailing empty field from an editor, but require the
        # four declared columns.
        if len(fields) >= 4 and fields[-1] == "" and len(fields) > 4:
            fields = fields[:-1]
        if _is_header_row(fields):
            continue
        if len(fields) < 4:
            raise AllowListError(f"denylist: malformed allow.tsv line {lineno}")
        # Reason may contain tabs; keep columns 4+ joined.
        rel_path, rule_name, digest, reason = (
            fields[0].strip(),
            fields[1].strip(),
            fields[2].strip().lower(),
            "\t".join(fields[3:]).strip(),
        )
        if not rel_path or not rule_name or not digest or not reason:
            raise AllowListError(f"denylist: malformed allow.tsv line {lineno}")
        try:
            rel_path = validate_exception_path(rel_path)
        except ValueError as exc:
            kind = str(exc)
            if kind == "glob":
                raise AllowListError(
                    f"denylist: exception path on allow.tsv line {lineno} contains a glob or wildcard"
                ) from exc
            raise AllowListError(
                f"denylist: exception path on allow.tsv line {lineno} is not an exact repo-relative path"
            ) from exc
        if rel_path == allow_rel:
            raise AllowListError(
                f"denylist: allow.tsv line {lineno} cannot except a hit in the allow file itself"
            )
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise AllowListError(f"denylist: malformed line_sha256 on allow.tsv line {lineno}")
        if not _valid_rule_name(rule_name) or rule_name not in by_name:
            raise AllowListError(f"denylist: unknown or invalid rule on allow.tsv line {lineno}")
        rule = by_name[rule_name]
        if rule.classification is None:
            raise AllowListError(
                f"denylist: exception refused on allow.tsv line {lineno}: "
                f"rule={rule_name} is unclassed (unclassed rules cannot be excepted)"
            )
        if rule.classification in NON_EXCEPTABLE_CLASSES:
            raise AllowListError(
                f"denylist: exception refused on allow.tsv line {lineno}: "
                f"rule={rule_name} class={rule.classification} "
                "(path/host/userpath rules cannot be excepted)"
            )
        if not rule.exceptable:
            raise AllowListError(
                f"denylist: exception refused on allow.tsv line {lineno}: "
                f"rule={rule_name} cannot be excepted"
            )
        key = (rel_path, rule_name, digest)
        if key in seen:
            raise AllowListError(f"denylist: duplicate exception on allow.tsv line {lineno}")
        seen.add(key)
        entries.append(
            ExceptionEntry(path=rel_path, rule=rule_name, line_sha256=digest, lineno=lineno)
        )
    return entries


def apply_exceptions(
    hits: list[Hit], entries: list[ExceptionEntry]
) -> tuple[list[Hit], int, list[str]]:
    """Return remaining hits, the number of exceptions applied, and errors."""
    errors: list[str] = []
    remaining = list(hits)
    applied = 0
    for entry in entries:
        matching = [
            hit
            for hit in remaining
            if hit.path == entry.path
            and hit.rule == entry.rule
            and hit.line_sha256 == entry.line_sha256
        ]
        if matching:
            suppress = set(id(hit) for hit in matching)
            remaining = [hit for hit in remaining if id(hit) not in suppress]
            applied += 1
            continue
        same_path_rule = [hit for hit in hits if hit.path == entry.path and hit.rule == entry.rule]
        same_path_hash = [
            hit
            for hit in hits
            if hit.path == entry.path and hit.line_sha256 == entry.line_sha256
        ]
        if same_path_rule:
            errors.append(
                f"denylist: hash mismatch: path={entry.path} rule={entry.rule} "
                f"line_sha256={entry.line_sha256} (hit stands)"
            )
        elif same_path_hash:
            errors.append(
                f"denylist: wrong rule: path={entry.path} rule={entry.rule} "
                f"line_sha256={entry.line_sha256} (hit stands; entry is stale)"
            )
        else:
            errors.append(
                f"denylist: stale exception: path={entry.path} rule={entry.rule} "
                f"line_sha256={entry.line_sha256}"
            )
    return remaining, applied, errors


def scan_files(root: Path, rules: list[Rule], files: list[Path]) -> list[Hit]:
    hits: list[Hit] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            digest = line_sha256(line)
            for rule in rules:
                if rule.pattern.search(line):
                    hits.append(Hit(path=rel, lineno=lineno, rule=rule.name, line_sha256=digest))
    return hits


def hash_line(root: Path, rules: list[Rule], spec: str) -> int:
    if ":" not in spec:
        print("denylist: --hash-line requires path:line", file=sys.stderr)
        return 2
    rel, _, line_s = spec.rpartition(":")
    try:
        lineno = int(line_s)
    except ValueError:
        print("denylist: --hash-line line number is invalid", file=sys.stderr)
        return 2
    if not rel or lineno < 1:
        print("denylist: --hash-line requires path:line", file=sys.stderr)
        return 2
    try:
        rel_norm = validate_exception_path(rel)
    except ValueError:
        print("denylist: --hash-line path must be an exact repo-relative path", file=sys.stderr)
        return 2
    path = (root / rel_norm)
    if not path.is_file() or not is_inside(root, path):
        print("denylist: --hash-line path is not a file in the repository", file=sys.stderr)
        return 2
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        print("denylist: --hash-line file could not be read as UTF-8", file=sys.stderr)
        return 2
    lines = text.splitlines()
    if lineno > len(lines):
        print("denylist: --hash-line line number is out of range", file=sys.stderr)
        return 2
    line = lines[lineno - 1]
    digest = line_sha256(line)
    names = [rule.name for rule in rules if rule.pattern.search(line)]
    print(f"{rel_norm}:{lineno}")
    print(f"line_sha256: {digest}")
    if names:
        print("rules: " + ", ".join(names))
    else:
        print("rules: (none)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None, help="repository root (default: discover from cwd)")
    parser.add_argument(
        "--patterns",
        type=Path,
        default=None,
        help="rule file that must resolve outside the repository root",
    )
    parser.add_argument(
        "--allow",
        type=Path,
        default=None,
        help="allow.tsv path (default: <root>/ci/denylist/allow.tsv)",
    )
    parser.add_argument(
        "--hash-line",
        metavar="PATH:LINE",
        default=None,
        help="print sha256 and hitting rule names for a repo-relative path:line (never prints the line or pattern)",
    )
    args = parser.parse_args(argv)
    secret = os.environ.get(ENV_VAR)
    if args.patterns is None and fork_secret_gate.maybe_skip_for_fork_pr(secret):
        return 0

    root = (args.root or find_root(Path.cwd())).resolve()

    try:
        rules = load_rules(root, args.patterns)
    except PermissionError:
        print("denylist: --patterns must be a file outside the repository root", file=sys.stderr)
        return 2
    except Exception:
        print(GENERIC_CONFIG_ERROR, file=sys.stderr)
        return 2

    if args.hash_line:
        return hash_line(root, rules, args.hash_line)

    if args.allow is not None:
        allow_path = args.allow.expanduser()
        if not allow_path.is_absolute():
            # A relative --allow is resolved against the repository root, not cwd,
            # so test fixtures and CI stay consistent.
            allow_path = (root / allow_path).resolve()
        else:
            allow_path = allow_path.resolve()
    else:
        allow_path = (root / DEFAULT_ALLOW).resolve()

    if is_inside(root, allow_path):
        allow_rel = allow_path.relative_to(root.resolve()).as_posix()
    else:
        allow_rel = allow_path.as_posix()

    try:
        entries = load_allow(allow_path, rules, allow_rel=allow_rel)
    except AllowListError as exc:
        print(exc.message, file=sys.stderr)
        return 2
    except Exception:
        print("denylist: allow.tsv is missing or invalid", file=sys.stderr)
        return 2

    files = iter_files(root)
    if is_inside(root, allow_path) and allow_path.is_file() and allow_path not in files:
        files.append(allow_path)

    hits = scan_files(root, rules, files)
    remaining, applied, errors = apply_exceptions(hits, entries)

    if errors:
        print(f"denylist: {len(errors)} allow.tsv error(s)")
        for err in errors[:200]:
            print(f"  {err}")
        if len(errors) > 200:
            print(f"  … {len(errors) - 200} more")

    if remaining:
        print(f"denylist: {len(remaining)} hit(s)")
        for hit in remaining[:200]:
            print(f"  {hit.path}:{hit.lineno}: rule={hit.rule}")
        if len(remaining) > 200:
            print(f"  … {len(remaining) - 200} more")
        print(f"exceptions applied: {applied}")
        return 1

    if errors:
        print(f"exceptions applied: {applied}")
        return 1

    print(f"denylist: no hits ({len(rules)} rules, {len(files)} files scanned)")
    print(f"exceptions applied: {applied}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
