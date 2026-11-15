"""Unit tests for ci/scripts/denylist_scan.py.

All rule bodies used here are synthetic fixtures created at test time.
These tests never load the repository Actions secret or any private
patterns file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import denylist_scan  # noqa: E402


SYNTH_NAME = "SYNTH_TOKEN"
SYNTH_OTHER = "SYNTH_OTHER"
# Distinctive pattern and line text used only in these tests. Assertions
# on --hash-line check that this pattern body never appears in output.
SYNTH_PATTERN = r"SYNTH_DENY_TOKEN_XYZ"
SYNTH_LINE = "payload includes SYNTH_DENY_TOKEN_XYZ here"
SYNTH_OTHER_PATTERN = r"SYNTH_OTHER_TOKEN_QQQ"
SYNTH_OTHER_LINE = "payload includes SYNTH_OTHER_TOKEN_QQQ here"


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _repo(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    for rel, content in (files or {}).items():
        _write(root / rel, content)
    return root


def _patterns(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "outside" / "patterns.txt"
    _write(path, text)
    return path


def _classed(name: str, classification: str, expr: str) -> str:
    return f"{name}\t{classification}\t{expr}\n"


def _allow_text(rows: list[tuple[str, str, str, str]], *, header: bool = True) -> str:
    lines = ["# test allow.tsv"]
    if header:
        lines.append("path\trule\tline_sha256\treason")
    for path, rule, digest, reason in rows:
        lines.append(f"{path}\t{rule}\t{digest}\t{reason}")
    return "\n".join(lines) + "\n"


def _run(
    root: Path,
    patterns: Path,
    allow: Path | None = None,
    extra: list[str] | None = None,
    capsys: pytest.CaptureFixture[str] | None = None,
) -> tuple[int, str, str]:
    argv = ["--root", str(root), "--patterns", str(patterns)]
    if allow is not None:
        argv += ["--allow", str(allow)]
    if extra:
        argv += extra
    code = denylist_scan.main(argv)
    out = err = ""
    if capsys is not None:
        captured = capsys.readouterr()
        out, err = captured.out, captured.err
    return code, out, err


def test_valid_exception_suppresses_and_reports_count(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/sample.md", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 0
    assert "exceptions applied: 1" in out
    assert "denylist: no hits" in out
    assert "hit(s)" not in out
    assert err == ""


def test_hash_mismatch_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    wrong = denylist_scan.line_sha256("a different line")
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/sample.md", SYNTH_NAME, wrong, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 1
    assert "hash mismatch" in out
    assert f"notes/sample.md:1: rule={SYNTH_NAME}" in out
    assert "exceptions applied: 0" in out


def test_wrong_rule_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(
        tmp_path,
        _classed(SYNTH_NAME, "content", SYNTH_PATTERN)
        + _classed(SYNTH_OTHER, "content", SYNTH_OTHER_PATTERN),
    )
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/sample.md", SYNTH_OTHER, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 1
    assert "wrong rule" in out
    assert "stale" in out
    assert f"notes/sample.md:1: rule={SYNTH_NAME}" in out
    assert "exceptions applied: 0" in out


def test_stale_entry_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": "clean line\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    digest = denylist_scan.line_sha256("clean line")
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/sample.md", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 1
    assert "stale exception" in out
    assert "exceptions applied: 0" in out


def test_glob_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/*.md", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 2
    assert "glob" in err or "wildcard" in err
    assert SYNTH_PATTERN not in out + err


@pytest.mark.parametrize(
    "classification",
    ["path", "host", "userpath"],
)
def test_path_host_userpath_class_entry_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], classification: str
) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, classification, SYNTH_PATTERN))
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/sample.md", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 2
    assert "cannot be excepted" in err
    assert f"class={classification}" in err


def test_unclassed_rule_entry_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    # Backward-compatible NAME<TAB>regex line, no CLASS.
    patterns = _patterns(tmp_path, f"{SYNTH_NAME}\t{SYNTH_PATTERN}\n")
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/sample.md", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 2
    assert "unclassed" in err
    assert "cannot be excepted" in err


def test_malformed_row_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    allow = _write(
        root / "ci/denylist/allow.tsv",
        "# test\npath\trule\tline_sha256\treason\nnotes/sample.md\tonly-two-columns\n",
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 2
    assert "malformed" in err


def test_allow_tsv_itself_is_scanned(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/clean.md": "nothing to see\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("notes/clean.md", SYNTH_NAME, denylist_scan.line_sha256("nothing to see"), SYNTH_LINE)]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    # The reason smuggles the denied token; that hit must stand. The
    # exception itself is also stale (notes/clean.md does not hit), but
    # an attempt to except the allow file is refused separately in
    # another test. Here the reason is scanned as file content.
    assert code != 0
    combined = out + err
    assert "ci/denylist/allow.tsv" in combined
    assert f"rule={SYNTH_NAME}" in combined
    # Never echo the pattern body.
    assert SYNTH_PATTERN not in combined


def test_exception_targeting_allow_file_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path)
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("ci/denylist/allow.tsv", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 2
    assert "allow file itself" in err or "allow.tsv" in err


def test_hash_line_prints_hash_and_rule_names_without_pattern(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    # allow.tsv is not required for --hash-line; still ship an empty one
    # so a default-path run would work.
    _write(root / "ci/denylist/allow.tsv", _allow_text([]))
    expected = denylist_scan.line_sha256(SYNTH_LINE)
    code, out, err = _run(
        root,
        patterns,
        extra=["--hash-line", "notes/sample.md:1"],
        capsys=capsys,
    )
    assert code == 0
    assert f"line_sha256: {expected}" in out
    assert f"rules: {SYNTH_NAME}" in out
    assert "notes/sample.md:1" in out
    assert SYNTH_PATTERN not in out
    assert SYNTH_PATTERN not in err
    assert SYNTH_LINE not in out
    assert SYNTH_LINE not in err
    assert err == ""


def test_empty_allow_reports_zero_exceptions(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/clean.md": "nothing to see\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    allow = _write(root / "ci/denylist/allow.tsv", _allow_text([]))
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 0
    assert "exceptions applied: 0" in out
    assert "denylist: no hits" in out


def test_named_hits_print_rule_name_not_index(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    allow = _write(root / "ci/denylist/allow.tsv", _allow_text([]))
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 1
    assert f"rule={SYNTH_NAME}" in out
    assert "rule=rule-1" not in out


def test_leading_slash_path_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("/notes/sample.md", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 2
    assert "exact repo-relative path" in err


def test_dotdot_path_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    digest = denylist_scan.line_sha256(SYNTH_LINE)
    allow = _write(
        root / "ci/denylist/allow.tsv",
        _allow_text([("../notes/sample.md", SYNTH_NAME, digest, "documented test fixture")]),
    )
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 2
    assert "exact repo-relative path" in err or "glob" in err


def test_plain_regex_line_still_loads_and_is_not_exceptable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path, {"notes/sample.md": SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, f"{SYNTH_PATTERN}\n")
    allow = _write(root / "ci/denylist/allow.tsv", _allow_text([]))
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 1
    assert "rule=rule-1" in out
    assert SYNTH_PATTERN not in out
    assert SYNTH_PATTERN not in err


@pytest.mark.parametrize(
    "rel",
    [
        "notes/sample.patch",
        "notes/sample.base",
        "notes/sample.sha256",
        ".gitleaksignore",
        "empty/.gitkeep",
        "notes/no_suffix_readme",
        "notes/custom.unknownext",
    ],
)
def test_previously_skipped_text_suffixes_are_scanned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], rel: str
) -> None:
    root = _repo(tmp_path, {rel: SYNTH_LINE + "\n"})
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    allow = _write(root / "ci/denylist/allow.tsv", _allow_text([]))
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 1
    assert f"{rel}:1: rule={SYNTH_NAME}" in out
    assert SYNTH_PATTERN not in out + err


def test_nul_byte_file_is_skipped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/clean.md": "nothing to see\n"})
    binary = root / "notes" / "blob.bin"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"payload includes SYNTH_DENY_TOKEN_XYZ\x00here\n")
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    allow = _write(root / "ci/denylist/allow.tsv", _allow_text([]))
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 0
    assert "denylist: no hits" in out
    assert "blob.bin" not in out


def test_invalid_utf8_file_is_skipped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path, {"notes/clean.md": "nothing to see\n"})
    binary = root / "notes" / "blob.dat"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"payload includes SYNTH_DENY_TOKEN_XYZ \xff\xfe")
    patterns = _patterns(tmp_path, _classed(SYNTH_NAME, "content", SYNTH_PATTERN))
    allow = _write(root / "ci/denylist/allow.tsv", _allow_text([]))
    code, out, err = _run(root, patterns, allow, capsys=capsys)
    assert code == 0
    assert "denylist: no hits" in out
    assert "blob.dat" not in out


def test_known_text_suffixes_include_rc1_additions() -> None:
    for suffix in (".patch", ".base", ".sha256", ".gitleaksignore", ".gitkeep"):
        assert suffix in denylist_scan.TEXT_SUFFIXES
