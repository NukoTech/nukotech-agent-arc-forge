"""Unit tests for fork-PR secret skip vs fail-closed.

Uses only synthetic secret payloads. These tests never print a secret,
its length, or a digest of it.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import author_email_check  # noqa: E402
import denylist_scan  # noqa: E402
import fork_secret_gate  # noqa: E402
import test_author_email_check as author_fixtures  # noqa: E402
import test_denylist_scan as denylist_fixtures  # noqa: E402

FORK = "outsider/nukotech-agent-arc-forge"
ORIGIN = "NukoTech/nukotech-agent-arc-forge"
SYNTH_SECRET = "synthetic-secret-value-not-a-real-credential"
MALFORMED_SECRET = "{not-valid-secret"


def _github(
    monkeypatch: pytest.MonkeyPatch,
    *,
    event: str,
    head: str = "",
    repository: str = ORIGIN,
) -> None:
    monkeypatch.setenv("EVENT_NAME", event)
    monkeypatch.setenv("GITHUB_REPOSITORY", repository)
    if head:
        monkeypatch.setenv("HEAD_REPO", head)
    else:
        monkeypatch.delenv("HEAD_REPO", raising=False)


def _assert_no_secret_leak(combined: str, secret: str | None) -> None:
    if secret:
        assert secret not in combined
    assert SYNTH_SECRET not in combined
    assert MALFORMED_SECRET not in combined
    assert "key_hex" not in combined


def test_fork_with_no_secret_skips() -> None:
    assert fork_secret_gate.should_skip_secret_backed_check(
        secret=None,
        event_name="pull_request",
        head_repo=FORK,
        repository=ORIGIN,
    )
    assert fork_secret_gate.should_skip_secret_backed_check(
        secret="   ",
        event_name="pull_request",
        head_repo=FORK,
        repository=ORIGIN,
    )


def test_same_repo_with_no_secret_fails_closed() -> None:
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=None,
        event_name="pull_request",
        head_repo=ORIGIN,
        repository=ORIGIN,
    )


def test_push_with_no_secret_fails_closed() -> None:
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=None,
        event_name="push",
        head_repo="",
        repository=ORIGIN,
    )


def test_malformed_secret_does_not_skip() -> None:
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=MALFORMED_SECRET,
        event_name="pull_request",
        head_repo=FORK,
        repository=ORIGIN,
    )
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=MALFORMED_SECRET,
        event_name="pull_request",
        head_repo=ORIGIN,
        repository=ORIGIN,
    )
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=MALFORMED_SECRET,
        event_name="push",
        head_repo="",
        repository=ORIGIN,
    )


def test_valid_secret_does_not_skip() -> None:
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=SYNTH_SECRET,
        event_name="pull_request",
        head_repo=FORK,
        repository=ORIGIN,
    )
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=SYNTH_SECRET,
        event_name="pull_request",
        head_repo=ORIGIN,
        repository=ORIGIN,
    )
    assert not fork_secret_gate.should_skip_secret_backed_check(
        secret=SYNTH_SECRET,
        event_name="push",
        head_repo="",
        repository=ORIGIN,
    )


def test_emit_notice_writes_summary_without_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    fork_secret_gate.emit_fork_skip_notice()
    captured = capsys.readouterr()
    text = captured.out + captured.err + summary.read_text(encoding="utf-8")
    assert fork_secret_gate.GITHUB_NOTICE in captured.out
    assert fork_secret_gate.FORK_SKIP_NOTICE in summary.read_text(encoding="utf-8")
    _assert_no_secret_leak(text, SYNTH_SECRET)


def test_author_email_fork_without_secret_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = author_fixtures._repo(tmp_path)
    _github(monkeypatch, event="pull_request", head=FORK)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    code, out, err = author_fixtures._run(monkeypatch, root, None, capsys)
    assert code == 0
    assert fork_secret_gate.FORK_SKIP_NOTICE in out
    assert fork_secret_gate.FORK_SKIP_NOTICE in summary.read_text(encoding="utf-8")
    _assert_no_secret_leak(out + err, None)


def test_author_email_same_repo_without_secret_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = author_fixtures._repo(tmp_path)
    _github(monkeypatch, event="pull_request", head=ORIGIN)
    code, out, err = author_fixtures._run(monkeypatch, root, None, capsys)
    assert code == 2
    assert "missing or invalid" in err
    assert fork_secret_gate.FORK_SKIP_NOTICE not in out + err
    _assert_no_secret_leak(out + err, None)


def test_author_email_push_without_secret_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = author_fixtures._repo(tmp_path)
    _github(monkeypatch, event="push")
    code, out, err = author_fixtures._run(monkeypatch, root, None, capsys)
    assert code == 2
    assert "missing or invalid" in err
    _assert_no_secret_leak(out + err, None)


def test_author_email_malformed_secret_fails_on_fork(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = author_fixtures._repo(tmp_path)
    _github(monkeypatch, event="pull_request", head=FORK)
    code, out, err = author_fixtures._run(monkeypatch, root, MALFORMED_SECRET, capsys)
    assert code == 2
    assert "missing or invalid" in err
    assert MALFORMED_SECRET not in out + err
    _assert_no_secret_leak(out + err, MALFORMED_SECRET)


def test_author_email_valid_secret_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = author_fixtures._repo(tmp_path)
    author_fixtures._commit(
        root,
        "clean",
        author=author_fixtures.ALLOWED_EMAIL,
        committer=author_fixtures.OTHER_EMAIL,
    )
    _github(monkeypatch, event="push")
    secret = author_fixtures._secret()
    code, out, err = author_fixtures._run(monkeypatch, root, secret, capsys)
    assert code == 0
    assert "no banned addresses" in out
    assert fork_secret_gate.FORK_SKIP_NOTICE not in out + err
    _assert_no_secret_leak(out + err, secret)


def _denylist_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    secret: str | None,
    extra: list[str] | None = None,
) -> tuple[int, str, str]:
    if secret is None:
        monkeypatch.delenv(denylist_scan.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(denylist_scan.ENV_VAR, secret)
    argv = extra or []
    code = denylist_scan.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_denylist_fork_without_secret_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _github(monkeypatch, event="pull_request", head=FORK)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    code, out, err = _denylist_main(monkeypatch, capsys, secret=None)
    assert code == 0
    assert fork_secret_gate.FORK_SKIP_NOTICE in out
    assert fork_secret_gate.FORK_SKIP_NOTICE in summary.read_text(encoding="utf-8")
    _assert_no_secret_leak(out + err, None)


def test_denylist_same_repo_without_secret_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _github(monkeypatch, event="pull_request", head=ORIGIN)
    code, out, err = _denylist_main(monkeypatch, capsys, secret=None)
    assert code == 2
    assert "missing or invalid" in err
    assert fork_secret_gate.FORK_SKIP_NOTICE not in out + err
    _assert_no_secret_leak(out + err, None)


def test_denylist_push_without_secret_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _github(monkeypatch, event="push")
    code, out, err = _denylist_main(monkeypatch, capsys, secret=None)
    assert code == 2
    assert "missing or invalid" in err
    _assert_no_secret_leak(out + err, None)


def test_denylist_malformed_secret_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _github(monkeypatch, event="pull_request", head=ORIGIN)
    code, out, err = _denylist_main(monkeypatch, capsys, secret=MALFORMED_SECRET)
    assert code == 2
    assert "missing or invalid" in err
    assert MALFORMED_SECRET not in out + err
    _assert_no_secret_leak(out + err, MALFORMED_SECRET)


def test_denylist_valid_secret_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = denylist_fixtures._repo(tmp_path, {"notes/clean.md": "nothing to see\n"})
    denylist_fixtures._write(
        root / "ci/denylist/allow.tsv",
        denylist_fixtures._allow_text([]),
    )
    rules = denylist_fixtures._classed(
        denylist_fixtures.SYNTH_NAME, "content", denylist_fixtures.SYNTH_PATTERN
    )
    encoded = base64.b64encode(rules.encode("utf-8")).decode("ascii")
    _github(monkeypatch, event="push")
    code, out, err = _denylist_main(
        monkeypatch, capsys, secret=encoded, extra=["--root", str(root)]
    )
    assert code == 0
    assert "denylist: no hits" in out
    assert fork_secret_gate.FORK_SKIP_NOTICE not in out + err
    _assert_no_secret_leak(out + err, encoded)
    assert denylist_fixtures.SYNTH_PATTERN not in out + err
