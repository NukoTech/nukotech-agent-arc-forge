"""Unit tests for ci/scripts/author_email_check.py.

Uses a SYNTHETIC HMAC key and synthetic mailbox local-parts at a reserved
invalid domain. These tests never load the repository Actions secret and
never print a key, digest, or email.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import author_email_check  # noqa: E402

# Synthetic 32-byte key. Not used outside these tests.
SYNTH_KEY_HEX = "11" * 32
SYNTH_KEY = bytes.fromhex(SYNTH_KEY_HEX)
_DOMAIN = "example.invalid"


def _addr(local: str) -> str:
    return local + "@" + _DOMAIN


BANNED_EMAIL = _addr("banned")
ALLOWED_EMAIL = _addr("allowed")
OTHER_EMAIL = _addr("other")


def _digest(email: str, key: bytes = SYNTH_KEY) -> str:
    return hmac.new(key, email.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()


def _secret(digests: list[str] | None = None, **overrides: object) -> str:
    payload: dict[str, object] = {
        "v": 1,
        "alg": "hmac-sha256",
        "key_hex": SYNTH_KEY_HEX,
        "digests": digests if digests is not None else [_digest(BANNED_EMAIL)],
    }
    payload.update(overrides)
    return json.dumps(payload)


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    subprocess.run(["git", "-C", str(root), *args], check=True, env=merged, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "synthetic")
    _git(root, "config", "user.email", ALLOWED_EMAIL)
    (root / "README").write_text("ok\n", encoding="utf-8")
    return root


def _commit(root: Path, message: str, *, author: str, committer: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "synthetic-author",
        "GIT_AUTHOR_EMAIL": author,
        "GIT_COMMITTER_NAME": "synthetic-committer",
        "GIT_COMMITTER_EMAIL": committer,
    }
    _git(root, "add", "README")
    _git(root, "commit", "-m", message, env=env)
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    return sha


def _run(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    secret: str | None,
    capsys: pytest.CaptureFixture[str],
    extra: list[str] | None = None,
) -> tuple[int, str, str]:
    if secret is None:
        monkeypatch.delenv(author_email_check.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(author_email_check.ENV_VAR, secret)
    argv = ["--root", str(root)]
    if extra:
        argv += extra
    code = author_email_check.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _assert_no_secrets(combined: str) -> None:
    assert SYNTH_KEY_HEX not in combined
    assert _digest(BANNED_EMAIL) not in combined
    assert BANNED_EMAIL not in combined
    assert ALLOWED_EMAIL not in combined
    assert OTHER_EMAIL not in combined
    assert "key_hex" not in combined
    assert "example.invalid" not in combined


def test_match_author_reports_sha_and_side(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path)
    sha = _commit(root, "banned author", author=BANNED_EMAIL, committer=ALLOWED_EMAIL)
    code, out, err = _run(monkeypatch, root, _secret(), capsys)
    combined = out + err
    assert code == 1
    line = [ln for ln in out.splitlines() if sha in ln][0]
    assert "author" in line
    assert "committer" not in line
    _assert_no_secrets(combined)


def test_no_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path)
    _commit(root, "clean", author=ALLOWED_EMAIL, committer=OTHER_EMAIL)
    code, out, err = _run(monkeypatch, root, _secret(), capsys)
    assert code == 0
    assert "no banned addresses" in out
    _assert_no_secrets(out + err)


def test_match_committer_side(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path)
    sha = _commit(root, "banned committer", author=ALLOWED_EMAIL, committer=BANNED_EMAIL)
    code, out, err = _run(monkeypatch, root, _secret(), capsys)
    combined = out + err
    assert code == 1
    assert sha in out
    line = [ln for ln in out.splitlines() if sha in ln][0]
    assert "committer" in line
    assert "author" not in line
    _assert_no_secrets(combined)


@pytest.mark.parametrize(
    "secret",
    [
        None,
        "",
        "   ",
        "{not-json",
        json.dumps({"v": 2, "alg": "hmac-sha256", "key_hex": SYNTH_KEY_HEX, "digests": ["ab" * 32]}),
        json.dumps({"v": 1, "alg": "sha256", "key_hex": SYNTH_KEY_HEX, "digests": ["ab" * 32]}),
        json.dumps({"v": 1, "alg": "hmac-sha256", "key_hex": "11" * 16, "digests": ["ab" * 32]}),
        json.dumps({"v": 1, "alg": "hmac-sha256", "key_hex": SYNTH_KEY_HEX, "digests": []}),
        json.dumps({"v": 1, "alg": "hmac-sha256", "key_hex": SYNTH_KEY_HEX, "digests": ["xyz"]}),
        json.dumps({"v": 1, "alg": "hmac-sha256", "key_hex": SYNTH_KEY_HEX, "digests": ["ab" * 31]}),
        json.dumps({"v": 1, "alg": "hmac-sha256", "key_hex": SYNTH_KEY_HEX, "digests": [123]}),
        json.dumps({"v": 1, "alg": "hmac-sha256", "key_hex": "not-hex", "digests": ["ab" * 32]}),
    ],
)
def test_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    secret: str | None,
) -> None:
    root = _repo(tmp_path)
    code, out, err = _run(monkeypatch, root, secret, capsys)
    assert code == 2
    assert "missing or invalid" in err
    _assert_no_secrets(out + err)
    if secret:
        # Config body must never be echoed.
        assert secret not in out + err
