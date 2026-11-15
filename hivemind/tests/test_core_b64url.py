from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive_protocol.core import (
    ProtocolError,
    _b64url_decode,
    _b64url_encode,
    b64url_decode_strict,
    b64url_encode,
    sign_document,
    verify_document,
)


_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _signed() -> tuple[dict, dict, str]:
    key = Ed25519PrivateKey.generate()
    signed = sign_document({"schema_version": "test.v1", "n": 1}, key)
    value = signed["signature"]["value"]
    keys = {signed["signature"]["key_id"]: key.public_key()}
    return signed, keys, value


def _with_value(signed: dict, value: str) -> dict:
    candidate = json.loads(json.dumps(signed))
    candidate["signature"]["value"] = value
    return candidate


def _lenient_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def test_canonical_signature_verifies_and_strict_decode_roundtrips() -> None:
    signed, keys, value = _signed()
    verify_document(signed, keys)
    raw = b64url_decode_strict(value, expected_len=64)
    assert len(raw) == 64
    assert b64url_encode(raw) == value
    assert _b64url_decode(value) == raw
    assert _b64url_encode(raw) == value


def test_verify_document_rejects_flipped_trailing_bit_variant() -> None:
    signed, keys, value = _signed()
    non_canonical = value[:-1] + _ALPHABET[_ALPHABET.index(value[-1]) ^ 1]
    assert non_canonical != value
    # A lenient decoder would accept the same 64 bytes; only the encoding differs.
    assert _lenient_decode(non_canonical) == _lenient_decode(value)
    assert len(_lenient_decode(non_canonical)) == 64
    assert b64url_encode(_lenient_decode(non_canonical)) == value

    with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
        b64url_decode_strict(non_canonical, expected_len=64)
    with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
        verify_document(_with_value(signed, non_canonical), keys)
    verify_document(signed, keys)


def test_verify_document_rejects_padded_signature() -> None:
    signed, keys, value = _signed()
    padded = value + "=="
    with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
        b64url_decode_strict(padded, expected_len=64)
    with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
        verify_document(_with_value(signed, padded), keys)


def test_verify_document_rejects_whitespace_in_signature() -> None:
    signed, keys, value = _signed()
    for mutated in (
        " " + value,
        value + " ",
        value[:10] + " " + value[10:],
        "\t" + value,
        value + "\n",
    ):
        with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
            b64url_decode_strict(mutated, expected_len=64)
        with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
            verify_document(_with_value(signed, mutated), keys)


def test_verify_document_rejects_wrong_length_signature() -> None:
    signed, keys, value = _signed()
    for mutated in (
        value + "A",  # 87 characters
        value[:-2],  # decodes to 63 bytes
        value + "A" * 86,  # decodes to 128 bytes
    ):
        with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
            b64url_decode_strict(mutated, expected_len=64)
        with pytest.raises(ProtocolError, match="INVALID_BASE64URL"):
            verify_document(_with_value(signed, mutated), keys)
