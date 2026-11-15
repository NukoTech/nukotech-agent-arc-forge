"""Keychain references only: configuration never accepts secret material."""

from __future__ import annotations

import re

from hive_protocol.core import ProtocolError

_REF = re.compile(r"^keychain:[A-Za-z0-9._:/-]{1,256}$")


def require_keychain_reference(reference: str, *, available: bool) -> str:
    if not _REF.fullmatch(reference):
        raise ProtocolError("KEYCHAIN_REFERENCE_REQUIRED", "only a Keychain reference is permitted")
    if not available:
        raise ProtocolError("KEYCHAIN_REFERENCE_UNAVAILABLE", "referenced Keychain item is unavailable")
    return reference
