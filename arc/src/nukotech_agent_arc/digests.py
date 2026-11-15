"""Constant-time compare helpers for hex digests."""

from __future__ import annotations

import hmac


def digests_equal(left: object, right: object) -> bool:
    """Return True when both values are same-length strings with equal contents."""

    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)
