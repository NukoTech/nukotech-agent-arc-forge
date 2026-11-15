"""Execution identities and deadlines for adapter mutations."""

from __future__ import annotations

import hashlib
import re
import signal
import threading
import time
from types import FrameType
from typing import Any

from hive_protocol.core import ProtocolError


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def operation_key(request_digest: str, plan_digest: str) -> str:
    if not _SHA256.fullmatch(request_digest) or not _SHA256.fullmatch(plan_digest):
        raise ProtocolError(
            "ADAPTER_OPERATION_KEY_INVALID",
            "operation key inputs must be exact lowercase SHA-256 digests",
        )
    material = (
        b"hive.adapter-operation.v1\0"
        + bytes.fromhex(request_digest)
        + bytes.fromhex(plan_digest)
    )
    return hashlib.sha256(material).hexdigest()


class _ExecutionDeadline:
    def __init__(self, timeout_seconds: int) -> None:
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds < 1
        ):
            raise ProtocolError(
                "ADAPTER_TIMEOUT_INVALID", "adapter timeout must be a positive integer"
            )
        self.timeout_seconds = timeout_seconds
        self.previous_handler: Any = None
        self.previous_delay = 0.0
        self.previous_interval = 0.0
        self.started = 0.0

    @staticmethod
    def _expired(signum: int, frame: FrameType | None) -> None:
        raise ProtocolError(
            "ADAPTER_TIMEOUT_EXCEEDED", "adapter execution exceeded its signed limit"
        )

    def __enter__(self) -> "_ExecutionDeadline":
        if threading.current_thread() is not threading.main_thread() or not hasattr(
            signal, "setitimer"
        ):
            raise ProtocolError(
                "ADAPTER_TIMEOUT_UNAVAILABLE",
                "bounded adapter execution requires the supported main-thread runtime",
            )
        self.previous_handler = signal.getsignal(signal.SIGALRM)
        self.previous_delay, self.previous_interval = signal.getitimer(
            signal.ITIMER_REAL
        )
        effective_timeout = (
            min(float(self.timeout_seconds), self.previous_delay)
            if self.previous_delay > 0
            else float(self.timeout_seconds)
        )
        self.started = time.monotonic()
        signal.signal(signal.SIGALRM, self._expired)
        signal.setitimer(signal.ITIMER_REAL, effective_timeout)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.previous_handler)
        if self.previous_delay > 0:
            remaining = max(
                0.000001, self.previous_delay - (time.monotonic() - self.started)
            )
            signal.setitimer(signal.ITIMER_REAL, remaining, self.previous_interval)
        return False


def execution_deadline(timeout_seconds: int) -> _ExecutionDeadline:
    return _ExecutionDeadline(timeout_seconds)
