from __future__ import annotations

import time

import pytest

from hive_protocol.adapters.execution import execution_deadline, operation_key
from hive_protocol.core import ProtocolError


def test_operation_key_binds_exact_request_and_plan_digests() -> None:
    exact = operation_key("a" * 64, "b" * 64)

    assert exact == operation_key("a" * 64, "b" * 64)
    assert exact != operation_key("c" * 64, "b" * 64)
    assert exact != operation_key("a" * 64, "d" * 64)
    assert len(exact) == 64


def test_execution_deadline_interrupts_adapter_call() -> None:
    started = time.monotonic()

    with pytest.raises(ProtocolError, match="ADAPTER_TIMEOUT_EXCEEDED"):
        with execution_deadline(1):
            time.sleep(2)

    assert time.monotonic() - started < 1.8
