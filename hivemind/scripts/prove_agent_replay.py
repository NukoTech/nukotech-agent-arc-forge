#!/usr/bin/env python3
"""Deliver one signed disposable task and prove exact replay refusal."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from hive_protocol.agents import AgentOperations, build_signed_task
from hive_protocol.core import ProtocolError, document_digest, load_private_key


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: prove_agent_replay.py VAULT")
    vault = Path(sys.argv[1]).expanduser().resolve()
    agent_id = "alpha-researcher"
    key = load_private_key(vault / ".hive" / "keys" / "agents" / f"{agent_id}.private.pem")
    now = datetime.now(timezone.utc)
    task = build_signed_task(
        {
            "schema_version": "hive.task-envelope.v1",
            "task_id": str(uuid4()),
            "tenant_id": "local-user",
            "workspace_id": "local-hive",
            "sender_agent": agent_id,
            "recipient_agent": agent_id,
            "required_capabilities": ["vault:search"],
            "required_trust": "OBSERVE",
            "operation": "replay.proof",
            "payload": {"kind": "search", "query": "rollback"},
            "provenance": ["nukotech-hive-local-alpha-v0.1.0", "linux-x86_64-emulated-proof"],
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
            "nonce": uuid4().hex,
        },
        key,
    )
    operations = AgentOperations(vault / ".hive" / "agent-operations")
    delivered = operations.deliver(task)
    reason_code = None
    try:
        operations.deliver(task)
    except ProtocolError as exc:
        reason_code = exc.code
    if reason_code != "REPLAY_MESSAGE_ID":
        raise SystemExit(f"replay was not rejected as expected: {reason_code}")
    print(
        json.dumps(
            {
                "outcome": "REPLAY_REJECTED",
                "reason_code": reason_code,
                "first_delivery": delivered["status"],
                "task_id": task["task_id"],
                "task_sha256": document_digest(task),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
