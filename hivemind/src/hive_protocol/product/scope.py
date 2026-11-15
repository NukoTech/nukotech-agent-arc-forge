"""Attended authority scope defaults, configurable once per process.

``HIVE_TENANT_ID`` and ``HIVE_PROJECT_ID`` override the built-in
``local-user`` / ``HiveMind`` defaults. They are read only here, at import,
and are used for new Hive configuration, legacy Hive fallbacks, the attended
adapter authority and the loadout scope check.
"""

import os
import re

from hive_protocol.core import ProtocolError

SCOPE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
DEFAULT_TENANT_ID = "local-user"
DEFAULT_PROJECT_ID = "HiveMind"


def _setting(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    if SCOPE_ID.fullmatch(value) is None:
        raise ProtocolError(
            "VAULT_SCOPE_INVALID",
            f"{name} must be 1-128 characters of A-Z, a-z, 0-9, '.', '_', ':' or '-'",
        )
    return value


# Captured once: changing the environment later must not relabel a live
# adapter authority, its grants or an already open Hive.
TENANT_ID = _setting("HIVE_TENANT_ID", DEFAULT_TENANT_ID)
ADAPTER_PROJECT_ID = _setting("HIVE_PROJECT_ID", DEFAULT_PROJECT_ID)
if TENANT_ID == ADAPTER_PROJECT_ID:
    raise ProtocolError("VAULT_SCOPE_INVALID", "configured tenant and project must differ")
