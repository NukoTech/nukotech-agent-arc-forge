"""Machine- and capability-specific Hive application adapters."""

from hive_protocol.adapters.base import HiveApplicationAdapter
from hive_protocol.adapters.manifest import AdapterManifest, load_manifest, manifest_digest
from hive_protocol.adapters.registry import AdapterRegistry, RegisteredAdapter

__all__ = [
    "AdapterManifest",
    "AdapterRegistry",
    "HiveApplicationAdapter",
    "RegisteredAdapter",
    "load_manifest",
    "manifest_digest",
]
