"""Strict YAML input boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class DuplicateKeyError(ValueError):
    """Raised when a YAML mapping contains the same key more than once."""

    def __init__(self, path: Path, key: str, line: int) -> None:
        self.path = path
        self.key = key
        self.line = line
        super().__init__(f"{path}:{line}: duplicate YAML key {key!r}")


class StrictSafeLoader(yaml.SafeLoader):
    """Safe loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: StrictSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            path = Path(getattr(loader, "source_path", "<memory>"))
            raise DuplicateKeyError(path, str(key), key_node.start_mark.line + 1)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_yaml_strict(path: Path) -> dict[str, Any]:
    """Load one YAML document as a mapping and reject ambiguous input."""

    source = Path(path)
    loader = StrictSafeLoader(source.read_text(encoding="utf-8"))
    loader.source_path = source
    try:
        value = loader.get_single_data()
    finally:
        loader.dispose()
    if not isinstance(value, dict):
        raise TypeError(f"{source}: top-level YAML value must be a mapping")
    return value
