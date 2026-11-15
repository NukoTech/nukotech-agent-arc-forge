"""Narrow application adapter protocol; authority remains in the runtime."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class HiveApplicationAdapter(Protocol):
    def health(self) -> dict[str, Any]:
        raise NotImplementedError

    def plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def apply(
        self, payload: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        raise NotImplementedError

    def recover(self, operation_key: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def export(
        self, scope: dict[str, Any], *, operation_key: str
    ) -> dict[str, Any]:
        raise NotImplementedError

    def rollback(
        self, rollback_ref: str, *, operation_key: str
    ) -> dict[str, Any]:
        raise NotImplementedError

    def recover_lifecycle(
        self, operation: str, operation_key: str
    ) -> dict[str, Any] | None:
        raise NotImplementedError
