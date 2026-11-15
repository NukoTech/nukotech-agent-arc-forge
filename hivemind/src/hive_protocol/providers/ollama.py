"""Loopback-only Ollama adapter with explicit capability discovery."""

from __future__ import annotations

import json
from http.client import HTTPConnection
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ..core import ProtocolError


@dataclass(frozen=True)
class ProviderCapability:
    available: bool
    provider: str
    model: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "provider": self.provider,
            "model": self.model,
            "reason": self.reason,
        }


class OllamaLocalProvider:
    """Use Ollama without credentials or non-loopback network access."""

    def __init__(
        self,
        model: str | None,
        *,
        embedding_model: str | None = None,
        base_url: str = "http://127.0.0.1:11434",
        timeout_seconds: float = 15.0,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ProtocolError(
                "PROVIDER_BOUNDARY",
                "local provider URL must use HTTP on a loopback host",
            )
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ProtocolError("PROVIDER_BOUNDARY", "provider URL may not contain credentials or query data")
        self.model = model
        self.embedding_model = embedding_model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._host = parsed.hostname
        self._port = parsed.port or 11434

    def _request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        connection = HTTPConnection(self._host, self._port, timeout=self.timeout_seconds)
        try:
            connection.request(
                "GET" if body is None else "POST",
                path,
                body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if response.status < 200 or response.status >= 300:
                raise ProtocolError(
                    "LOCAL_PROVIDER_UNAVAILABLE", f"loopback Ollama returned HTTP {response.status}"
                )
            result = json.loads(response.read().decode("utf-8"))
        except (TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("LOCAL_PROVIDER_UNAVAILABLE", "loopback Ollama request failed") from exc
        finally:
            connection.close()
        if not isinstance(result, dict):
            raise ProtocolError("LOCAL_PROVIDER_INVALID", "Ollama returned a non-object response")
        return result

    def _available_models(self) -> set[str]:
        result = self._request("/api/tags")
        models = result.get("models", [])
        return {
            name
            for item in models
            if isinstance(item, dict)
            and isinstance((name := item.get("name")), str)
        }

    def chat_capability(self) -> ProviderCapability:
        if not self.model:
            return ProviderCapability(False, "ollama-loopback", None, "NO_MODEL_CONFIGURED")
        try:
            available = self._available_models()
        except ProtocolError:
            return ProviderCapability(False, "ollama-loopback", self.model, "ENDPOINT_UNAVAILABLE")
        if self.model not in available:
            return ProviderCapability(False, "ollama-loopback", self.model, "MODEL_NOT_INSTALLED")
        return ProviderCapability(True, "ollama-loopback", self.model, "AVAILABLE")

    def embedding_capability(self) -> ProviderCapability:
        if not self.embedding_model:
            return ProviderCapability(False, "ollama-loopback", None, "NO_EMBEDDING_MODEL_CONFIGURED")
        try:
            available = self._available_models()
        except ProtocolError:
            return ProviderCapability(
                False, "ollama-loopback", self.embedding_model, "ENDPOINT_UNAVAILABLE"
            )
        if self.embedding_model not in available:
            return ProviderCapability(
                False, "ollama-loopback", self.embedding_model, "MODEL_NOT_INSTALLED"
            )
        return ProviderCapability(True, "ollama-loopback", self.embedding_model, "AVAILABLE")

    def chat(self, system: str, user: str) -> str:
        capability = self.chat_capability()
        if not capability.available or not self.model:
            raise ProtocolError("LOCAL_MODEL_UNAVAILABLE", capability.reason)
        result = self._request(
            "/api/chat",
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "think": False,
                "options": {"temperature": 0},
            },
        )
        message = result.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ProtocolError("LOCAL_PROVIDER_INVALID", "Ollama returned no answer text")
        return content.strip()

    def embed(self, text: str) -> list[float]:
        capability = self.embedding_capability()
        if not capability.available or not self.embedding_model:
            raise ProtocolError("LOCAL_EMBEDDING_UNAVAILABLE", capability.reason)
        result = self._request(
            "/api/embed", {"model": self.embedding_model, "input": text, "truncate": False}
        )
        embeddings = result.get("embeddings")
        vector = embeddings[0] if isinstance(embeddings, list) and embeddings else None
        if not isinstance(vector, list) or not vector or not all(
            isinstance(value, (int, float)) for value in vector
        ):
            raise ProtocolError("LOCAL_PROVIDER_INVALID", "Ollama returned no numeric embedding")
        return [float(value) for value in vector]
