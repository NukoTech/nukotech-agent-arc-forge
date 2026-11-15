"""Deterministic local normalization with bounded injectable multimodal providers."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Mapping, Protocol

from hive_protocol.adapters.security import reject_credential_values
from hive_protocol.core import ProtocolError

from .models import CitationAnchor
from .security import (
    enforce_container_boundary,
    enforce_media_signature,
    prompt_injection_flags,
)


_CHANNELS = frozenset(
    {
        "TEXT",
        "MARKDOWN",
        "CLIPBOARD",
        "FILE",
        "FOLDER_HANDOFF",
        "BROWSER_HANDOFF",
        "WEBPAGE_SNAPSHOT",
        "PDF",
        "IMAGE",
        "AUDIO",
        "VIDEO",
        "MEETING_RECORDING",
        "TRANSCRIPT",
    }
)
_PROVIDER_CHANNELS = frozenset(
    {"PDF", "IMAGE", "AUDIO", "VIDEO", "MEETING_RECORDING"}
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
_TRANSFORMATION = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_TIMESTAMP = re.compile(
    r"^(?:(\d{2}):)?(\d{2}):(\d{2})[.,](\d{3})\s+-->\s+"
    r"(?:(\d{2}):)?(\d{2}):(\d{2})[.,](\d{3})$"
)


@dataclass(frozen=True)
class CaptureLimits:
    max_input_bytes: int = 10 * 1024 * 1024
    max_output_bytes: int = 10 * 1024 * 1024
    max_segments: int = 10_000
    max_anchors: int = 100_000
    max_pages: int = 1_000
    max_duration_ms: int = 24 * 60 * 60 * 1_000
    max_segment_bytes: int = 16_384

    def __post_init__(self) -> None:
        for name in (
            "max_input_bytes",
            "max_output_bytes",
            "max_segments",
            "max_anchors",
            "max_pages",
            "max_duration_ms",
            "max_segment_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ProviderCapability:
    available: bool
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.available, bool) or _TRANSFORMATION.fullmatch(
            self.reason
        ) is None:
            raise ProtocolError(
                "CAPTURE_PROVIDER_CAPABILITY_INVALID",
                "normalization provider capability is malformed",
            )


class NormalizationProvider(Protocol):
    def capability(self) -> ProviderCapability: ...

    def normalize(
        self, payload: bytes, *, media_type: str, filename: str
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class NormalizedSegment:
    text: str
    locator: dict[str, Any]
    char_start: int
    char_end: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "locator", copy.deepcopy(self.locator))


@dataclass(frozen=True)
class NormalizationResult:
    status: str
    media_type: str
    parser: dict[str, str] | None
    normalized_text: str | None
    segments: list[NormalizedSegment]
    transformations: list[str]
    risk_flags: list[str]
    provider_reason: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "parser", copy.deepcopy(self.parser))
        object.__setattr__(self, "segments", copy.deepcopy(self.segments))
        object.__setattr__(self, "transformations", list(self.transformations))
        object.__setattr__(self, "risk_flags", list(self.risk_flags))

    def citation_anchors(
        self, *, source_id: str, source_sha256: str
    ) -> list[CitationAnchor]:
        if self.normalized_text is None:
            return []
        return [
            CitationAnchor.from_text(
                source_id=source_id,
                source_sha256=source_sha256,
                normalized_text=self.normalized_text,
                char_start=segment.char_start,
                char_end=segment.char_end,
                locator=segment.locator,
            )
            for segment in self.segments
        ]


class _HTMLBlocks(HTMLParser):
    _BLOCKS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6", "p", "li"})
    _IGNORED = frozenset({"head", "script", "style", "template", "noscript"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[str] = []
        self.current_tag: str | None = None
        self.current: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        if lowered in self._IGNORED:
            self.ignored_depth += 1
            return
        if self.ignored_depth == 0 and lowered in self._BLOCKS:
            self._flush()
            self.current_tag = lowered

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in self._IGNORED:
            self.ignored_depth = max(0, self.ignored_depth - 1)
            return
        if self.ignored_depth == 0 and lowered == self.current_tag:
            self._flush()

    def handle_data(self, data: str) -> None:
        if self.ignored_depth == 0 and self.current_tag is not None:
            self.current.append(data)

    def close(self) -> None:
        super().close()
        self._flush()

    def _flush(self) -> None:
        if self.current_tag is not None:
            value = " ".join(" ".join(self.current).split())
            if value:
                if self.current_tag.startswith("h"):
                    value = f"{'#' * int(self.current_tag[1])} {value}"
                elif self.current_tag == "li":
                    value = f"- {value}"
                self.blocks.append(value)
        self.current_tag = None
        self.current = []


def _decode_utf8(payload: bytes) -> str:
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ProtocolError(
            "CAPTURE_TEXT_ENCODING_INVALID", "capture text must be valid UTF-8"
        ) from exc


def _text_segments(text: str) -> tuple[str, list[NormalizedSegment]]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    segments: list[NormalizedSegment] = []
    offset = 0
    for line_number, line in enumerate(normalized.splitlines(keepends=True), start=1):
        value = line.rstrip("\n")
        if value.strip():
            start = offset
            end = offset + len(value)
            segments.append(
                NormalizedSegment(
                    value,
                    {
                        "kind": "line",
                        "line_start": line_number,
                        "line_end": line_number,
                    },
                    start,
                    end,
                )
            )
        offset += len(line)
    return normalized, segments


def _provider_segments(
    raw_segments: Any, *, limits: CaptureLimits
) -> tuple[str, list[NormalizedSegment]]:
    if not isinstance(raw_segments, list):
        raise ProtocolError(
            "CAPTURE_PROVIDER_OUTPUT_INVALID", "provider segments must be an array"
        )
    if len(raw_segments) > limits.max_segments or len(raw_segments) > limits.max_anchors:
        raise ProtocolError(
            "CAPTURE_PROVIDER_OUTPUT_LIMIT", "provider returned too many segments"
        )
    validated: list[tuple[str, dict[str, Any]]] = []
    for raw in raw_segments:
        if not isinstance(raw, Mapping) or set(raw) != {"text", "locator"}:
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_INVALID", "provider segment shape is invalid"
            )
        text = raw["text"]
        locator = raw["locator"]
        if (
            not isinstance(text, str)
            or not text.strip()
            or len(text.encode("utf-8")) > limits.max_segment_bytes
            or not isinstance(locator, Mapping)
        ):
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_INVALID", "provider segment value is invalid"
            )
        locator_copy = copy.deepcopy(dict(locator))
        _validate_locator(locator_copy, limits=limits)
        reject_credential_values(text, location="normalization provider segment")
        validated.append((text.strip(), locator_copy))
    normalized = "\n\n".join(text for text, _ in validated)
    if normalized:
        normalized += "\n"
    if len(normalized.encode("utf-8")) > limits.max_output_bytes:
        raise ProtocolError(
            "CAPTURE_PROVIDER_OUTPUT_LIMIT", "provider normalized output is too large"
        )
    segments: list[NormalizedSegment] = []
    cursor = 0
    for text, locator in validated:
        start = normalized.index(text, cursor)
        end = start + len(text)
        segments.append(NormalizedSegment(text, locator, start, end))
        cursor = end
    return normalized, segments


def _validate_locator(locator: dict[str, Any], *, limits: CaptureLimits) -> None:
    kind = locator.get("kind")
    if kind == "page" and set(locator) == {"kind", "page"}:
        page = locator["page"]
        if (
            not isinstance(page, int)
            or isinstance(page, bool)
            or page < 1
            or page > limits.max_pages
        ):
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_LIMIT", "provider page limit was exceeded"
            )
        return
    if kind == "time" and set(locator) == {
        "kind",
        "time_start_ms",
        "time_end_ms",
    }:
        start = locator["time_start_ms"]
        end = locator["time_end_ms"]
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end <= start
            or end > limits.max_duration_ms
        ):
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_LIMIT", "provider duration limit was exceeded"
            )
        return
    if kind == "region" and set(locator) == {
        "kind",
        "x",
        "y",
        "width",
        "height",
    }:
        values = [locator[name] for name in ("x", "y", "width", "height")]
        if not all(isinstance(value, (int, float)) for value in values) or any(
            value < 0 for value in values[:2]
        ) or any(value <= 0 for value in values[2:]):
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_INVALID", "provider region is invalid"
            )
        return
    if kind == "line" and set(locator) == {"kind", "line_start", "line_end"}:
        start = locator["line_start"]
        end = locator["line_end"]
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 1
            or end < start
        ):
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_INVALID", "provider line range is invalid"
            )
        return
    raise ProtocolError(
        "CAPTURE_PROVIDER_OUTPUT_INVALID", "provider locator is invalid"
    )


def _timestamp_ms(groups: tuple[str | None, ...]) -> int:
    hours, minutes, seconds, millis = groups
    return (
        int(hours or 0) * 3_600_000
        + int(minutes or 0) * 60_000
        + int(seconds or 0) * 1_000
        + int(millis or 0)
    )


def _transcript_segments(
    text: str, *, limits: CaptureLimits
) -> tuple[str, list[NormalizedSegment]]:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    raw_segments: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        match = _TIMESTAMP.fullmatch(lines[index].strip())
        if match is None:
            index += 1
            continue
        start = _timestamp_ms(match.groups()[:4])
        end = _timestamp_ms(match.groups()[4:])
        index += 1
        payload_lines: list[str] = []
        while index < len(lines) and lines[index].strip():
            payload_lines.append(lines[index].strip())
            index += 1
        value = " ".join(payload_lines).strip()
        if value:
            raw_segments.append(
                {
                    "text": value,
                    "locator": {
                        "kind": "time",
                        "time_start_ms": start,
                        "time_end_ms": end,
                    },
                }
            )
    if not raw_segments:
        raise ProtocolError(
            "CAPTURE_TRANSCRIPT_INVALID", "transcript has no bounded timestamp spans"
        )
    return _provider_segments(raw_segments, limits=limits)


class NormalizerRegistry:
    def __init__(
        self,
        *,
        providers: Mapping[str, NormalizationProvider] | None = None,
        limits: CaptureLimits | None = None,
    ) -> None:
        self.providers = {
            str(channel).upper(): provider
            for channel, provider in (providers or {}).items()
        }
        if any(channel not in _PROVIDER_CHANNELS for channel in self.providers):
            raise ProtocolError(
                "CAPTURE_PROVIDER_CHANNEL_INVALID", "provider channel is unsupported"
            )
        self.limits = limits or CaptureLimits()

    def describe(self, channel: str) -> dict[str, Any]:
        """Return the bounded provider decision used by a signed capture plan."""

        normalized_channel = channel.upper() if isinstance(channel, str) else ""
        if normalized_channel not in _CHANNELS:
            raise ProtocolError(
                "CAPTURE_NORMALIZATION_INPUT_INVALID", "capture channel is unsupported"
            )
        if normalized_channel in _PROVIDER_CHANNELS:
            provider = self.providers.get(normalized_channel)
            capability = (
                provider.capability()
                if provider is not None
                else ProviderCapability(False, "NO_PROVIDER_CONFIGURED")
            )
            if not isinstance(capability, ProviderCapability):
                raise ProtocolError(
                    "CAPTURE_PROVIDER_CAPABILITY_INVALID",
                    "normalization provider returned an invalid capability",
                )
            provider_state = "AVAILABLE" if capability.available else "UNAVAILABLE"
            provider_reason = capability.reason
            parser_strategy = "INJECTED_PROVIDER"
        else:
            provider_state = "AVAILABLE"
            provider_reason = "BUILTIN_LOCAL"
            parser_strategy = "BUILTIN_LOCAL"
        return {
            "provider_state": provider_state,
            "provider_reason": provider_reason,
            "parser_strategy": parser_strategy,
            "missing_provider_behavior": "QUEUED_PROVIDER",
            "max_output_bytes": self.limits.max_output_bytes,
            "max_segments": self.limits.max_segments,
            "max_anchors": self.limits.max_anchors,
            "max_pages": self.limits.max_pages,
            "max_duration_ms": self.limits.max_duration_ms,
        }

    def normalize(
        self,
        *,
        channel: str,
        payload: bytes,
        media_type: str,
        filename: str,
    ) -> NormalizationResult:
        normalized_channel = channel.upper() if isinstance(channel, str) else ""
        if (
            normalized_channel not in _CHANNELS
            or not isinstance(payload, bytes)
            or not isinstance(media_type, str)
            or not media_type
            or not isinstance(filename, str)
            or not filename
        ):
            raise ProtocolError(
                "CAPTURE_NORMALIZATION_INPUT_INVALID",
                "capture channel, bytes, media type, and filename are required",
            )
        if (
            filename != filename.strip()
            or filename in {".", ".."}
            or len(filename.encode("utf-8")) > 255
            or any(character in filename for character in ("/", "\\", "\x00"))
            or any(ord(character) < 32 for character in filename)
        ):
            raise ProtocolError(
                "CAPTURE_FILENAME_INVALID",
                "capture filename must be one bounded basename",
            )
        if len(payload) > self.limits.max_input_bytes:
            raise ProtocolError(
                "CAPTURE_INPUT_LIMIT_EXCEEDED", "capture input exceeds its byte limit"
            )
        enforce_container_boundary(payload, media_type)
        enforce_media_signature(payload, media_type)

        if normalized_channel in _PROVIDER_CHANNELS:
            return self._normalize_with_provider(
                normalized_channel, payload, media_type=media_type, filename=filename
            )
        text = _decode_utf8(payload)
        reject_credential_values(text, location="capture source text")
        if normalized_channel in {"WEBPAGE_SNAPSHOT", "BROWSER_HANDOFF"} or media_type.lower() == "text/html":
            parser = _HTMLBlocks()
            parser.feed(text)
            parser.close()
            normalized, segments = _provider_segments(
                [
                    {
                        "text": block,
                        "locator": {
                            "kind": "line",
                            "line_start": index,
                            "line_end": index,
                        },
                    }
                    for index, block in enumerate(parser.blocks, start=1)
                ],
                limits=self.limits,
            )
            parser_document = {"parser_id": "builtin.html", "version": "1.0.0"}
            transformations = ["UTF8_DECODE", "HTML_TEXT_EXTRACTION"]
        elif normalized_channel == "TRANSCRIPT" or media_type.lower() in {
            "text/vtt",
            "application/x-subrip",
        }:
            normalized, segments = _transcript_segments(text, limits=self.limits)
            parser_document = {
                "parser_id": "builtin.transcript",
                "version": "1.0.0",
            }
            transformations = ["UTF8_DECODE", "TRANSCRIPT_NORMALIZATION"]
        else:
            normalized, segments = _text_segments(text)
            if len(normalized.encode("utf-8")) > self.limits.max_output_bytes:
                raise ProtocolError(
                    "CAPTURE_PROVIDER_OUTPUT_LIMIT",
                    "normalized text exceeds its output limit",
                )
            if len(segments) > self.limits.max_segments:
                raise ProtocolError(
                    "CAPTURE_PROVIDER_OUTPUT_LIMIT",
                    "normalized text has too many segments",
                )
            parser_document = {
                "parser_id": "builtin.markdown"
                if normalized_channel == "MARKDOWN"
                else "builtin.text",
                "version": "1.0.0",
            }
            transformations = ["UTF8_DECODE"]
            if b"\r" in payload:
                transformations.append("NEWLINE_NORMALIZATION")
        return NormalizationResult(
            "NORMALIZED",
            media_type,
            parser_document,
            normalized,
            segments,
            transformations,
            prompt_injection_flags(normalized),
            None,
        )

    def _normalize_with_provider(
        self,
        channel: str,
        payload: bytes,
        *,
        media_type: str,
        filename: str,
    ) -> NormalizationResult:
        provider = self.providers.get(channel)
        if provider is None:
            capability = ProviderCapability(False, "NO_PROVIDER_CONFIGURED")
        else:
            capability = provider.capability()
            if not isinstance(capability, ProviderCapability):
                raise ProtocolError(
                    "CAPTURE_PROVIDER_CAPABILITY_INVALID",
                    "normalization provider returned an invalid capability",
                )
        if not capability.available:
            return NormalizationResult(
                "DEGRADED",
                media_type,
                None,
                None,
                [],
                [],
                [],
                capability.reason,
            )
        if provider is None:  # pragma: no cover - capability above is unavailable
            raise ProtocolError(
                "CAPTURE_PROVIDER_CAPABILITY_INVALID", "available provider is absent"
            )
        try:
            output = provider.normalize(
                bytes(payload), media_type=media_type, filename=filename
            )
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError(
                "CAPTURE_PROVIDER_FAILED", "normalization provider failed"
            ) from exc
        if not isinstance(output, Mapping) or set(output) != {
            "parser_id",
            "version",
            "segments",
            "transformations",
        }:
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_INVALID", "provider output shape is invalid"
            )
        parser_id = output["parser_id"]
        version = output["version"]
        transformations = output["transformations"]
        if (
            not isinstance(parser_id, str)
            or _SAFE_ID.fullmatch(parser_id) is None
            or not isinstance(version, str)
            or _SEMVER.fullmatch(version) is None
            or not isinstance(transformations, list)
            or len(transformations) > 64
            or not all(
                isinstance(value, str) and _TRANSFORMATION.fullmatch(value)
                for value in transformations
            )
        ):
            raise ProtocolError(
                "CAPTURE_PROVIDER_OUTPUT_INVALID",
                "provider identity or transformations are invalid",
            )
        normalized, segments = _provider_segments(
            output["segments"], limits=self.limits
        )
        return NormalizationResult(
            "NORMALIZED",
            media_type,
            {"parser_id": parser_id, "version": version},
            normalized,
            segments,
            list(transformations),
            prompt_injection_flags(normalized),
            capability.reason,
        )
