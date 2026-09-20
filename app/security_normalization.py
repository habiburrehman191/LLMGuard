from __future__ import annotations

import base64
from dataclasses import dataclass
import html
import re
import unicodedata
from urllib.parse import unquote_plus


DEFAULT_MAX_CONTENT_BYTES = 128_000
DEFAULT_MAX_DECODE_DEPTH = 2
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_ESCAPED_TEXT = re.compile(
    r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}|\\[nrt]"
)
_INVISIBLE_CODEPOINTS = frozenset(
    {
        "\u00ad",
        "\u034f",
        "\u061c",
        "\u180e",
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2060",
        "\u2061",
        "\u2062",
        "\u2063",
        "\u2064",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\u206a",
        "\u206b",
        "\u206c",
        "\u206d",
        "\u206e",
        "\u206f",
        "\ufeff",
    }
)
_SECURITY_BASE64_TERMS = (
    "admin",
    "bypass",
    "confidential",
    "developer",
    "ignore",
    "instructions",
    "override",
    "private records",
    "prompt",
    "reveal",
    "system",
    "tool",
)


class SecurityNormalizationLimitError(ValueError):
    """Raised when raw or canonical inspection content exceeds its bound."""


@dataclass(frozen=True, slots=True)
class NormalizedSecurityContent:
    raw_content: str
    inspection_content: str
    normalization_applied: bool
    transformations: tuple[str, ...]


def normalize_security_text(
    content: str,
    *,
    max_input_bytes: int = DEFAULT_MAX_CONTENT_BYTES,
    max_output_bytes: int | None = None,
    max_decode_depth: int = DEFAULT_MAX_DECODE_DEPTH,
) -> NormalizedSecurityContent:
    """Return bounded canonical inspection text while retaining exact raw text."""
    if not isinstance(content, str):
        raise TypeError("Security normalization content must be text.")
    if max_input_bytes <= 0 or max_decode_depth < 0:
        raise ValueError("Security normalization bounds must be positive.")
    output_limit = max_input_bytes if max_output_bytes is None else max_output_bytes
    if output_limit <= 0:
        raise ValueError("Security normalization output bound must be positive.")

    _require_bounded(content, max_input_bytes, label="raw")
    transformations: list[str] = []
    current = _canonical_characters(content, transformations)
    _require_bounded(current, output_limit, label="normalized")

    for _ in range(max_decode_depth):
        previous = current
        current = _apply_transform(
            current,
            html.unescape,
            "html_entity_decode",
            transformations,
        )
        current = _apply_transform(
            current,
            _url_decode,
            "url_decode",
            transformations,
        )
        current = _apply_transform(
            current,
            _decode_escaped_text,
            "escaped_text_decode",
            transformations,
        )
        current = _apply_transform(
            current,
            _replace_confident_base64,
            "base64_decode",
            transformations,
        )
        current = _canonical_characters(current, transformations)
        _require_bounded(current, output_limit, label="normalized")
        if current == previous:
            break

    return NormalizedSecurityContent(
        raw_content=content,
        inspection_content=current,
        normalization_applied=current != content,
        transformations=tuple(transformations),
    )


def decode_confident_base64(text: str) -> tuple[str, ...]:
    """Decode only UTF-8 text tokens carrying recognizable security instructions."""
    decoded: list[str] = []
    for match in _BASE64_TOKEN.finditer(text):
        value = _decode_base64_token(match.group(0))
        if value is not None and value not in decoded:
            decoded.append(value)
    return tuple(decoded)


def _canonical_characters(text: str, transformations: list[str]) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    _record_change(text, normalized, "unicode_nfkc", transformations)

    without_invisible = "".join(
        character
        for character in normalized
        if character not in _INVISIBLE_CODEPOINTS
    )
    _record_change(
        normalized,
        without_invisible,
        "invisible_character_removal",
        transformations,
    )

    cleaned_controls = "".join(
        (
            character
            if character in "\t\n\r" or unicodedata.category(character) != "Cc"
            else " "
        )
        for character in without_invisible
    )
    _record_change(
        without_invisible,
        cleaned_controls,
        "control_character_cleanup",
        transformations,
    )

    collapsed = " ".join(cleaned_controls.split())
    _record_change(
        cleaned_controls,
        collapsed,
        "whitespace_normalization",
        transformations,
    )
    return collapsed


def _apply_transform(
    text: str,
    transform,
    name: str,
    transformations: list[str],
) -> str:
    try:
        transformed = transform(text)
    except (UnicodeError, ValueError):
        return text
    _record_change(text, transformed, name, transformations)
    return transformed


def _record_change(
    before: str,
    after: str,
    name: str,
    transformations: list[str],
) -> None:
    if before != after and name not in transformations:
        transformations.append(name)


def _url_decode(text: str) -> str:
    return unquote_plus(text, encoding="utf-8", errors="replace")


def _decode_escaped_text(text: str) -> str:
    def decode(match: re.Match[str]) -> str:
        token = match.group(0)
        if token == r"\n":
            return "\n"
        if token == r"\r":
            return "\r"
        if token == r"\t":
            return "\t"
        try:
            if token.startswith(r"\u"):
                codepoint = int(token[2:], 16)
            elif token.startswith(r"\U"):
                codepoint = int(token[2:], 16)
            else:
                codepoint = int(token[2:], 16)
            if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                return token
            return chr(codepoint)
        except (ValueError, OverflowError):
            return token

    return _ESCAPED_TEXT.sub(decode, text)


def _replace_confident_base64(text: str) -> str:
    return _BASE64_TOKEN.sub(
        lambda match: _decode_base64_token(match.group(0)) or match.group(0),
        text,
    )


def _decode_base64_token(token: str) -> str | None:
    if len(token) % 4 == 1:
        return None
    padding = "=" * (-len(token) % 4)
    candidate = token + padding
    try:
        decoded_bytes = base64.b64decode(
            candidate.replace("-", "+").replace("_", "/"),
            validate=True,
        )
        decoded = decoded_bytes.decode("utf-8", errors="strict").strip()
    except (ValueError, UnicodeError):
        return None
    if not decoded or len(decoded) > DEFAULT_MAX_CONTENT_BYTES:
        return None
    printable = sum(character.isprintable() or character.isspace() for character in decoded)
    if printable / len(decoded) < 0.90:
        return None
    lowered = " ".join(decoded.lower().split())
    if not any(term in lowered for term in _SECURITY_BASE64_TERMS):
        return None
    return decoded


def _require_bounded(text: str, limit: int, *, label: str) -> None:
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError(f"Security normalization {label} text is malformed.") from exc
    if size > limit:
        raise SecurityNormalizationLimitError(
            f"Security normalization {label} text exceeds {limit} bytes."
        )
