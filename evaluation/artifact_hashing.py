"""Hash helpers for evaluation evidence with explicit text/binary semantics."""
from __future__ import annotations

import hashlib
from pathlib import Path


def canonicalize_utf8_text(data: bytes) -> bytes:
    """Return valid UTF-8 bytes with only line endings normalized to LF."""
    data.decode("utf-8")
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def canonical_text_sha256_bytes(data: bytes) -> str:
    """Hash UTF-8 text after CRLF and lone-CR normalization to LF."""
    return hashlib.sha256(canonicalize_utf8_text(data)).hexdigest()


def canonical_text_sha256(path: Path) -> str:
    """Hash a UTF-8 text evidence file using its canonical LF bytes."""
    return canonical_text_sha256_bytes(path.read_bytes())


def binary_sha256(path: Path) -> str:
    """Hash binary evidence byte-for-byte without text normalization."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
