"""Format adapter registry and format detection utilities."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from typing import TypeVar, overload

from datamasking.adapters.base import FormatAdapter
from datamasking.exceptions import UnsupportedFormatError

TAdapter = TypeVar("TAdapter", bound=FormatAdapter)

_REGISTRY: dict[str, FormatAdapter] = {}
_EXTENSION_MAP: dict[str, str] = {}


@overload
def register_adapter(
    format_name: str,
    adapter: None = None,
    *,
    extensions: Sequence[str] | None = None,
) -> Callable[[type[TAdapter]], type[TAdapter]]: ...


@overload
def register_adapter(
    format_name: str,
    adapter: FormatAdapter | type[FormatAdapter],
    *,
    extensions: Sequence[str] | None = None,
) -> FormatAdapter: ...


def register_adapter(
    format_name: str,
    adapter: FormatAdapter | type[FormatAdapter] | None = None,
    *,
    extensions: Sequence[str] | None = None,
) -> Callable[[type[TAdapter]], type[TAdapter]] | FormatAdapter:
    """Register a :class:`FormatAdapter` as a class decorator or imperatively.

    Args:
        format_name: Canonical format name (for example ``"json"`` or ``"jsonl"``).
        adapter: Adapter instance or subclass when registering imperatively.
        extensions: Optional file extensions (e.g. ``[".jsonl", ".ndjson"]``)
            mapped to *format_name* by :func:`detect_format_from_filename`.
    """
    canonical = format_name.lower().strip()
    if not canonical:
        raise ValueError("Format name must be a non-empty string.")

    def _bind_extensions(exts: Sequence[str] | None) -> None:
        if not exts:
            return
        for ext in exts:
            normalized_ext = ext.lower().strip()
            if not normalized_ext.startswith("."):
                normalized_ext = f".{normalized_ext}"
            _EXTENSION_MAP[normalized_ext] = canonical

    if adapter is None:

        def decorator(cls: type[TAdapter]) -> type[TAdapter]:
            _REGISTRY[canonical] = cls()
            _bind_extensions(extensions)
            return cls

        return decorator

    instance = adapter() if isinstance(adapter, type) else adapter
    _REGISTRY[canonical] = instance
    _bind_extensions(extensions)
    return instance


def get_adapter(format_name: str) -> FormatAdapter:
    """Return the registered :class:`FormatAdapter` for *format_name*."""
    fmt = format_name.lower().strip()
    if fmt not in _REGISTRY:
        raise UnsupportedFormatError(fmt, supported=list_supported_formats())
    return _REGISTRY[fmt]


def list_supported_formats() -> list[str]:
    """Return a sorted list of registered format names."""
    return sorted(_REGISTRY.keys())


def detect_format_from_filename(filename: str) -> str:
    """Infer canonical format name from a filename's extension."""
    _, ext = os.path.splitext(filename)
    canonical = _EXTENSION_MAP.get(ext.lower())
    if not canonical:
        raise UnsupportedFormatError(filename, supported=list_supported_formats())
    return canonical


def detect_format_from_content(raw_bytes: bytes) -> str:
    """Heuristically infer ``json``, ``xml``, ``csv``, or ``yaml`` from raw bytes.

    When format ambiguity is undesirable, pass ``format=...`` explicitly to
    :meth:`datamasking.MaskingEngine.mask` or declare ``format`` in the policy.
    """
    stripped = raw_bytes.strip()
    if not stripped:
        return "json"

    if stripped.startswith(b"<?xml") or (stripped.startswith(b"<") and stripped.endswith(b">")):
        return "xml"

    if (stripped.startswith(b"{") and stripped.endswith(b"}")) or (
        stripped.startswith(b"[") and stripped.endswith(b"]")
    ):
        return "json"

    lines = stripped.splitlines()
    if (
        len(lines) >= 2
        and b"," in lines[0]
        and not stripped.startswith(b"---")
        and b": " not in lines[0]
    ):
        return "csv"

    return "yaml"
