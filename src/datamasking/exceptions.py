"""Structured exception hierarchy for ``datamasking-core``.

Every exception raised intentionally by this library inherits from
:class:`DataMaskingError` and carries an optional structured ``detail``
mapping for programmatic error handling and logging.
"""

from __future__ import annotations

from typing import Any


class DataMaskingError(Exception):
    """Base exception for all errors raised by ``datamasking-core``."""

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail: dict[str, Any] = detail or {}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, detail={self.detail!r})"


class PolicyValidationError(DataMaskingError):
    """Raised when a masking policy is syntactically or semantically invalid."""


class FormatParseError(DataMaskingError):
    """Raised when input payload bytes cannot be parsed or exceed configured limits."""


class UnsupportedFormatError(DataMaskingError):
    """Raised when an unregistered serialization format or file extension is requested."""

    def __init__(self, requested_format: str, *, supported: list[str] | None = None) -> None:
        supported_list = supported or []
        suffix = f" Supported formats: {', '.join(supported_list)}." if supported_list else ""
        super().__init__(
            f"Unsupported format '{requested_format}'.{suffix}",
            detail={"requested_format": requested_format, "supported": supported_list},
        )


class SelectorEvaluationError(DataMaskingError):
    """Raised when a JSONPath or XPath selector has invalid syntax or cannot be evaluated."""


class TechniqueNotFoundError(DataMaskingError):
    """Raised when a policy references an unregistered masking technique."""

    def __init__(self, technique_name: str, *, available: list[str] | None = None) -> None:
        available_list = available or []
        suffix = f" Registered techniques: {', '.join(available_list)}." if available_list else ""
        super().__init__(
            f"Masking technique '{technique_name}' is not registered.{suffix}",
            detail={"technique": technique_name, "available": available_list},
        )


class TechniqueExecutionError(DataMaskingError):
    """Raised when a technique fails on an incompatible value and ``on_error='raise'``."""


class HierarchyNotFoundError(DataMaskingError):
    """Raised when a rule or k-anonymity config references an unregistered hierarchy."""

    def __init__(self, hierarchy_name: str, *, available: list[str] | None = None) -> None:
        available_list = available or []
        suffix = f" Registered hierarchies: {', '.join(available_list)}." if available_list else ""
        super().__init__(
            f"Generalization hierarchy '{hierarchy_name}' is not registered.{suffix}",
            detail={"hierarchy": hierarchy_name, "available": available_list},
        )


class PluginLoadError(DataMaskingError):
    """Raised when loading an external plugin module, file, or entry point fails."""
