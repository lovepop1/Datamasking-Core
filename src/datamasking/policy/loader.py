"""YAML, dictionary, file loader, and JSON Schema exporter for :class:`MaskingPolicy`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from datamasking.exceptions import DataMaskingError, PolicyValidationError
from datamasking.policy.models import MaskingPolicy


def load_policy_from_dict(data: dict[str, Any]) -> MaskingPolicy:
    """Validate a Python dictionary into an immutable :class:`MaskingPolicy`.

    Raises:
        PolicyValidationError: If *data* is not a mapping or fails policy validation.
    """
    if not isinstance(data, dict):
        raise PolicyValidationError(
            f"Policy data must be a mapping/dictionary, got {type(data).__name__}.",
            detail={"received_type": type(data).__name__},
        )
    try:
        return MaskingPolicy.model_validate(data)
    except PolicyValidationError:
        raise
    except ValidationError as exc:
        raise PolicyValidationError(
            f"Policy validation failed: {exc}",
            detail={"errors": exc.errors()},
        ) from exc
    except DataMaskingError as exc:
        raise PolicyValidationError(exc.message, detail=exc.detail) from exc


def load_policy_from_yaml(yaml_content: str) -> MaskingPolicy:
    """Parse a YAML string with ``yaml.safe_load`` and validate into a :class:`MaskingPolicy`.

    Raises:
        PolicyValidationError: If YAML syntax is invalid, empty, or fails schema validation.
    """
    if not isinstance(yaml_content, str) or not yaml_content.strip():
        raise PolicyValidationError("Policy YAML content must be a non-empty string.")

    try:
        parsed = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(
            f"Invalid YAML syntax in policy: {exc}",
            detail={"yaml_error": str(exc)},
        ) from exc

    if not isinstance(parsed, dict):
        raise PolicyValidationError(
            "Policy YAML root must be a mapping/dictionary.",
            detail={"received_type": type(parsed).__name__},
        )

    return load_policy_from_dict(parsed)


def load_policy_from_file(file_path: str | Path) -> MaskingPolicy:
    """Read a UTF-8 YAML policy file from disk and validate into a :class:`MaskingPolicy`."""
    path = Path(file_path)
    if not path.is_file():
        raise PolicyValidationError(
            f"Policy file not found: '{file_path}'",
            detail={"path": str(file_path)},
        )
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyValidationError(
            f"Failed to read policy file '{file_path}': {exc}",
            detail={"path": str(file_path), "error": str(exc)},
        ) from exc

    return load_policy_from_yaml(content)


def export_policy_json_schema() -> dict[str, Any]:
    """Export a Draft 2020-12 JSON Schema for :class:`MaskingPolicy`.

    Note:
        Because ``MaskingRule`` accepts inline technique parameters alongside
        nested ``params`` for authoring ergonomics, the exported JSON Schema marks
        ``MaskingRule`` with ``additionalProperties: true`` while keeping strict
        ``additionalProperties: false`` on all structural policy objects.
    """
    schema = MaskingPolicy.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "DataMasking Policy Specification"

    defs = schema.get("$defs", {})
    if "MaskingRule" in defs and isinstance(defs["MaskingRule"], dict):
        defs["MaskingRule"]["additionalProperties"] = True

    return schema
