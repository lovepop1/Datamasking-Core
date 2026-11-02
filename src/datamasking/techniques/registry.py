"""Technique registry and strict parameter validation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ValidationError

from datamasking.exceptions import PolicyValidationError
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    OnErrorMode,
    TechniqueParams,
    get_technique,
    list_techniques,
    register_technique,
    register_technique_instance,
)


def validate_technique_params(name: str, raw_params: dict[str, Any]) -> BaseModel:
    """Validate *raw_params* against the registered technique's ``params_model``.

    Rejects unknown parameter names even when a third-party plugin author inherits
    directly from :class:`pydantic.BaseModel` instead of :class:`TechniqueParams`
    (unless the plugin explicitly opted into ``extra='allow'``).
    """
    tech = get_technique(name)
    model_cls = tech.params_model

    extra_setting = model_cls.model_config.get("extra")
    if extra_setting is None:
        declared_fields = set(model_cls.model_fields.keys())
        unknown = sorted(set(raw_params.keys()) - declared_fields)
        if unknown:
            allowed_str = ", ".join(sorted(declared_fields)) if declared_fields else "(none)"
            raise PolicyValidationError(
                f"Unknown parameter(s) {unknown} for technique '{tech.name}'. "
                f"Allowed parameters: {allowed_str}.",
                detail={
                    "technique": tech.name,
                    "unknown_params": unknown,
                    "allowed_params": sorted(declared_fields),
                },
            )

    try:
        return model_cls.model_validate(raw_params)
    except ValidationError as exc:
        raise PolicyValidationError(
            f"Invalid parameters for technique '{tech.name}': {exc}",
            detail={"technique": tech.name, "params": raw_params, "errors": exc.errors()},
        ) from exc
    except Exception as exc:
        raise PolicyValidationError(
            f"Invalid parameters for technique '{tech.name}': {exc}",
            detail={"technique": tech.name, "params": raw_params, "error": str(exc)},
        ) from exc


__all__ = [
    "BaseTechnique",
    "MaskingContext",
    "OnErrorMode",
    "TechniqueParams",
    "get_technique",
    "list_techniques",
    "register_technique",
    "register_technique_instance",
    "validate_technique_params",
]
