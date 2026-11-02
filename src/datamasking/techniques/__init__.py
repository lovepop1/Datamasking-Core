"""Pluggable masking techniques package.

Importing this package registers all 10 built-in techniques into the global
technique registry.
"""

from __future__ import annotations

import datamasking.techniques.builtins as _builtins  # noqa: F401
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
from datamasking.techniques.registry import validate_technique_params

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
