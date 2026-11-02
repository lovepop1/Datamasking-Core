"""datamasking-core — Declarative, policy-driven, in-memory data masking library."""

from __future__ import annotations

import datamasking.adapters as _adapters  # noqa: F401
import datamasking.hierarchies as _hierarchies  # noqa: F401
import datamasking.techniques as _techniques  # noqa: F401
from datamasking.adapters.base import FormatAdapter
from datamasking.adapters.registry import (
    detect_format_from_content,
    detect_format_from_filename,
    get_adapter,
    list_supported_formats,
    register_adapter,
)
from datamasking.engine import MaskingEngine
from datamasking.exceptions import (
    DataMaskingError,
    FormatParseError,
    HierarchyNotFoundError,
    PluginLoadError,
    PolicyValidationError,
    SelectorEvaluationError,
    TechniqueExecutionError,
    TechniqueNotFoundError,
    UnsupportedFormatError,
)
from datamasking.hierarchies.base import (
    Hierarchy,
    get_hierarchy,
    list_hierarchies,
    register_hierarchy,
)
from datamasking.pipeline.kanon import KAnonReport
from datamasking.pipeline.phase3_apply import ExecutionMode
from datamasking.pipeline.runner import PipelineResult, run_pipeline
from datamasking.plugins import discover_entrypoint_plugins, load_plugin
from datamasking.policy.loader import (
    export_policy_json_schema,
    load_policy_from_dict,
    load_policy_from_file,
    load_policy_from_yaml,
)
from datamasking.policy.models import (
    KAnonConfig,
    MaskingPolicy,
    MaskingProfile,
    MaskingRule,
    QuasiIdentifier,
    RoleDefinition,
    RoleStrategy,
    ScopeRule,
)
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

# Ergonomic alias for file-based policy loading
load_policy = load_policy_from_file

__version__ = "0.1.0"

__all__ = [
    "BaseTechnique",
    "DataMaskingError",
    "ExecutionMode",
    "FormatAdapter",
    "FormatParseError",
    "Hierarchy",
    "HierarchyNotFoundError",
    "KAnonConfig",
    "KAnonReport",
    "MaskingContext",
    "MaskingEngine",
    "MaskingPolicy",
    "MaskingProfile",
    "MaskingRule",
    "OnErrorMode",
    "PipelineResult",
    "PluginLoadError",
    "PolicyValidationError",
    "QuasiIdentifier",
    "RoleDefinition",
    "RoleStrategy",
    "ScopeRule",
    "SelectorEvaluationError",
    "TechniqueExecutionError",
    "TechniqueNotFoundError",
    "TechniqueParams",
    "UnsupportedFormatError",
    "__version__",
    "detect_format_from_content",
    "detect_format_from_filename",
    "discover_entrypoint_plugins",
    "export_policy_json_schema",
    "get_adapter",
    "get_hierarchy",
    "get_technique",
    "list_hierarchies",
    "list_supported_formats",
    "list_techniques",
    "load_plugin",
    "load_policy",
    "load_policy_from_dict",
    "load_policy_from_file",
    "load_policy_from_yaml",
    "register_adapter",
    "register_hierarchy",
    "register_technique",
    "register_technique_instance",
    "run_pipeline",
]
