"""Declarative masking policy models.

A :class:`MaskingPolicy` is the single source of truth for every transformation
performed by ``datamasking-core``. Policies are strictly validated at load time
(rejecting unknown keys, unregistered techniques, unknown parameters, missing
hierarchies, and malformed format-specific selectors) and remain immutable
throughout execution.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import datamasking.adapters as _adapters  # noqa: F401
import datamasking.hierarchies as _hierarchies  # noqa: F401
import datamasking.techniques as _techniques  # noqa: F401
from datamasking.adapters.registry import get_adapter
from datamasking.exceptions import (
    DataMaskingError,
    PolicyValidationError,
)
from datamasking.hierarchies.base import get_hierarchy
from datamasking.plugins import discover_entrypoint_plugins
from datamasking.techniques.base import OnErrorMode, get_technique
from datamasking.techniques.registry import validate_technique_params

UnmatchedAction = Literal["preserve", "redact", "nullify", "suppress"]

SubtreeStrategyType = Literal[
    "masked",
    "passthrough",
    "drop_subtree",
    "deep_redact",
    "synthesize",
]

KAnonStrategy = Literal["verify", "enforce", "suppress"]
KAnonUnresolvedAction = Literal["flag", "suppress"]

_RESERVED_RULE_KEYS = frozenset(
    {
        "id",
        "description",
        "selector",
        "technique",
        "params",
        "priority",
        "roles",
        "on_error",
    }
)


def _normalize_subtree_strategy(value: Any) -> Any:
    if isinstance(value, str) and value.strip().lower() == "default_allow":
        return "passthrough"
    if isinstance(value, str):
        return value.strip().lower()
    return value


class MaskingRule(BaseModel):
    """A single declarative rule mapping a path selector to a masking technique.

    Technique parameters can be supplied either under the ``params`` mapping or
    inline at the rule level for concise YAML authoring; inline keys outside the
    reserved rule attributes are normalized into ``params`` prior to strict
    validation against the target technique's parameter schema.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str | None = Field(
        default=None,
        description="Optional stable identifier for audit and conflict logs.",
    )
    description: str | None = Field(
        default=None,
        description="Optional human-readable explanation of why this rule exists.",
    )
    selector: str = Field(
        ...,
        min_length=1,
        description="JSONPath (JSON/YAML/CSV) or XPath (XML) expression selecting target nodes.",
    )
    technique: str = Field(
        ...,
        min_length=1,
        description="Registered technique identifier (e.g. 'redact', 'pseudonymize', 'suppress').",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Validated parameters passed to the technique.",
    )
    priority: int = Field(
        default=0,
        description="Explicit precedence override; higher priority wins before selector specificity.",
    )
    roles: list[str] | None = Field(
        default=None,
        description="Optional list of caller roles to which this rule applies; applies to all roles when omitted.",
    )
    on_error: OnErrorMode | None = Field(
        default=None,
        description="Optional per-rule override for incompatible values ('raise', 'preserve', 'redact', 'nullify').",
    )

    @model_validator(mode="before")
    @classmethod
    def _fold_inline_params(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        raw_params = normalized.get("params")
        if raw_params is None:
            merged_params: dict[str, Any] = {}
        elif isinstance(raw_params, dict):
            merged_params = dict(raw_params)
        else:
            raise PolicyValidationError(
                "Rule 'params' must be a mapping/dictionary.",
                detail={"params": raw_params},
            )

        inline_keys = [k for k in list(normalized.keys()) if k not in _RESERVED_RULE_KEYS]
        for key in inline_keys:
            val = normalized.pop(key)
            if key in merged_params and merged_params[key] != val:
                raise PolicyValidationError(
                    f"Parameter '{key}' specified both inline and inside 'params' with conflicting values.",
                    detail={"parameter": key},
                )
            merged_params[key] = val

        if isinstance(normalized.get("technique"), str):
            normalized["technique"] = normalized["technique"].strip().lower()
        if isinstance(normalized.get("selector"), str):
            normalized["selector"] = normalized["selector"].strip()

        normalized["params"] = merged_params
        return normalized

    @model_validator(mode="after")
    def _validate_technique_and_params(self) -> MaskingRule:
        discover_entrypoint_plugins()

        try:
            get_technique(self.technique)
        except DataMaskingError as exc:
            raise PolicyValidationError(str(exc), detail=exc.detail) from exc

        validated = validate_technique_params(self.technique, self.params)

        if self.technique == "generalize":
            hierarchy_name = getattr(validated, "hierarchy", None)
            if isinstance(hierarchy_name, str):
                try:
                    get_hierarchy(hierarchy_name)
                except DataMaskingError as exc:
                    raise PolicyValidationError(str(exc), detail=exc.detail) from exc

        return self

    @property
    def params_dict(self) -> dict[str, Any]:
        """Return a copy of the rule's parameter dictionary."""
        return dict(self.params)

    def validated_params(self) -> BaseModel:
        """Instantiate and return the technique's validated Pydantic parameter object."""
        return validate_technique_params(self.technique, self.params)


# Alias kept for ergonomics in profile definitions and backwards compatibility
ProfileRule = MaskingRule


class MaskingProfile(BaseModel):
    """Named, reusable bundle of masking rules referenced by subtree scopes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    description: str | None = Field(default=None, description="Optional profile description.")
    rules: list[MaskingRule] = Field(
        default_factory=list,
        description="Rules activated inside scopes that apply this profile.",
    )


class RoleDefinition(BaseModel):
    """Policy-defined caller role behavior."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    description: str | None = Field(default=None, description="Optional role description.")
    passthrough: bool = Field(
        default=False,
        description="When true, callers with this role bypass masking and receive the original document.",
    )
    default_scope_strategy: SubtreeStrategyType | None = Field(
        default=None,
        description="Fallback strategy used in scopes that omit both this role and 'default'.",
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_fields(cls, data: Any) -> Any:
        if isinstance(data, dict) and "default_fallback" in data:
            copied = dict(data)
            legacy_val = copied.pop("default_fallback")
            copied.setdefault("default_scope_strategy", legacy_val)
            return copied
        return data

    @field_validator("default_scope_strategy", mode="before")
    @classmethod
    def _coerce_strategy(cls, value: Any) -> Any:
        return _normalize_subtree_strategy(value)


class RoleStrategy(BaseModel):
    """How a specific role is handled inside a :class:`ScopeRule`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    strategy: SubtreeStrategyType = Field(
        default="masked",
        description="Subtree handling strategy ('masked', 'passthrough', 'drop_subtree', 'deep_redact', 'synthesize').",
    )
    profile: str | None = Field(
        default=None,
        description="Optional profile from policy.profiles overriding scope.apply_profile when strategy='masked'.",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional technique parameters when strategy is 'deep_redact' or 'synthesize'.",
    )

    @field_validator("strategy", mode="before")
    @classmethod
    def _coerce_strategy(cls, value: Any) -> Any:
        return _normalize_subtree_strategy(value)

    @model_validator(mode="after")
    def _validate_strategy_params(self) -> RoleStrategy:
        if self.params:
            if self.strategy in ("deep_redact", "synthesize"):
                discover_entrypoint_plugins()
                validate_technique_params(self.strategy, self.params)
            else:
                raise PolicyValidationError(
                    f"RoleStrategy 'params' is only supported for 'deep_redact' or 'synthesize', "
                    f"not '{self.strategy}'.",
                    detail={"strategy": self.strategy, "params": self.params},
                )
        return self


class ScopeRule(BaseModel):
    """Path-bounded subtree governance rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(
        ...,
        min_length=1,
        description="Selector identifying the subtree root node(s) governed by this scope.",
    )
    apply_profile: str | None = Field(
        default=None,
        description="Default profile from policy.profiles applied when strategy='masked'.",
    )
    roles: dict[str, RoleStrategy] = Field(
        default_factory=dict,
        description="Role-specific strategy mapping (use key 'default' to match unlisted roles).",
    )
    rules: list[MaskingRule] = Field(
        default_factory=list,
        description="Inline rules restricted to nodes inside this subtree when strategy='masked'.",
    )


class QuasiIdentifier(BaseModel):
    """Quasi-identifier attribute specification for k-anonymity evaluation and enforcement."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    selector: str = Field(
        ...,
        min_length=1,
        description="Selector evaluated relative to each record returned by policy.record_root.",
    )
    hierarchy: str | None = Field(
        default=None,
        description="Optional registered hierarchy used to generalize values when strategy='enforce'.",
    )
    max_level: int | None = Field(
        default=None,
        ge=0,
        description="Optional maximum generalization level cap for this quasi-identifier.",
    )

    @model_validator(mode="before")
    @classmethod
    def _coerce_from_string(cls, data: Any) -> Any:
        if isinstance(data, str):
            return {"selector": data.strip()}
        return data

    @model_validator(mode="after")
    def _validate_hierarchy(self) -> QuasiIdentifier:
        if self.hierarchy is not None:
            discover_entrypoint_plugins()
            try:
                h = get_hierarchy(self.hierarchy)
            except DataMaskingError as exc:
                raise PolicyValidationError(str(exc), detail=exc.detail) from exc
            if self.max_level is not None and self.max_level > h.max_level:
                raise PolicyValidationError(
                    f"Quasi-identifier '{self.selector}' sets max_level={self.max_level}, "
                    f"which exceeds hierarchy '{h.name}' max_level={h.max_level}.",
                    detail={
                        "selector": self.selector,
                        "hierarchy": h.name,
                        "max_level": self.max_level,
                        "hierarchy_max_level": h.max_level,
                    },
                )
        elif self.max_level is not None:
            raise PolicyValidationError(
                f"Quasi-identifier '{self.selector}' sets 'max_level' without specifying 'hierarchy'.",
                detail={"selector": self.selector, "max_level": self.max_level},
            )
        return self


class KAnonConfig(BaseModel):
    """Configuration for record-level k-anonymity verification or enforcement."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(default=True, description="Whether k-anonymity processing is active.")
    k: int = Field(
        ...,
        ge=2,
        description="Minimum required equivalence class size (must be >= 2).",
    )
    quasi_identifiers: list[QuasiIdentifier] = Field(
        ...,
        min_length=1,
        description="Quasi-identifier selectors (strings or {selector, hierarchy, max_level} mappings).",
    )
    strategy: KAnonStrategy = Field(
        default="verify",
        description=(
            "'verify' reports equivalence class violations without modifying data; "
            "'enforce' generalizes quasi-identifiers via their hierarchies; "
            "'suppress' removes records belonging to equivalence classes smaller than k."
        ),
    )
    on_unresolved: KAnonUnresolvedAction = Field(
        default="flag",
        description=(
            "When strategy='enforce' cannot reach k using generalization alone: "
            "'flag' keeps records intact and sets k_achieved=False; "
            "'suppress' removes remaining outlier records."
        ),
    )

    @model_validator(mode="after")
    def _validate_enforcement_requirements(self) -> KAnonConfig:
        if self.strategy == "enforce":
            has_hierarchy = any(qi.hierarchy is not None for qi in self.quasi_identifiers)
            if not has_hierarchy and self.on_unresolved == "flag":
                raise PolicyValidationError(
                    "k_anonymity with strategy='enforce' requires at least one quasi_identifier "
                    "to specify a 'hierarchy' (or use strategy='verify' / strategy='suppress').",
                    detail={"strategy": self.strategy},
                )
        return self


class MaskingPolicy(BaseModel):
    """Root declarative masking policy specification.

    ``MaskingPolicy`` is the sole source of truth for what gets masked and how:

    - Fields not matched by any active rule or scope default to
      ``unmatched_fields='preserve'`` (left completely untouched).
    - Type/domain mismatches default to ``on_error='raise'`` (never silently
      overwritten with ``[REDACTED]`` unless explicitly configured).
    - Caller roles have no built-in magic names; role behavior is governed
      exclusively by ``roles``, ``rules[*].roles``, and ``scopes[*].roles``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(
        default="1.0",
        description="Policy schema version ('1.0'; '3.0' also accepted for compatibility).",
    )
    name: str | None = Field(
        default=None,
        description="Optional human-readable policy name.",
    )
    description: str | None = Field(
        default=None,
        description="Optional summary of the policy's purpose and compliance scope.",
    )
    format: str | None = Field(
        default=None,
        description="Optional target payload format ('json', 'xml', 'yaml', 'csv'). Enables load-time selector validation.",
    )
    unmatched_fields: UnmatchedAction = Field(
        default="preserve",
        description="Action applied to scalar leaf fields not matched by any active rule ('preserve', 'redact', 'nullify', 'suppress').",
    )
    unmatched_replacement: str = Field(
        default="[REDACTED]",
        description="Replacement string used only when unmatched_fields='redact'.",
    )
    on_error: OnErrorMode = Field(
        default="raise",
        description="Default error policy when a technique encounters an incompatible value ('raise', 'preserve', 'redact', 'nullify').",
    )
    record_root: str | list[str] = Field(
        default="$",
        description="Selector(s) identifying individual subject records for k-anonymity evaluation (e.g. '$.patients[*]' or '//patient').",
    )
    rules: list[MaskingRule] = Field(
        default_factory=list,
        description="Global masking rules evaluated across the document.",
    )
    roles: dict[str, RoleDefinition] = Field(
        default_factory=dict,
        description="Optional user-defined caller roles and their policy defaults.",
    )
    profiles: dict[str, MaskingProfile] = Field(
        default_factory=dict,
        description="Named reusable rule bundles referenced by scopes.",
    )
    scopes: list[ScopeRule] = Field(
        default_factory=list,
        description="Subtree-level governance rules and role strategies.",
    )
    k_anonymity: KAnonConfig | None = Field(
        default=None,
        description="Optional k-anonymity verification or enforcement settings.",
    )

    @field_validator("version", mode="before")
    @classmethod
    def _coerce_version(cls, value: Any) -> str:
        if value is None:
            return "1.0"
        s = str(value).strip()
        if s in ("1", "1.0"):
            return "1.0"
        if s in ("3", "3.0"):
            return "3.0"
        raise PolicyValidationError(
            f"Unsupported policy version '{s}'. Supported versions: '1.0', '3.0'.",
            detail={"version": s, "supported_versions": ["1.0", "3.0"]},
        )

    @model_validator(mode="after")
    def _validate_policy_integrity(self) -> MaskingPolicy:
        discover_entrypoint_plugins()

        # 1. Verify all profile references in scopes exist
        available_profiles = sorted(self.profiles.keys())
        for idx, scope in enumerate(self.scopes):
            if scope.apply_profile and scope.apply_profile not in self.profiles:
                raise PolicyValidationError(
                    f"Scope {idx} (path='{scope.path}'): apply_profile '{scope.apply_profile}' "
                    f"is not defined in 'profiles'. Available profiles: {available_profiles}.",
                    detail={
                        "scope_index": idx,
                        "scope_path": scope.path,
                        "missing_profile": scope.apply_profile,
                        "available_profiles": available_profiles,
                    },
                )
            for role_name, strat in scope.roles.items():
                if strat.profile and strat.profile not in self.profiles:
                    raise PolicyValidationError(
                        f"Scope {idx} (path='{scope.path}') role '{role_name}': profile "
                        f"'{strat.profile}' is not defined in 'profiles'. "
                        f"Available profiles: {available_profiles}.",
                        detail={
                            "scope_index": idx,
                            "scope_path": scope.path,
                            "role": role_name,
                            "missing_profile": strat.profile,
                            "available_profiles": available_profiles,
                        },
                    )

        # 2. If format is declared, validate format and every selector at load time
        if self.format is not None:
            fmt = self.format.strip().lower()
            try:
                adapter = get_adapter(fmt)
            except DataMaskingError as exc:
                raise PolicyValidationError(str(exc), detail=exc.detail) from exc

            selectors_to_check: list[tuple[str, str]] = []
            for i, rule in enumerate(self.rules):
                selectors_to_check.append((f"rules[{i}].selector", rule.selector))
            for prof_name, prof in self.profiles.items():
                for i, prule in enumerate(prof.rules):
                    selectors_to_check.append(
                        (f"profiles.{prof_name}.rules[{i}].selector", prule.selector)
                    )
            for i, scope in enumerate(self.scopes):
                selectors_to_check.append((f"scopes[{i}].path", scope.path))
                for j, srule in enumerate(scope.rules):
                    selectors_to_check.append((f"scopes[{i}].rules[{j}].selector", srule.selector))
            if self.k_anonymity is not None:
                roots = (
                    self.record_root if isinstance(self.record_root, list) else [self.record_root]
                )
                for i, r_sel in enumerate(roots):
                    selectors_to_check.append((f"record_root[{i}]", r_sel))
                for i, qi in enumerate(self.k_anonymity.quasi_identifiers):
                    selectors_to_check.append(
                        (f"k_anonymity.quasi_identifiers[{i}].selector", qi.selector)
                    )

            for location, sel in selectors_to_check:
                try:
                    adapter.validate_selector(sel)
                except DataMaskingError as exc:
                    raise PolicyValidationError(
                        f"Invalid selector at {location} for format '{fmt}': {exc.message}",
                        detail={"location": location, "selector": sel, "format": fmt},
                    ) from exc

        return self
