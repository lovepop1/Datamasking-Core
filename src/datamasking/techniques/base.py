"""Base classes, execution context, and registry for pluggable masking techniques."""

from __future__ import annotations

import random
import secrets
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict

from datamasking.adapters.base import FormatAdapter
from datamasking.exceptions import TechniqueExecutionError, TechniqueNotFoundError

OnErrorMode = Literal["raise", "preserve", "redact", "nullify"]


class TechniqueParams(BaseModel):
    """Strict base parameter model forbidding unknown or misspelled rule parameters."""

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass
class MaskingContext:
    """Per-execution state passed into every :meth:`BaseTechnique.apply` call.

    Attributes:
        role: Optional caller role evaluated against policy rules and scopes.
        tenant_id: Optional tenant identifier passed through by multi-tenant callers.
        salt: Secret key material for keyed HMAC operations. Defaults to a fresh
            256-bit cryptographically random key per engine/execution when not
            explicitly supplied by the caller.
        rng: Isolated :class:`random.Random` instance (seeded when ``seed`` is set)
            so randomized techniques never touch process-global random state.
        on_error: Active error-handling policy for the current rule
            (``"raise"``, ``"preserve"``, ``"redact"``, or ``"nullify"``).
        node_path: Canonical path of the node currently being transformed.
        warnings: Structured non-fatal warnings emitted when ``on_error != "raise"``.
        conflict_log: Conflict resolution audit entries collected during Phase 2.
    """

    role: str | None = None
    tenant_id: str | None = None
    salt: str = field(default_factory=lambda: secrets.token_hex(32))
    rng: random.Random = field(default_factory=random.Random)
    on_error: OnErrorMode = "raise"
    node_path: str = ""
    warnings: list[dict[str, Any]] = field(default_factory=list)
    conflict_log: list[dict[str, Any]] = field(default_factory=list)

    def handle_value_error(
        self,
        adapter: FormatAdapter,
        node: Any,
        *,
        technique: str,
        reason: str,
        redaction_token: str = "[REDACTED]",
    ) -> None:
        """Handle an incompatible node value strictly according to ``self.on_error``."""
        if self.on_error == "raise":
            raise TechniqueExecutionError(
                f"Technique '{technique}' failed at '{self.node_path}': {reason}",
                detail={
                    "technique": technique,
                    "path": self.node_path,
                    "reason": reason,
                },
            )

        if self.on_error == "redact":
            adapter.set_value(node, redaction_token)
        elif self.on_error == "nullify":
            adapter.set_value(node, None)
        # When self.on_error == "preserve", the original node value is left untouched.

        self.warnings.append(
            {
                "path": self.node_path,
                "technique": technique,
                "action": self.on_error,
                "reason": reason,
            }
        )


TTechnique = TypeVar("TTechnique", bound="BaseTechnique")


class BaseTechnique(ABC):
    """Abstract base class implemented by all built-in and plugin masking techniques.

    To create a custom technique, subclass :class:`BaseTechnique`, optionally set
    :attr:`params_model` to a :class:`TechniqueParams` (or :class:`pydantic.BaseModel`)
    subclass, implement :meth:`apply`, and decorate the class with
    :func:`register_technique`.
    """

    name: str = ""
    params_model: type[BaseModel] = TechniqueParams

    @abstractmethod
    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: Any,
        context: MaskingContext,
    ) -> None:
        """Mutate *node* in-place through *adapter* according to *params* and *context*."""

    def auditor_label(self, params: Any) -> str:
        """Return a non-destructive dry-run preview label describing this transformation.

        Subclasses may override this for custom formatting; the default implementation
        formats the technique name and any parameters set on *params*.
        """
        if isinstance(params, BaseModel):
            dumped = params.model_dump(exclude_defaults=False)
            if dumped:
                kv = " | ".join(f"{k}={v!r}" for k, v in dumped.items())
                return f"[WOULD APPLY: {self.name} | {kv}]"
        return f"[WOULD APPLY: {self.name}]"

    def apply_subtree(
        self,
        adapter: FormatAdapter,
        subtree_root: Any,
        params: Any,
        context: MaskingContext,
    ) -> None:
        """Apply this technique across every scalar leaf node within *subtree_root*."""
        leaves = [n for n in adapter.iter_subtree(subtree_root) if adapter.is_leaf_node(n)]
        for leaf in leaves:
            if not adapter.is_attached(leaf):
                continue
            context.node_path = adapter.get_path(leaf)
            self.apply(adapter, leaf, params, context)


_REGISTRY: dict[str, BaseTechnique] = {}


def register_technique(name: str) -> Callable[[type[TTechnique]], type[TTechnique]]:
    """Class decorator registering a :class:`BaseTechnique` implementation under *name*."""
    norm = name.lower().strip()
    if not norm:
        raise ValueError("Technique name must be a non-empty string.")

    def decorator(cls: type[TTechnique]) -> type[TTechnique]:
        instance = cls()
        instance.name = norm
        _REGISTRY[norm] = instance
        return cls

    return decorator


def register_technique_instance(name: str, instance: BaseTechnique) -> None:
    """Imperatively register an instantiated :class:`BaseTechnique` under *name*."""
    norm = name.lower().strip()
    if not norm:
        raise ValueError("Technique name must be a non-empty string.")
    instance.name = norm
    _REGISTRY[norm] = instance


def get_technique(name: str) -> BaseTechnique:
    """Return the registered :class:`BaseTechnique` for *name* or raise :class:`TechniqueNotFoundError`."""
    norm = name.lower().strip()
    if norm not in _REGISTRY:
        raise TechniqueNotFoundError(norm, available=list_techniques())
    return _REGISTRY[norm]


def list_techniques() -> list[str]:
    """Return a sorted list of registered technique identifiers."""
    return sorted(_REGISTRY.keys())
