"""Abstract base class and registry for generalization hierarchies.

A :class:`Hierarchy` defines deterministic coarsening levels for a scalar domain
(for example, ISO-8601 dates, postal codes, or integer ages). Level ``0`` always
returns the original normalized value, and progressively higher levels reduce
precision up to :attr:`Hierarchy.max_level`.

Hierarchies never silently redact invalid inputs; if a value does not belong to
the hierarchy's domain, :meth:`Hierarchy.generalize` raises :class:`ValueError`
so the calling rule's ``on_error`` policy setting controls what happens.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TypeVar, overload

from datamasking.exceptions import HierarchyNotFoundError

THierarchy = TypeVar("THierarchy", bound="Hierarchy")


class Hierarchy(ABC):
    """Contract implemented by all generalization taxonomies."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical lowercase identifier (for example ``'date'`` or ``'zipcode'``)."""

    @property
    @abstractmethod
    def max_level(self) -> int:
        """Maximum coarsening level (inclusive, must be ``>= 1``)."""

    @abstractmethod
    def generalize(self, value: str, level: int) -> str:
        """Generalize *value* to *level* (``0`` = original, ``max_level`` = coarsest).

        Raises:
            ValueError: If *value* cannot be parsed as a member of this domain,
                or if *level* is negative.
        """


_HIERARCHY_REGISTRY: dict[str, Hierarchy] = {}


@overload
def register_hierarchy(name: str) -> Callable[[type[THierarchy]], type[THierarchy]]: ...


@overload
def register_hierarchy(name: str, instance_or_cls: Hierarchy | type[Hierarchy]) -> Hierarchy: ...


def register_hierarchy(
    name: str,
    instance_or_cls: Hierarchy | type[Hierarchy] | None = None,
) -> Callable[[type[THierarchy]], type[THierarchy]] | Hierarchy:
    """Register a :class:`Hierarchy` either as a class decorator or imperatively.

    Examples:
        As a decorator::

            @register_hierarchy("icd10")
            class ICD10Hierarchy(Hierarchy):
                ...

        Imperatively::

            register_hierarchy("icd10", ICD10Hierarchy())
    """
    norm = name.lower().strip()
    if not norm:
        raise ValueError("Hierarchy name must be a non-empty string.")

    if instance_or_cls is None:

        def decorator(cls: type[THierarchy]) -> type[THierarchy]:
            _HIERARCHY_REGISTRY[norm] = cls()
            return cls

        return decorator

    instance = instance_or_cls() if isinstance(instance_or_cls, type) else instance_or_cls
    _HIERARCHY_REGISTRY[norm] = instance
    return instance


def get_hierarchy(name: str) -> Hierarchy:
    """Return the registered :class:`Hierarchy` for *name* or raise :class:`HierarchyNotFoundError`."""
    norm = name.lower().strip()
    if norm not in _HIERARCHY_REGISTRY:
        raise HierarchyNotFoundError(norm, available=list_hierarchies())
    return _HIERARCHY_REGISTRY[norm]


def list_hierarchies() -> list[str]:
    """Return a sorted list of registered hierarchy identifiers."""
    return sorted(_HIERARCHY_REGISTRY.keys())
