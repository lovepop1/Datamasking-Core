"""Generalization hierarchy registry and built-in taxonomies."""

from __future__ import annotations

from datamasking.hierarchies.base import (
    Hierarchy,
    get_hierarchy,
    list_hierarchies,
    register_hierarchy,
)
from datamasking.hierarchies.builtins import (
    AgeHierarchy,
    DateHierarchy,
    ICD10Hierarchy,
    ZipHierarchy,
)

register_hierarchy("date", DateHierarchy)
register_hierarchy("zipcode", ZipHierarchy)
register_hierarchy("zip", ZipHierarchy)
register_hierarchy("age", AgeHierarchy)
register_hierarchy("icd10", ICD10Hierarchy)

__all__ = [
    "AgeHierarchy",
    "DateHierarchy",
    "Hierarchy",
    "ICD10Hierarchy",
    "ZipHierarchy",
    "get_hierarchy",
    "list_hierarchies",
    "register_hierarchy",
]
