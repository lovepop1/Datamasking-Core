"""Built-in generalization hierarchies."""

from __future__ import annotations

from datamasking.hierarchies.builtins.age_hierarchy import AgeHierarchy
from datamasking.hierarchies.builtins.date_hierarchy import DateHierarchy
from datamasking.hierarchies.builtins.icd10_hierarchy import ICD10Hierarchy
from datamasking.hierarchies.builtins.zip_hierarchy import ZipHierarchy

__all__ = ["AgeHierarchy", "DateHierarchy", "ICD10Hierarchy", "ZipHierarchy"]
