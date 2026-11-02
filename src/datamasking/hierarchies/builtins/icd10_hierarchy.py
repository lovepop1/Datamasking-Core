"""ICD-10 diagnosis code generalization hierarchy."""

from __future__ import annotations

import re

from datamasking.hierarchies.base import Hierarchy

_ICD10_RE = re.compile(r"^([A-Za-z])(\d{2})(?:\.[A-Za-z0-9]{1,4})?$")


class ICD10Hierarchy(Hierarchy):
    """Generalizes ICD-10 diagnosis codes across four precision levels.

    Levels:
        - ``0``: normalized uppercase code (e.g. ``"J45.909"``)
        - ``1``: 3-character category (e.g. ``"J45"``)
        - ``2``: chapter letter wildcard (e.g. ``"J**"``)
        - ``3``: ``"***"`` (top / fully generalized)
    """

    @property
    def name(self) -> str:
        return "icd10"

    @property
    def max_level(self) -> int:
        return 3

    def generalize(self, value: str, level: int) -> str:
        if level < 0:
            raise ValueError(f"Generalization level must be >= 0, got {level}.")

        code = value.strip().upper()
        match = _ICD10_RE.match(code)
        if not match:
            raise ValueError(f"Value {value!r} is not a valid ICD-10 diagnosis code.")

        if level == 0:
            return code

        letter, digits = match.group(1), match.group(2)
        if level == 1:
            return f"{letter}{digits}"
        if level == 2:
            return f"{letter}**"
        return "***"
