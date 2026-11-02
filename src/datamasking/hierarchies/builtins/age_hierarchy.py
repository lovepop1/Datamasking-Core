"""Integer age interval generalization hierarchy."""

from __future__ import annotations

from datamasking.hierarchies.base import Hierarchy


class AgeHierarchy(Hierarchy):
    """Generalizes non-negative integer ages (`0`-`150`) into coarser intervals.

    Levels:
        - ``0``: exact age (e.g. ``"27"``)
        - ``1``: 5-year bucket (e.g. ``"25-29"``)
        - ``2``: 10-year bucket (e.g. ``"20-29"``)
        - ``3``: 20-year bucket (e.g. ``"20-39"``)
        - ``4``: ``"*"`` (top / fully generalized)
    """

    @property
    def name(self) -> str:
        return "age"

    @property
    def max_level(self) -> int:
        return 4

    def generalize(self, value: str, level: int) -> str:
        if level < 0:
            raise ValueError(f"Generalization level must be >= 0, got {level}.")

        stripped = value.strip()
        try:
            age = int(stripped)
        except ValueError as exc:
            raise ValueError(f"Value {value!r} is not a valid integer age.") from exc

        if age < 0 or age > 150:
            raise ValueError(f"Age {age} is outside the supported domain [0, 150].")

        if level == 0:
            return str(age)
        if level == 1:
            low = (age // 5) * 5
            return f"{low}-{low + 4}"
        if level == 2:
            low = (age // 10) * 10
            return f"{low}-{low + 9}"
        if level == 3:
            low = (age // 20) * 20
            return f"{low}-{low + 19}"
        return "*"
