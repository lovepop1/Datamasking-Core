"""ISO-8601 date generalization hierarchy."""

from __future__ import annotations

import datetime as dt
import re

from datamasking.hierarchies.base import Hierarchy


class DateHierarchy(Hierarchy):
    """Generalizes ISO-8601 dates across five precision levels.

    Levels:
        - ``0``: ``YYYY-MM-DD`` (exact date, e.g. ``"1985-07-23"``)
        - ``1``: ``YYYY-MM`` (year and month, e.g. ``"1985-07"``)
        - ``2``: ``YYYY`` (year, e.g. ``"1985"``)
        - ``3``: ``YYYY-YYYY`` (decade interval, e.g. ``"1980-1989"``)
        - ``4``: ``"*"`` (top / fully generalized)
    """

    _ISO_PREFIX_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T\s].*)?$")

    @property
    def name(self) -> str:
        return "date"

    @property
    def max_level(self) -> int:
        return 4

    def generalize(self, value: str, level: int) -> str:
        if level < 0:
            raise ValueError(f"Generalization level must be >= 0, got {level}.")

        stripped = value.strip()
        match = self._ISO_PREFIX_RE.match(stripped)
        if not match:
            raise ValueError(f"Value {value!r} is not a valid ISO-8601 date (YYYY-MM-DD).")

        year_s, month_s, day_s = match.groups()
        try:
            parsed = dt.date(int(year_s), int(month_s), int(day_s))
        except ValueError as exc:
            raise ValueError(f"Invalid calendar date {value!r}: {exc}") from exc

        if level == 0:
            return parsed.isoformat()
        if level == 1:
            return f"{parsed.year:04d}-{parsed.month:02d}"
        if level == 2:
            return f"{parsed.year:04d}"
        if level == 3:
            decade_start = (parsed.year // 10) * 10
            return f"{decade_start:04d}-{decade_start + 9:04d}"
        return "*"
