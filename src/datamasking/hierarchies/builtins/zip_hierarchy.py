"""5-digit postal / ZIP code generalization hierarchy."""

from __future__ import annotations

import re

from datamasking.hierarchies.base import Hierarchy


class ZipHierarchy(Hierarchy):
    """Generalizes 5-digit US ZIP codes (including ``ZIP+4`` inputs) by right-truncation.

    Levels:
        - ``0``: ``10001``
        - ``1``: ``1000*``
        - ``2``: ``100**``
        - ``3``: ``10***``
        - ``4``: ``1****``
        - ``5``: ``*****``
    """

    _ZIP_RE = re.compile(r"^(\d{5})(?:-\d{4})?$")

    @property
    def name(self) -> str:
        return "zipcode"

    @property
    def max_level(self) -> int:
        return 5

    def generalize(self, value: str, level: int) -> str:
        if level < 0:
            raise ValueError(f"Generalization level must be >= 0, got {level}.")

        match = self._ZIP_RE.match(value.strip())
        if not match:
            raise ValueError(f"Value {value!r} is not a valid 5-digit ZIP or ZIP+4 code.")

        zip5 = match.group(1)
        if level == 0:
            return zip5
        if level >= 5:
            return "*****"
        keep = 5 - level
        return zip5[:keep] + ("*" * level)
