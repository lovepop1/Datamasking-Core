"""Example third-party plugin registering a custom ``date_shift`` technique.

Can be imported in Python or passed directly to the CLI via:
``datamasking mask -i input.json -p policy.yaml --plugin examples/custom_plugin/date_shift.py``
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from pydantic import Field

from datamasking import (
    BaseTechnique,
    FormatAdapter,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class DateShiftParams(TechniqueParams):
    """Parameters for the custom ``date_shift`` plugin technique."""

    days: int = Field(..., description="Signed number of calendar days to shift ISO-8601 dates.")
    preserve_null: bool = Field(default=True, description="Leave null values untouched.")


@register_technique("date_shift")
class DateShiftTechnique(BaseTechnique):
    """Shift ISO-8601 ``YYYY-MM-DD`` dates by a fixed day offset."""

    name = "date_shift"
    params_model = DateShiftParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: DateShiftParams,
        context: MaskingContext,
    ) -> None:
        raw = adapter.get_value(node)
        if raw is None and params.preserve_null:
            return
        try:
            parsed = date.fromisoformat(str(raw).strip())
        except ValueError as exc:
            context.handle_value_error(
                adapter,
                node,
                technique=self.name,
                reason=f"Expected YYYY-MM-DD date string, got {raw!r}: {exc}",
            )
            return

        shifted = parsed + timedelta(days=params.days)
        adapter.set_value(node, shifted.isoformat())
