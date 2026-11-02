"""Template-based partial reveal masking."""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field

from datamasking.adapters.base import FormatAdapter
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class MaskPatternParams(TechniqueParams):
    """Parameters for the ``mask_pattern`` technique."""

    pattern: str = Field(
        ...,
        min_length=1,
        description=(
            "Masking template supporting {first1}, {first2}, {first3}, {first4}, "
            "{last2}, {last4}, {digits_last4}, and {domain}."
        ),
    )
    preserve_null: bool = Field(
        default=True,
        description="Leave null/None values untouched when true.",
    )


@register_technique("mask_pattern")
class MaskPatternTechnique(BaseTechnique):
    """Format values into a template exposing only selected prefix, suffix, or domain segments."""

    name = "mask_pattern"
    params_model = MaskPatternParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: MaskPatternParams,
        context: MaskingContext,
    ) -> None:
        raw_value = adapter.get_value(node)
        if raw_value is None and params.preserve_null:
            return

        s = "" if raw_value is None else str(raw_value)
        digits_only = re.sub(r"\D", "", s)
        domain = s.rsplit("@", 1)[1] if "@" in s else ""

        replacements = {
            "{first1}": s[:1],
            "{first2}": s[:2],
            "{first3}": s[:3],
            "{first4}": s[:4],
            "{last2}": s[-2:] if len(s) >= 2 else s,
            "{last4}": s[-4:] if len(s) >= 4 else s,
            "{digits_last4}": digits_only[-4:] if len(digits_only) >= 4 else digits_only,
            "{domain}": domain,
        }

        result = params.pattern
        for placeholder, val in replacements.items():
            result = result.replace(placeholder, val)

        adapter.set_value(node, result)

    def auditor_label(self, params: MaskPatternParams) -> str:
        return f"[WOULD APPLY: mask_pattern | pattern={params.pattern!r}]"
