"""Generalization technique — coarsens values through registered domain hierarchies."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from datamasking.adapters.base import FormatAdapter
from datamasking.hierarchies.base import get_hierarchy
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class GeneralizeParams(TechniqueParams):
    """Parameters for the ``generalize`` technique."""

    hierarchy: str = Field(
        ...,
        min_length=1,
        description="Registered hierarchy identifier (e.g. 'date', 'zipcode', 'age').",
    )
    level: int = Field(
        default=1,
        ge=0,
        description="Generalization level (0 = normalized original, higher = coarser).",
    )
    preserve_null: bool = Field(
        default=True,
        description="Leave null/None values untouched when true.",
    )


@register_technique("generalize")
class GeneralizeTechnique(BaseTechnique):
    """Reduce precision of a scalar value using a registered :class:`Hierarchy`."""

    name = "generalize"
    params_model = GeneralizeParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: GeneralizeParams,
        context: MaskingContext,
    ) -> None:
        raw_value = adapter.get_value(node)
        if raw_value is None:
            if params.preserve_null:
                return
            context.handle_value_error(
                adapter,
                node,
                technique=self.name,
                reason="Cannot generalize null value when preserve_null=False.",
            )
            return

        hierarchy = get_hierarchy(params.hierarchy)
        try:
            generalized = hierarchy.generalize(str(raw_value), params.level)
        except ValueError as exc:
            context.handle_value_error(
                adapter,
                node,
                technique=self.name,
                reason=str(exc),
            )
            return

        adapter.set_value(node, generalized)

    def auditor_label(self, params: GeneralizeParams) -> str:
        return f"[WOULD APPLY: generalize | hierarchy={params.hierarchy!r} | level={params.level}]"
