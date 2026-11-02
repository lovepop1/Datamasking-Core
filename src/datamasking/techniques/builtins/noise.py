"""Bounded multiplicative numeric perturbation technique."""

from __future__ import annotations

import math
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

_INT_STR_RE = re.compile(r"^[+-]?\d+$")


class NoiseParams(TechniqueParams):
    """Parameters for the ``noise`` technique."""

    percentage: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Maximum uniform multiplicative perturbation range (±percentage%).",
    )
    precision: int = Field(
        default=2,
        ge=0,
        le=10,
        description="Decimal rounding places for floating-point values.",
    )
    preserve_null: bool = Field(
        default=True,
        description="Leave null/None values untouched when true.",
    )


@register_technique("noise")
class NoiseTechnique(BaseTechnique):
    """Perturb numeric values by a uniform factor in ``[1 - percentage/100, 1 + percentage/100]``.

    Note:
        Uniform multiplicative perturbation is suitable for test-data realism and basic
        numeric obfuscation; it is not a formally differentially private mechanism.
    """

    name = "noise"
    params_model = NoiseParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: NoiseParams,
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
                reason="Cannot apply numeric noise to null value when preserve_null=False.",
            )
            return

        if isinstance(raw_value, bool):
            context.handle_value_error(
                adapter,
                node,
                technique=self.name,
                reason=f"Expected int or float, got boolean {raw_value!r}.",
            )
            return

        try:
            num = float(raw_value)
        except (ValueError, TypeError):
            context.handle_value_error(
                adapter,
                node,
                technique=self.name,
                reason=f"Value {raw_value!r} is not numeric.",
            )
            return

        if math.isnan(num) or math.isinf(num):
            context.handle_value_error(
                adapter,
                node,
                technique=self.name,
                reason=f"Numeric value {raw_value!r} must be finite.",
            )
            return

        pct = params.percentage / 100.0
        factor = 1.0 + context.rng.uniform(-pct, pct)
        perturbed = num * factor

        if isinstance(raw_value, int):
            adapter.set_value(node, round(perturbed))
        elif isinstance(raw_value, str):
            if _INT_STR_RE.match(raw_value.strip()):
                adapter.set_value(node, str(round(perturbed)))
            else:
                adapter.set_value(node, str(round(perturbed, params.precision)))
        else:
            adapter.set_value(node, round(perturbed, params.precision))

    def auditor_label(self, params: NoiseParams) -> str:
        return (
            f"[WOULD APPLY: noise | percentage={params.percentage} | precision={params.precision}]"
        )
