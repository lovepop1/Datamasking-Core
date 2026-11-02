"""Redaction technique — replaces scalar values with a static replacement string."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from datamasking.adapters.base import FormatAdapter
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class RedactParams(TechniqueParams):
    """Parameters for the ``redact`` technique."""

    replacement: str = Field(
        default="[REDACTED]",
        description="Static string that replaces matched values.",
    )
    preserve_null: bool = Field(
        default=False,
        description="When true, null/None values remain null instead of being replaced.",
    )


@register_technique("redact")
class RedactTechnique(BaseTechnique):
    """Replace matched leaf values with a constant redaction string."""

    name = "redact"
    params_model = RedactParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: RedactParams,
        context: MaskingContext,
    ) -> None:
        if params.preserve_null and adapter.get_value(node) is None:
            return
        adapter.set_value(node, params.replacement)

    def auditor_label(self, params: RedactParams) -> str:
        return f"[WOULD APPLY: redact | replacement={params.replacement!r}]"
