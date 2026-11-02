"""Recursive subtree leaf redaction technique."""

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


class DeepRedactParams(TechniqueParams):
    """Parameters for the ``deep_redact`` technique."""

    replacement: str = Field(
        default="[REDACTED]",
        description="Static replacement string written to every scalar leaf in the target node or subtree.",
    )
    preserve_null: bool = Field(
        default=False,
        description="When true, null/None scalar leaves remain null.",
    )


@register_technique("deep_redact")
class DeepRedactTechnique(BaseTechnique):
    """Walk all scalar leaf nodes within a target node or container subtree and redact each leaf."""

    name = "deep_redact"
    params_model = DeepRedactParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: DeepRedactParams,
        context: MaskingContext,
    ) -> None:
        leaves = [child for child in adapter.iter_subtree(node) if adapter.is_leaf_node(child)]
        for leaf in leaves:
            if not adapter.is_attached(leaf):
                continue
            if params.preserve_null and adapter.get_value(leaf) is None:
                continue
            adapter.set_value(leaf, params.replacement)

    def auditor_label(self, params: DeepRedactParams) -> str:
        return f"[WOULD APPLY: deep_redact | replacement={params.replacement!r}]"
