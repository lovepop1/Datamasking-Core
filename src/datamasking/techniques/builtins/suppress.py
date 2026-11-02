"""Suppression technique — removes matched nodes or subtrees from the document AST."""

from __future__ import annotations

from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class SuppressParams(TechniqueParams):
    """Parameters for the ``suppress`` technique (takes no arguments)."""


@register_technique("suppress")
class SuppressTechnique(BaseTechnique):
    """Detach and remove matched nodes (keys, array items, XML elements/attributes, CSV columns)."""

    name = "suppress"
    params_model = SuppressParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: SuppressParams,
        context: MaskingContext,
    ) -> None:
        adapter.remove_node(node)

    def auditor_label(self, params: SuppressParams) -> str:
        return "[WOULD APPLY: suppress]"
