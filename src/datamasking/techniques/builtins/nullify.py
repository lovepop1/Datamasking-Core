"""Nullify technique — replaces scalar values with ``None`` / ``null``."""

from __future__ import annotations

from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class NullifyParams(TechniqueParams):
    """Parameters for the ``nullify`` technique (takes no arguments)."""


@register_technique("nullify")
class NullifyTechnique(BaseTechnique):
    """Set matched scalar values to ``None`` (serialized as ``null`` in JSON/YAML or empty text in XML/CSV)."""

    name = "nullify"
    params_model = NullifyParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: NullifyParams,
        context: MaskingContext,
    ) -> None:
        adapter.set_value(node, None)

    def auditor_label(self, params: NullifyParams) -> str:
        return "[WOULD APPLY: nullify]"
