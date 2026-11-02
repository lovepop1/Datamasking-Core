"""Pseudonymization technique — keyed HMAC-SHA256 or randomized tokenization."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from pydantic import Field

from datamasking.adapters.base import FormatAdapter
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)

_HEX_ALPHABET = "0123456789abcdef"


class PseudonymizeParams(TechniqueParams):
    """Parameters for the ``pseudonymize`` technique."""

    consistent: bool = Field(
        default=True,
        description="Produce deterministic HMAC-SHA256 tokens keyed by salt so joins remain intact.",
    )
    prefix: str = Field(
        default="ANON_",
        description="String prefix prepended to generated hexadecimal tokens.",
    )
    token_length: int = Field(
        default=16,
        ge=4,
        le=64,
        description="Number of hexadecimal characters included after the prefix (4-64).",
    )
    salt: str | None = Field(
        default=None,
        description="Optional per-rule HMAC key overriding the execution context salt.",
    )
    preserve_null: bool = Field(
        default=True,
        description="Leave null/None values untouched when true.",
    )


@register_technique("pseudonymize")
class PseudonymizeTechnique(BaseTechnique):
    """Replace identifiers with keyed HMAC-SHA256 pseudonyms or random tokens."""

    name = "pseudonymize"
    params_model = PseudonymizeParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: PseudonymizeParams,
        context: MaskingContext,
    ) -> None:
        raw_value = adapter.get_value(node)
        if raw_value is None and params.preserve_null:
            return

        val_str = "" if raw_value is None else str(raw_value)

        if params.consistent:
            effective_salt = params.salt if params.salt is not None else context.salt
            digest = hmac.new(
                effective_salt.encode("utf-8"),
                val_str.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            suffix = digest[: params.token_length]
        else:
            suffix = "".join(context.rng.choice(_HEX_ALPHABET) for _ in range(params.token_length))

        adapter.set_value(node, f"{params.prefix}{suffix}")

    def auditor_label(self, params: PseudonymizeParams) -> str:
        return (
            f"[WOULD APPLY: pseudonymize | consistent={params.consistent} "
            f"| prefix={params.prefix!r} | token_length={params.token_length}]"
        )
