"""Format-preserving character-class scrambling."""

from __future__ import annotations

import hashlib
import hmac
import random
import string
from typing import Any

from pydantic import Field

from datamasking.adapters.base import FormatAdapter
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class FormatPreserveParams(TechniqueParams):
    """Parameters for the ``format_preserve`` technique."""

    deterministic: bool = Field(
        default=False,
        description="Derive character substitutions deterministically using HMAC-SHA256 keyed with salt.",
    )
    preserve_prefix: int = Field(
        default=0,
        ge=0,
        description="Number of leading characters to leave unmasked.",
    )
    preserve_suffix: int = Field(
        default=0,
        ge=0,
        description="Number of trailing characters to leave unmasked.",
    )
    preserve_null: bool = Field(
        default=True,
        description="Leave null/None values untouched when true.",
    )


@register_technique("format_preserve")
class FormatPreserveTechnique(BaseTechnique):
    """Scramble ASCII digits, uppercase, and lowercase letters in-class while preserving punctuation."""

    name = "format_preserve"
    params_model = FormatPreserveParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: FormatPreserveParams,
        context: MaskingContext,
    ) -> None:
        raw_value = adapter.get_value(node)
        if raw_value is None and params.preserve_null:
            return

        text = "" if raw_value is None else str(raw_value)
        length = len(text)
        start = min(params.preserve_prefix, length)
        end = max(start, length - params.preserve_suffix)

        if params.deterministic:
            digest = hmac.new(
                context.salt.encode("utf-8"),
                text.encode("utf-8"),
                hashlib.sha256,
            ).digest()
            rng = random.Random(int.from_bytes(digest[:16], "big"))
        else:
            rng = context.rng

        chars: list[str] = list(text[:start])
        for ch in text[start:end]:
            if ch.isascii() and ch.isdigit():
                chars.append(rng.choice(string.digits))
            elif ch.isascii() and ch.isupper():
                chars.append(rng.choice(string.ascii_uppercase))
            elif ch.isascii() and ch.islower():
                chars.append(rng.choice(string.ascii_lowercase))
            else:
                chars.append(ch)
        chars.extend(text[end:])

        adapter.set_value(node, "".join(chars))

    def auditor_label(self, params: FormatPreserveParams) -> str:
        return (
            f"[WOULD APPLY: format_preserve | deterministic={params.deterministic} "
            f"| preserve_prefix={params.preserve_prefix} | preserve_suffix={params.preserve_suffix}]"
        )
