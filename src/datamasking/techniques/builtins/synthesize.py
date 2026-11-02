"""Keyed synthetic data generation for personal, financial, and clinical attributes."""

from __future__ import annotations

import hashlib
import hmac
import random
import re
from typing import Any, Literal

from pydantic import Field

from datamasking.adapters.base import FormatAdapter
from datamasking.techniques.base import (
    BaseTechnique,
    MaskingContext,
    TechniqueParams,
    register_technique,
)

SyntheticCategory = Literal[
    "full_name",
    "first_name",
    "last_name",
    "email",
    "phone",
    "street_address",
    "city",
    "state",
    "zipcode",
    "ssn",
    "credit_card",
    "cvv",
    "date",
    "clinical_note",
    "generic",
]

_SYNTHETIC_FIRST_NAMES = (
    "Alex",
    "Jordan",
    "Taylor",
    "Morgan",
    "Sam",
    "Chris",
    "Pat",
    "Robin",
    "Casey",
    "Jamie",
    "Riley",
    "Avery",
    "Logan",
    "Dakota",
    "Reese",
)
_SYNTHETIC_LAST_NAMES = (
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Gonzalez",
)
_SYNTHETIC_STREETS = (
    "Oak Street",
    "Maple Avenue",
    "Cedar Lane",
    "Pine Road",
    "Elm Boulevard",
    "Washington Way",
    "Lakeview Drive",
    "Highland Court",
    "Park Place",
)
_SYNTHETIC_CITIES = (
    "Springfield",
    "Riverdale",
    "Franklin",
    "Clinton",
    "Georgetown",
    "Fairview",
    "Salem",
    "Madison",
    "Greenville",
    "Bristol",
)
_SYNTHETIC_STATES = ("CA", "NY", "TX", "FL", "IL", "PA", "OH", "GA", "NC", "MI")


def _infer_category(field_name: str) -> SyntheticCategory:
    key = field_name.lower().strip()
    if any(k in key for k in ("street", "address", "addr", "line1")):
        return "street_address"
    if any(k in key for k in ("city", "town", "municipality")):
        return "city"
    if any(k in key for k in ("zip", "postal", "postcode")):
        return "zipcode"
    if any(k in key for k in ("state", "province")):
        return "state"
    if any(k in key for k in ("first_name", "firstname", "fname", "given_name")):
        return "first_name"
    if any(k in key for k in ("last_name", "lastname", "lname", "surname", "family_name")):
        return "last_name"
    if any(k in key for k in ("name", "full_name", "patient_name", "client_name")):
        return "full_name"
    if "email" in key:
        return "email"
    if any(k in key for k in ("phone", "mobile", "tel", "cell")):
        return "phone"
    if any(k in key for k in ("card", "cc_num", "credit_card")):
        return "credit_card"
    if any(k in key for k in ("cvv", "cvc", "security_code")):
        return "cvv"
    if any(k in key for k in ("ssn", "social_security")):
        return "ssn"
    if any(k in key for k in ("dob", "birth_date", "birthdate", "date")):
        return "date"
    if any(k in key for k in ("note", "notes", "admission", "prognosis", "summary")):
        return "clinical_note"
    return "generic"


def _render_category(category: SyntheticCategory, field_name: str, rng: random.Random) -> str:
    if category == "street_address":
        return f"{rng.randint(100, 9999)} {rng.choice(_SYNTHETIC_STREETS)}"
    if category == "city":
        return rng.choice(_SYNTHETIC_CITIES)
    if category == "zipcode":
        return f"{rng.randint(10001, 99950):05d}"
    if category == "state":
        return rng.choice(_SYNTHETIC_STATES)
    if category == "first_name":
        return rng.choice(_SYNTHETIC_FIRST_NAMES)
    if category == "last_name":
        return rng.choice(_SYNTHETIC_LAST_NAMES)
    if category == "full_name":
        return f"{rng.choice(_SYNTHETIC_FIRST_NAMES)} {rng.choice(_SYNTHETIC_LAST_NAMES)}"
    if category == "email":
        first = rng.choice(_SYNTHETIC_FIRST_NAMES).lower()
        last = rng.choice(_SYNTHETIC_LAST_NAMES).lower()
        return f"{first}.{last}{rng.randint(10, 99)}@example.invalid"
    if category == "phone":
        return f"+1-555-{rng.randint(100, 199):03d}-{rng.randint(1000, 9999):04d}"
    if category == "credit_card":
        return (
            f"4000-{rng.randint(1000, 9999):04d}-"
            f"{rng.randint(1000, 9999):04d}-{rng.randint(1000, 9999):04d}"
        )
    if category == "cvv":
        return f"{rng.randint(100, 999):03d}"
    if category == "ssn":
        return f"900-{rng.randint(10, 99):02d}-{rng.randint(1000, 9999):04d}"
    if category == "date":
        return f"{rng.randint(1950, 2005):04d}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
    if category == "clinical_note":
        return "[SYNTHETIC CLINICAL NOTE]"
    clean = field_name.upper() if field_name else "VALUE"
    return f"[SYNTHETIC_{clean}_{rng.randint(1000, 9999)}]"


def _extract_field_name(adapter: FormatAdapter, node: Any) -> str:
    try:
        path = adapter.get_path(node)
        tokens = [
            p.strip("'\"")
            for p in re.split(r"[./\[\]@]+", path)
            if p and not p.isdigit() and p not in ("$", "")
        ]
        return tokens[-1].lower() if tokens else "field"
    except Exception:
        return "field"


class SynthesizeParams(TechniqueParams):
    """Parameters for the ``synthesize`` technique."""

    category: SyntheticCategory | None = Field(
        default=None,
        description="Explicit synthetic category; inferred from the leaf field name when omitted.",
    )
    deterministic: bool = Field(
        default=True,
        description="Generate consistent synthetic values keyed via HMAC-SHA256 and salt.",
    )
    preserve_null: bool = Field(
        default=True,
        description="Leave null/None values untouched when true.",
    )


@register_technique("synthesize")
class SynthesizeTechnique(BaseTechnique):
    """Replace values with realistic format-compatible synthetic substitutes."""

    name = "synthesize"
    params_model = SynthesizeParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: SynthesizeParams,
        context: MaskingContext,
    ) -> None:
        raw_value = adapter.get_value(node)
        if raw_value is None and params.preserve_null:
            return

        field_name = _extract_field_name(adapter, node)
        category: SyntheticCategory = params.category or _infer_category(field_name)

        if params.deterministic:
            msg = f"{category}:{field_name}:{raw_value}".encode()
            digest = hmac.new(context.salt.encode(), msg, hashlib.sha256).digest()
            rng = random.Random(int.from_bytes(digest[:16], "big"))
        else:
            rng = context.rng

        adapter.set_value(node, _render_category(category, field_name, rng))

    def auditor_label(self, params: SynthesizeParams) -> str:
        cat_part = f" | category={params.category!r}" if params.category else ""
        return f"[WOULD APPLY: synthesize | deterministic={params.deterministic}{cat_part}]"
