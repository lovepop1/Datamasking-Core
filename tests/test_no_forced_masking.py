"""Tests verifying the core invariant: Policy is the single source of truth.

Nothing in ``datamasking-core`` may apply a default policy, mutate unmatched
fields without explicit policy instructions, recognize hardcoded magic role
names, or silently overwrite incompatible values with ``[REDACTED]``.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
import yaml
from lxml import etree

from datamasking import (
    MaskingEngine,
    PolicyValidationError,
    TechniqueExecutionError,
)


def test_engine_rejects_none_policy() -> None:
    with pytest.raises(PolicyValidationError, match="no default policy exists"):
        MaskingEngine(None)  # type: ignore[arg-type]


def test_empty_policy_leaves_all_formats_completely_untouched(
    sample_json: bytes,
    sample_xml: bytes,
    sample_yaml: bytes,
    sample_csv: bytes,
) -> None:
    engine = MaskingEngine({"version": "1.0", "rules": []})

    # JSON
    res_json = engine.mask(sample_json, format="json")
    assert json.loads(res_json.output_bytes) == json.loads(sample_json)

    # YAML
    res_yaml = engine.mask(sample_yaml, format="yaml")
    assert yaml.safe_load(res_yaml.output_bytes) == yaml.safe_load(sample_yaml)

    # CSV
    res_csv = engine.mask(sample_csv, format="csv")
    orig_rows = list(csv.DictReader(io.StringIO(sample_csv.decode("utf-8"))))
    out_rows = list(csv.DictReader(io.StringIO(res_csv.output_text)))
    assert out_rows == orig_rows

    # XML
    res_xml = engine.mask(sample_xml, format="xml")
    out_root = etree.fromstring(res_xml.output_bytes)
    assert out_root.xpath("//ssn")[0].text == "111-22-3333"
    assert out_root.xpath("//name")[0].text == "Alice Smith"


def test_partial_policy_only_masks_declared_selector() -> None:
    payload = {
        "ssn": "123-45-6789",
        "name": "Alice Carter",
        "email": "alice@example.com",
        "clinical_score": 98.4,
        "notes": {"summary": "Unmatched nested note"},
    }
    engine = MaskingEngine(
        {
            "version": "1.0",
            "rules": [{"selector": "$.ssn", "technique": "redact"}],
        }
    )
    masked = engine.mask_data(payload)

    assert masked["ssn"] == "[REDACTED]"
    assert masked["name"] == "Alice Carter"
    assert masked["email"] == "alice@example.com"
    assert masked["clinical_score"] == 98.4
    assert masked["notes"] == {"summary": "Unmatched nested note"}


def test_explicit_unmatched_fields_modes() -> None:
    payload = {"matched": "secret", "extra_a": "keep_or_change", "extra_b": 42}

    # 1. unmatched_fields='redact'
    eng_redact = MaskingEngine(
        {
            "unmatched_fields": "redact",
            "unmatched_replacement": "[CLOSED]",
            "rules": [{"selector": "$.matched", "technique": "redact", "replacement": "[M]"}],
        }
    )
    assert eng_redact.mask_data(payload) == {
        "matched": "[M]",
        "extra_a": "[CLOSED]",
        "extra_b": "[CLOSED]",
    }

    # 2. unmatched_fields='nullify'
    eng_null = MaskingEngine(
        {
            "unmatched_fields": "nullify",
            "rules": [{"selector": "$.matched", "technique": "redact", "replacement": "[M]"}],
        }
    )
    assert eng_null.mask_data(payload) == {
        "matched": "[M]",
        "extra_a": None,
        "extra_b": None,
    }

    # 3. unmatched_fields='suppress'
    eng_suppress = MaskingEngine(
        {
            "unmatched_fields": "suppress",
            "rules": [{"selector": "$.matched", "technique": "redact", "replacement": "[M]"}],
        }
    )
    assert eng_suppress.mask_data(payload) == {"matched": "[M]"}


def test_no_magic_operator_or_auditor_roles() -> None:
    """Passing role='operator' or role='auditor' must NOT trigger hidden bypasses or labels."""
    engine = MaskingEngine(
        {
            "version": "1.0",
            "rules": [{"selector": "$.ssn", "technique": "redact"}],
        }
    )
    payload = {"ssn": "123-45-6789", "diagnosis": "I10"}

    # 'operator' is NOT defined with passthrough in policy -> MUST still mask $.ssn!
    op_out = engine.mask_data(payload, role="operator")
    assert op_out == {"ssn": "[REDACTED]", "diagnosis": "I10"}

    # 'auditor' is NOT a magic dry-run trigger -> MUST still mask $.ssn normally and leave $.diagnosis alone!
    aud_out = engine.mask_data(payload, role="auditor")
    assert aud_out == {"ssn": "[REDACTED]", "diagnosis": "I10"}


def test_explicit_policy_role_passthrough_and_explicit_dry_run() -> None:
    engine = MaskingEngine(
        {
            "version": "1.0",
            "roles": {
                "chief_privacy_officer": {"passthrough": True},
            },
            "rules": [{"selector": "$.ssn", "technique": "redact"}],
        }
    )
    payload = {"ssn": "123-45-6789", "diagnosis": "I10"}

    # Policy-declared passthrough role receives raw payload
    assert engine.mask_data(payload, role="chief_privacy_officer") == payload

    # Unlisted role still gets masked
    assert engine.mask_data(payload, role="data_scientist") == {
        "ssn": "[REDACTED]",
        "diagnosis": "I10",
    }

    # Explicit mode='dry_run' previews only matched rules and leaves unmatched fields untouched
    dry = engine.mask_data(payload, mode="dry_run")
    assert dry == {
        "ssn": "[WOULD APPLY: redact | replacement='[REDACTED]']",
        "diagnosis": "I10",
    }


def test_no_silent_redaction_on_domain_errors_unless_configured() -> None:
    payload = {"amount": "NOT_A_NUMBER", "dob": "9999-99-99"}

    # Default on_error='raise' fails loudly instead of silently emitting '[REDACTED]'
    strict_engine = MaskingEngine(
        {
            "rules": [{"selector": "$.amount", "technique": "noise", "percentage": 5.0}],
        }
    )
    with pytest.raises(TechniqueExecutionError, match="not numeric"):
        strict_engine.mask(payload)

    # Explicit on_error='preserve' leaves original value and records a warning
    preserve_engine = MaskingEngine(
        {
            "on_error": "preserve",
            "rules": [
                {"selector": "$.amount", "technique": "noise", "percentage": 5.0},
                {"selector": "$.dob", "technique": "generalize", "hierarchy": "date", "level": 1},
            ],
        }
    )
    res_preserve = preserve_engine.mask(payload)
    assert json.loads(res_preserve.output_text) == payload
    assert len(res_preserve.warnings) == 2

    # Explicit per-rule on_error='redact' and 'nullify'
    custom_err_engine = MaskingEngine(
        {
            "rules": [
                {
                    "selector": "$.amount",
                    "technique": "noise",
                    "on_error": "nullify",
                },
                {
                    "selector": "$.dob",
                    "technique": "generalize",
                    "hierarchy": "date",
                    "on_error": "redact",
                },
            ]
        }
    )
    res_custom = custom_err_engine.mask(payload)
    assert json.loads(res_custom.output_text) == {"amount": None, "dob": "[REDACTED]"}
    assert len(res_custom.warnings) == 2
