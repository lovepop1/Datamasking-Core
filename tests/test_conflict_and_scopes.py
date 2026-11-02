"""Tests for Phase 0 subtree scopes, role strategies, and Phase 2 conflict resolution."""

from __future__ import annotations

import json

from datamasking import MaskingEngine


def test_specificity_and_priority_conflict_resolution() -> None:
    payload = {"patients": [{"email": "alice@biocorp.com"}], "contact_email": "info@biocorp.com"}

    # Without explicit priority, specific '$.patients[*].email' beats recursive '$..email'
    engine_spec = MaskingEngine(
        {
            "rules": [
                {
                    "id": "broad",
                    "selector": "$..email",
                    "technique": "redact",
                    "replacement": "[BROAD]",
                },
                {
                    "id": "specific",
                    "selector": "$.patients[*].email",
                    "technique": "redact",
                    "replacement": "[SPECIFIC]",
                },
            ]
        }
    )
    res_spec = engine_spec.mask(payload)
    assert res_spec.conflict_count == 1
    assert res_spec.conflict_log[0]["winning_rule"]["id"] == "specific"
    assert json.loads(res_spec.output_text)["patients"][0]["email"] == "[SPECIFIC]"

    # Explicit priority overrides specificity
    engine_prio = MaskingEngine(
        {
            "rules": [
                {
                    "id": "high-prio-broad",
                    "selector": "$..email",
                    "technique": "redact",
                    "replacement": "[OVERRIDE]",
                    "priority": 50,
                },
                {
                    "id": "low-prio-specific",
                    "selector": "$.patients[*].email",
                    "technique": "redact",
                    "replacement": "[SPECIFIC]",
                    "priority": 0,
                },
            ]
        }
    )
    res_prio = engine_prio.mask(payload)
    assert res_prio.conflict_log[0]["winning_rule"]["id"] == "high-prio-broad"
    assert json.loads(res_prio.output_text)["patients"][0]["email"] == "[OVERRIDE]"


def test_per_rule_roles_filter() -> None:
    engine = MaskingEngine(
        {
            "rules": [
                {"selector": "$.ssn", "technique": "suppress"},
                {
                    "selector": "$.phone",
                    "technique": "redact",
                    "roles": ["external_vendor"],
                },
            ]
        }
    )
    payload = {"ssn": "111-22-3333", "phone": "555-0100"}

    assert engine.mask_data(payload, role="internal_clinician") == {"phone": "555-0100"}
    assert engine.mask_data(payload, role="external_vendor") == {"phone": "[REDACTED]"}


def test_nested_scopes_and_subtree_strategies() -> None:
    policy = {
        "profiles": {
            "patient_base": {
                "rules": [
                    {"selector": "$..name", "technique": "redact"},
                    {"selector": "$..ssn", "technique": "suppress"},
                ]
            }
        },
        "scopes": [
            {
                "path": "$.patient",
                "apply_profile": "patient_base",
                "roles": {
                    "researcher": {"strategy": "masked"},
                    "doctor": {"strategy": "passthrough"},
                },
            },
            {
                # Inner scope inside $.patient overrides outer scope for $.patient.psych_notes!
                "path": "$.patient.psych_notes",
                "roles": {
                    "researcher": {"strategy": "drop_subtree"},
                    "qa": {
                        "strategy": "deep_redact",
                        "params": {"replacement": "[PSYCH_REDACTED]"},
                    },
                    "demo": {"strategy": "synthesize"},
                    "doctor": {"strategy": "passthrough"},
                },
            },
        ],
    }
    engine = MaskingEngine(policy, salt="scope-test-salt")
    payload = {
        "patient": {
            "name": "Alice",
            "ssn": "123-45-6789",
            "diagnosis": "I10",
            "psych_notes": {"therapist": "Dr. Ray", "summary": "Confidential"},
        }
    }

    # 1. researcher: outer masked + inner drop_subtree
    res_researcher = engine.mask(payload, role="researcher")
    assert res_researcher.scopes_dropped == 1
    assert res_researcher.profiles_applied == ["patient_base"]
    assert json.loads(res_researcher.output_text) == {
        "patient": {"name": "[REDACTED]", "diagnosis": "I10"}
    }

    # 2. doctor: passthrough on both scopes
    assert engine.mask_data(payload, role="doctor") == payload

    # 3. qa: outer falls back to apply_profile ('masked') + inner 'deep_redact'
    assert engine.mask_data(payload, role="qa") == {
        "patient": {
            "name": "[REDACTED]",
            "diagnosis": "I10",
            "psych_notes": {"therapist": "[PSYCH_REDACTED]", "summary": "[PSYCH_REDACTED]"},
        }
    }

    # 4. demo: inner 'synthesize'
    demo_out = engine.mask_data(payload, role="demo")
    assert demo_out["patient"]["psych_notes"]["summary"] == "[SYNTHETIC CLINICAL NOTE]"

    # 5. dry_run mode on researcher previews drop_subtree and redact without deleting keys
    dry_out = engine.mask_data(payload, role="researcher", mode="dry_run")
    assert dry_out["patient"]["name"].startswith("[WOULD APPLY: redact")
    assert dry_out["patient"]["ssn"] == "[WOULD APPLY: suppress]"
    assert dry_out["patient"]["diagnosis"] == "I10"
    assert (
        dry_out["patient"]["psych_notes"]["summary"]
        == "[WOULD DROP SUBTREE: $.patient.psych_notes]"
    )
