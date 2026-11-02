"""Comprehensive unit tests for all 10 built-in masking techniques."""

from __future__ import annotations

import math
import random

import pytest

from datamasking import MaskingEngine, TechniqueExecutionError


def test_redact_and_preserve_null() -> None:
    eng_default = MaskingEngine(
        {"rules": [{"selector": "$.*", "technique": "redact", "replacement": "[HIDDEN]"}]}
    )
    assert eng_default.mask_data({"a": "hello", "b": None}) == {"a": "[HIDDEN]", "b": "[HIDDEN]"}

    eng_keep_null = MaskingEngine(
        {
            "rules": [
                {
                    "selector": "$.*",
                    "technique": "redact",
                    "params": {"replacement": "[HIDDEN]", "preserve_null": True},
                }
            ]
        }
    )
    assert eng_keep_null.mask_data({"a": "hello", "b": None}) == {"a": "[HIDDEN]", "b": None}


def test_suppress_and_nullify() -> None:
    engine = MaskingEngine(
        {
            "rules": [
                {"selector": "$.drop_me", "technique": "suppress"},
                {"selector": "$.null_me", "technique": "nullify"},
            ]
        }
    )
    assert engine.mask_data({"drop_me": 1, "null_me": "secret", "keep": True}) == {
        "null_me": None,
        "keep": True,
    }


def test_pseudonymize_consistent_keyed_and_random_seeded() -> None:
    policy = {
        "rules": [
            {
                "selector": "$.id",
                "technique": "pseudonymize",
                "params": {"consistent": True, "prefix": "USR_", "token_length": 12},
            },
            {
                "selector": "$.nonce",
                "technique": "pseudonymize",
                "params": {"consistent": False, "prefix": "TMP_", "token_length": 10},
            },
        ]
    }
    eng_a = MaskingEngine(policy, salt="secret-key-alpha")
    eng_b = MaskingEngine(policy, salt="secret-key-beta")

    out_a1 = eng_a.mask_data({"id": "U-1", "nonce": "X"}, seed=42)
    out_a2 = eng_a.mask_data({"id": "U-1", "nonce": "X"}, seed=42)
    out_a3 = eng_a.mask_data({"id": "U-1", "nonce": "X"}, seed=99)
    out_b1 = eng_b.mask_data({"id": "U-1", "nonce": "X"}, seed=42)

    assert out_a1["id"].startswith("USR_") and len(out_a1["id"]) == 16
    assert out_a1["id"] == out_a2["id"] == out_a3["id"]  # keyed HMAC is independent of RNG seed
    assert out_a1["id"] != out_b1["id"]  # different HMAC salt -> different token

    assert out_a1["nonce"] == out_a2["nonce"]  # identical seed -> identical random token
    assert out_a1["nonce"] != out_a3["nonce"]  # different seed -> different random token

    # Null preserved by default
    assert eng_a.mask_data({"id": None, "nonce": None}) == {"id": None, "nonce": None}


def test_format_preserve_and_global_rng_isolation() -> None:
    random.seed(12345)
    expected_next_global_rand = random.random()
    random.seed(12345)

    engine = MaskingEngine(
        {
            "rules": [
                {
                    "selector": "$.code",
                    "technique": "format_preserve",
                    "params": {"preserve_prefix": 3, "preserve_suffix": 2, "deterministic": True},
                },
                {
                    "selector": "$.serial",
                    "technique": "format_preserve",
                    "params": {"deterministic": False},
                },
            ]
        },
        salt="fpe-key",
    )
    out1 = engine.mask_data({"code": "ID-9876-AB", "serial": "Ab9-Zz"}, seed=7)
    out2 = engine.mask_data({"code": "ID-9876-AB", "serial": "Ab9-Zz"}, seed=7)

    # Global random module state was NOT touched!
    assert random.random() == expected_next_global_rand

    assert out1 == out2
    assert out1["code"].startswith("ID-") and out1["code"].endswith("AB")
    assert out1["code"][7] == "-"
    assert len(out1["serial"]) == len("Ab9-Zz") and out1["serial"][3] == "-"


def test_noise_numeric_types_and_boolean_nan_rejection() -> None:
    engine = MaskingEngine(
        {
            "rules": [
                {
                    "selector": "$.*",
                    "technique": "noise",
                    "params": {"percentage": 10.0, "precision": 3},
                }
            ]
        }
    )
    out = engine.mask_data(
        {"salary": 1000, "temp": 98.6, "str_int": "500", "str_flt": "12.5", "nil": None}, seed=11
    )
    assert isinstance(out["salary"], int) and 900 <= out["salary"] <= 1100
    assert isinstance(out["temp"], float) and 88.74 <= out["temp"] <= 108.46
    assert isinstance(out["str_int"], str) and out["str_int"].isdigit()
    assert isinstance(out["str_flt"], str)
    assert out["nil"] is None

    # Booleans must NOT be treated as int (isinstance(True, int) is True in Python!)
    with pytest.raises(TechniqueExecutionError, match="boolean"):
        engine.mask({"flag": True})

    # NaN / Inf rejected
    with pytest.raises(TechniqueExecutionError, match="finite"):
        engine.mask({"bad_float": "nan"})
    assert math.isnan(float("nan"))


def test_mask_pattern_placeholders() -> None:
    engine = MaskingEngine(
        {
            "rules": [
                {
                    "selector": "$.email",
                    "technique": "mask_pattern",
                    "pattern": "{first1}***@{domain}",
                },
                {
                    "selector": "$.card",
                    "technique": "mask_pattern",
                    "pattern": "****-{digits_last4}",
                },
                {"selector": "$.code", "technique": "mask_pattern", "pattern": "{first2}..{last2}"},
            ]
        }
    )
    out = engine.mask_data(
        {
            "email": "alice@biocorp.org",
            "card": "4111-2222-3333-9876",
            "code": "ABCDEF",
            "email_null": None,
        }
    )
    assert out["email"] == "a***@biocorp.org"
    assert out["card"] == "****-9876"
    assert out["code"] == "AB..EF"


def test_synthesize_categories_and_key_isolation() -> None:
    engine_1 = MaskingEngine(
        {
            "rules": [
                {"selector": "$.*", "technique": "synthesize", "params": {"deterministic": True}},
            ]
        },
        salt="synth-key-1",
    )
    engine_2 = MaskingEngine(
        {
            "rules": [
                {"selector": "$.*", "technique": "synthesize", "params": {"deterministic": True}},
            ]
        },
        salt="synth-key-2",
    )
    sample = {
        "first_name": "Alice",
        "last_name": "Smith",
        "full_name": "Alice Smith",
        "email": "alice@real.com",
        "phone": "415-555-9999",
        "street_address": "10 Real Rd",
        "city": "Boston",
        "state": "MA",
        "zipcode": "02108",
        "ssn": "123-45-6789",
        "credit_card": "4111-1111-1111-1111",
        "cvv": "999",
        "birth_date": "1990-05-10",
        "clinical_notes": "Patient presented with cough",
        "custom_metric": "raw",
        "optional_field": None,
    }
    res1 = engine_1.mask_data(sample)
    res1_repeat = engine_1.mask_data(sample)
    res2 = engine_2.mask_data(sample)

    assert res1 == res1_repeat
    assert res1["email"].endswith("@example.invalid")
    assert res1["ssn"].startswith("900-")
    assert res1["optional_field"] is None
    # Keyed HMAC ensures different salts do not map all attributes identically
    assert res1 != res2


def test_deep_redact_on_nested_container() -> None:
    engine = MaskingEngine(
        {
            "rules": [
                {
                    "selector": "$.audit_blob",
                    "technique": "deep_redact",
                    "params": {"replacement": "[SCRUBBED]", "preserve_null": True},
                }
            ]
        }
    )
    payload = {
        "id": "100",
        "audit_blob": {
            "actor": "dr_jones",
            "tags": ["vip", None],
            "nested": {"ip": "10.0.0.1"},
        },
    }
    assert engine.mask_data(payload) == {
        "id": "100",
        "audit_blob": {
            "actor": "[SCRUBBED]",
            "tags": ["[SCRUBBED]", None],
            "nested": {"ip": "[SCRUBBED]"},
        },
    }
