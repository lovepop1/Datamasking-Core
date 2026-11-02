"""Property-based Hypothesis tests, JSON Schema drift check, and runnable example verification."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from datamasking import MaskingEngine, export_policy_json_schema

REPO_ROOT = Path(__file__).resolve().parent.parent

_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=24),
)


@settings(max_examples=40, deadline=None)
@given(
    secret=st.text(min_size=1, max_size=30).filter(lambda s: s != "[REDACTED]"),
    untouched=st.dictionaries(
        keys=st.from_regex(r"^[a-z][a-z0-9_]{0,10}$", fullmatch=True).filter(
            lambda k: k != "secret"
        ),
        values=_JSON_SCALARS,
        max_size=6,
    ),
)
def test_property_policy_preserves_all_unmatched_fields_and_never_leaks_redacted_target(
    secret: str,
    untouched: dict[str, object],
) -> None:
    payload: dict[str, object] = {"secret": secret, **untouched}
    engine = MaskingEngine({"rules": [{"selector": "$.secret", "technique": "redact"}]})
    masked = engine.mask_data(payload)

    assert masked["secret"] == "[REDACTED]"
    for k, v in untouched.items():
        if isinstance(v, float):
            assert abs(float(masked[k]) - v) < 1e-5
        else:
            assert masked[k] == v


@settings(max_examples=30, deadline=None)
@given(
    val=st.text(min_size=1, max_size=40),
    salt_a=st.text(min_size=8, max_size=32),
    salt_b=st.text(min_size=8, max_size=32),
)
def test_property_hmac_pseudonymization_determinism_and_key_separation(
    val: str,
    salt_a: str,
    salt_b: str,
) -> None:
    policy = {
        "rules": [{"selector": "$.id", "technique": "pseudonymize", "params": {"token_length": 32}}]
    }
    eng_1 = MaskingEngine(policy, salt=salt_a)
    eng_2 = MaskingEngine(policy, salt=salt_a)
    assert eng_1.mask_data({"id": val}) == eng_2.mask_data({"id": val})

    if salt_a != salt_b:
        eng_other = MaskingEngine(policy, salt=salt_b)
        assert eng_1.mask_data({"id": val}) != eng_other.mask_data({"id": val})


@settings(max_examples=25, deadline=None)
@given(
    zips=st.lists(
        st.from_regex(r"^[1-9][0-9]{4}$", fullmatch=True),
        min_size=4,
        max_size=12,
    ),
    k=st.integers(min_value=2, max_value=4),
)
def test_property_kanon_enforce_guarantees_every_equivalence_class_at_least_k(
    zips: list[str],
    k: int,
) -> None:
    payload = {"records": [{"zipcode": z} for z in zips]}
    engine = MaskingEngine(
        {
            "record_root": "$.records[*]",
            "k_anonymity": {
                "k": k,
                "strategy": "enforce",
                "on_unresolved": "suppress",
                "quasi_identifiers": [{"selector": "$.zipcode", "hierarchy": "zipcode"}],
            },
        }
    )
    res = engine.mask(payload)
    assert res.k_achieved is True
    records = json.loads(res.output_text)["records"]
    counts: dict[str, int] = {}
    for rec in records:
        counts[rec["zipcode"]] = counts.get(rec["zipcode"], 0) + 1
    assert all(c >= k for c in counts.values())


def test_committed_json_schema_matches_exported_policy_schema() -> None:
    schema_path = REPO_ROOT / "schema" / "policy.schema.json"
    assert schema_path.is_file(), "schema/policy.schema.json is missing"
    committed = json.loads(schema_path.read_text(encoding="utf-8"))
    expected = export_policy_json_schema()
    assert committed == expected


def test_runnable_examples_execute_cleanly() -> None:
    quickstart_script = REPO_ROOT / "examples" / "quickstart" / "run.py"
    proc_qs = subprocess.run(
        [sys.executable, str(quickstart_script)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "k-Anonymity met:  True" in proc_qs.stdout
    assert "J45.909" in proc_qs.stdout  # Unmatched diagnosis_code preserved!
    assert "123-45-6789" not in proc_qs.stdout  # SSN suppressed!

    plugin_script = REPO_ROOT / "examples" / "custom_plugin" / "run.py"
    proc_pl = subprocess.run(
        [sys.executable, str(plugin_script)],
        capture_output=True,
        text=True,
        check=True,
    )
    parsed = json.loads(proc_pl.stdout)
    assert parsed["study_arm"] == "control"  # Unmatched field preserved!
    assert parsed["encounters"][0]["admitted_on"] == "2026-03-01"
