"""Tests for fail-fast load-time policy validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from datamasking import (
    PolicyValidationError,
    load_policy_from_dict,
    load_policy_from_file,
    load_policy_from_yaml,
)


def test_rejects_unknown_top_level_policy_key() -> None:
    with pytest.raises(PolicyValidationError, match="ruels"):
        load_policy_from_dict({"version": "1.0", "ruels": []})


def test_rejects_unregistered_technique_at_load_time() -> None:
    with pytest.raises(PolicyValidationError, match="not registered"):
        load_policy_from_dict(
            {
                "rules": [{"selector": "$.ssn", "technique": "quantum_encrypt"}],
            }
        )


def test_rejects_unknown_or_misspelled_technique_params_inline_and_nested() -> None:
    with pytest.raises(PolicyValidationError, match="replacment"):
        load_policy_from_dict(
            {
                "rules": [
                    {
                        "selector": "$.name",
                        "technique": "redact",
                        "replacment": "[MASKED]",
                    }
                ]
            }
        )

    with pytest.raises(PolicyValidationError, match="unknown_flag"):
        load_policy_from_dict(
            {
                "rules": [
                    {
                        "selector": "$.name",
                        "technique": "suppress",
                        "params": {"unknown_flag": True},
                    }
                ]
            }
        )


def test_rejects_conflicting_inline_and_nested_param() -> None:
    with pytest.raises(PolicyValidationError, match="conflicting values"):
        load_policy_from_dict(
            {
                "rules": [
                    {
                        "selector": "$.name",
                        "technique": "redact",
                        "replacement": "A",
                        "params": {"replacement": "B"},
                    }
                ]
            }
        )


def test_rejects_unknown_hierarchy_in_rule_and_kanon() -> None:
    with pytest.raises(PolicyValidationError, match="not registered"):
        load_policy_from_dict(
            {
                "rules": [
                    {
                        "selector": "$.dob",
                        "technique": "generalize",
                        "hierarchy": "nonexistent_taxonomy",
                    }
                ]
            }
        )

    with pytest.raises(PolicyValidationError, match="not registered"):
        load_policy_from_dict(
            {
                "k_anonymity": {
                    "k": 2,
                    "quasi_identifiers": [{"selector": "$.zip", "hierarchy": "unknown_h"}],
                }
            }
        )


def test_validates_selectors_at_load_time_when_format_is_declared() -> None:
    # XPath selector inside a JSON policy
    with pytest.raises(PolicyValidationError, match="expected JSONPath"):
        load_policy_from_dict(
            {
                "format": "json",
                "rules": [{"selector": "//patient/ssn", "technique": "suppress"}],
            }
        )

    # JSONPath selector inside an XML policy
    with pytest.raises(PolicyValidationError, match="expected XPath"):
        load_policy_from_dict(
            {
                "format": "xml",
                "rules": [{"selector": "$.patient.ssn", "technique": "suppress"}],
            }
        )

    # Broken JSONPath syntax
    with pytest.raises(PolicyValidationError, match="Invalid selector"):
        load_policy_from_dict(
            {
                "format": "json",
                "rules": [{"selector": "$[unclosed", "technique": "suppress"}],
            }
        )

    # Broken XPath syntax
    with pytest.raises(PolicyValidationError, match="Invalid selector"):
        load_policy_from_dict(
            {
                "format": "xml",
                "rules": [{"selector": "//patient[unclosed", "technique": "suppress"}],
            }
        )

    # Unknown format
    with pytest.raises(PolicyValidationError, match="Unsupported format"):
        load_policy_from_dict({"format": "protobuf", "rules": []})


def test_rejects_missing_scope_profile_references() -> None:
    with pytest.raises(PolicyValidationError, match="missing_prof"):
        load_policy_from_dict(
            {
                "scopes": [{"path": "$.notes", "apply_profile": "missing_prof"}],
            }
        )

    with pytest.raises(PolicyValidationError, match="role_missing_prof"):
        load_policy_from_dict(
            {
                "scopes": [
                    {
                        "path": "$.notes",
                        "roles": {
                            "analyst": {"strategy": "masked", "profile": "role_missing_prof"}
                        },
                    }
                ],
            }
        )


def test_kanon_validation_constraints() -> None:
    # k must be >= 2
    with pytest.raises(PolicyValidationError):
        load_policy_from_dict(
            {
                "k_anonymity": {"k": 1, "quasi_identifiers": ["$.zip"]},
            }
        )

    # max_level without hierarchy
    with pytest.raises(PolicyValidationError, match="without specifying 'hierarchy'"):
        load_policy_from_dict(
            {
                "k_anonymity": {
                    "k": 2,
                    "quasi_identifiers": [{"selector": "$.zip", "max_level": 3}],
                }
            }
        )

    # max_level exceeding hierarchy.max_level (zipcode max_level is 5)
    with pytest.raises(PolicyValidationError, match="exceeds hierarchy"):
        load_policy_from_dict(
            {
                "k_anonymity": {
                    "k": 2,
                    "quasi_identifiers": [
                        {"selector": "$.zip", "hierarchy": "zipcode", "max_level": 9}
                    ],
                }
            }
        )

    # strategy='enforce' with on_unresolved='flag' requires at least one hierarchy
    with pytest.raises(PolicyValidationError, match="requires at least one quasi_identifier"):
        load_policy_from_dict(
            {
                "k_anonymity": {
                    "k": 2,
                    "strategy": "enforce",
                    "quasi_identifiers": ["$.zip"],
                }
            }
        )


def test_yaml_and_file_loader_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyValidationError, match="non-empty"):
        load_policy_from_yaml("   ")

    with pytest.raises(PolicyValidationError, match="Invalid YAML"):
        load_policy_from_yaml("rules: [unclosed")

    with pytest.raises(PolicyValidationError, match="mapping/dictionary"):
        load_policy_from_yaml("- just_a_list")

    with pytest.raises(PolicyValidationError, match="mapping/dictionary"):
        load_policy_from_dict(["not_a_dict"])  # type: ignore[arg-type]

    with pytest.raises(PolicyValidationError, match="not found"):
        load_policy_from_file(tmp_path / "does_not_exist.yaml")

    with pytest.raises(PolicyValidationError, match="Unsupported policy version"):
        load_policy_from_dict({"version": "99.0", "rules": []})

    with pytest.raises(PolicyValidationError, match="only supported for"):
        load_policy_from_dict(
            {
                "scopes": [
                    {
                        "path": "$.x",
                        "roles": {
                            "r": {"strategy": "drop_subtree", "params": {"replacement": "X"}}
                        },
                    }
                ]
            }
        )
