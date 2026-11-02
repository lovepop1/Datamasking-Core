"""Tests for built-in and custom generalization hierarchies."""

from __future__ import annotations

import pytest

from datamasking import HierarchyNotFoundError, get_hierarchy, list_hierarchies


def test_builtin_hierarchies_registered() -> None:
    names = list_hierarchies()
    assert {"age", "date", "icd10", "zip", "zipcode"}.issubset(set(names))
    with pytest.raises(HierarchyNotFoundError):
        get_hierarchy("unknown_hierarchy")


def test_date_hierarchy_levels_and_validation() -> None:
    h = get_hierarchy("date")
    assert h.max_level == 4
    assert h.generalize("1984-06-19", 0) == "1984-06-19"
    assert h.generalize("1984-06-19T14:30:00Z", 1) == "1984-06"
    assert h.generalize("1984-06-19", 2) == "1984"
    assert h.generalize("1984-06-19", 3) == "1980-1989"
    assert h.generalize("1984-06-19", 4) == "*"
    assert h.generalize("1984-06-19", 99) == "*"

    # Real calendar date validation (Feb 30 does not exist)
    with pytest.raises(ValueError, match="Invalid calendar date"):
        h.generalize("2025-02-30", 1)
    with pytest.raises(ValueError, match="ISO-8601"):
        h.generalize("not-a-date", 1)
    with pytest.raises(ValueError, match=">= 0"):
        h.generalize("1984-06-19", -1)


def test_zipcode_hierarchy_levels_and_zip_plus_4() -> None:
    h = get_hierarchy("zipcode")
    assert h.max_level == 5
    assert h.generalize("94107-1234", 0) == "94107"
    assert h.generalize("94107", 1) == "9410*"
    assert h.generalize("94107", 2) == "941**"
    assert h.generalize("94107", 3) == "94***"
    assert h.generalize("94107", 4) == "9****"
    assert h.generalize("94107", 5) == "*****"

    with pytest.raises(ValueError, match="ZIP"):
        h.generalize("ABCDE", 1)
    with pytest.raises(ValueError, match=">= 0"):
        h.generalize("94107", -1)


def test_age_hierarchy_levels_and_bounds() -> None:
    h = get_hierarchy("age")
    assert h.max_level == 4
    assert h.generalize("41", 0) == "41"
    assert h.generalize("41", 1) == "40-44"
    assert h.generalize("41", 2) == "40-49"
    assert h.generalize("41", 3) == "40-59"
    assert h.generalize("41", 4) == "*"

    with pytest.raises(ValueError, match="domain"):
        h.generalize("-5", 1)
    with pytest.raises(ValueError, match="domain"):
        h.generalize("200", 1)
    with pytest.raises(ValueError, match="integer age"):
        h.generalize("forty", 1)
    with pytest.raises(ValueError, match=">= 0"):
        h.generalize("41", -1)


def test_icd10_hierarchy_levels_and_validation() -> None:
    h = get_hierarchy("icd10")
    assert h.max_level == 3
    assert h.generalize("j45.909", 0) == "J45.909"
    assert h.generalize("J45.909", 1) == "J45"
    assert h.generalize("J45.909", 2) == "J**"
    assert h.generalize("J45.909", 3) == "***"

    with pytest.raises(ValueError, match="ICD-10"):
        h.generalize("99999", 1)
    with pytest.raises(ValueError, match=">= 0"):
        h.generalize("J45", -1)
