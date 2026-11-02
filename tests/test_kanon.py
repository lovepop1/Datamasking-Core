"""Tests for k-anonymity verification, iterative full-domain generalization, and outlier suppression."""

from __future__ import annotations

import csv
import io
import json

from lxml import etree

from datamasking import MaskingEngine


def test_kanon_verify_does_not_mutate_data() -> None:
    payload = {
        "patients": [
            {"zip": "94107", "age": 41, "dx": "A"},
            {"zip": "94109", "age": 44, "dx": "B"},
        ]
    }
    engine = MaskingEngine(
        {
            "record_root": "$.patients[*]",
            "k_anonymity": {
                "k": 2,
                "strategy": "verify",
                "quasi_identifiers": ["$.zip", "$.age"],
            },
        }
    )
    res = engine.mask(payload)
    assert res.k_achieved is False
    assert res.kanon_report is not None
    assert len(res.kanon_report.violating_classes) == 2
    # Zero mutation in verify mode!
    assert json.loads(res.output_text) == payload


def test_kanon_enforce_iterative_generalization_reaches_k() -> None:
    payload = {
        "patients": [
            {"name": "P1", "dob": "1984-06-19", "zipcode": "94107", "age": 41},
            {"name": "P2", "dob": "1984-11-02", "zipcode": "94109", "age": 44},
            {"name": "P3", "dob": "1972-01-10", "zipcode": "60611", "age": 53},
            {"name": "P4", "dob": "1972-09-25", "zipcode": "60614", "age": 51},
        ]
    }
    engine = MaskingEngine(
        {
            "record_root": "$.patients[*]",
            "rules": [{"selector": "$.patients[*].name", "technique": "suppress"}],
            "k_anonymity": {
                "k": 2,
                "strategy": "enforce",
                "quasi_identifiers": [
                    {"selector": "$.dob", "hierarchy": "date"},
                    {"selector": "$.zipcode", "hierarchy": "zipcode"},
                    {"selector": "$.age", "hierarchy": "age"},
                ],
            },
        }
    )
    res = engine.mask(payload)
    assert res.k_achieved is True
    assert res.kanon_report is not None
    assert res.kanon_report.suppressed_records == 0
    assert res.kanon_report.total_records == 4

    out = json.loads(res.output_text)["patients"]
    # First pair and second pair form equivalence classes of size 2
    assert (out[0]["dob"], out[0]["zipcode"], out[0]["age"]) == (
        out[1]["dob"],
        out[1]["zipcode"],
        out[1]["age"],
    )
    assert (out[2]["dob"], out[2]["zipcode"], out[2]["age"]) == (
        out[3]["dob"],
        out[3]["zipcode"],
        out[3]["age"],
    )


def test_kanon_enforce_with_max_level_and_unresolved_flag_vs_suppress() -> None:
    payload = {
        "patients": [
            {"zipcode": "94107"},
            {"zipcode": "94107"},
            {"zipcode": "10001"},  # Singleton outlier in completely different region
        ]
    }

    # 1. With max_level=2 and on_unresolved='flag', singleton cannot merge with 941** -> flagged, not deleted
    eng_flag = MaskingEngine(
        {
            "record_root": "$.patients[*]",
            "k_anonymity": {
                "k": 2,
                "strategy": "enforce",
                "on_unresolved": "flag",
                "quasi_identifiers": [
                    {"selector": "$.zipcode", "hierarchy": "zipcode", "max_level": 2}
                ],
            },
        }
    )
    res_flag = eng_flag.mask(payload)
    assert res_flag.k_achieved is False
    assert len(json.loads(res_flag.output_text)["patients"]) == 3

    # 2. With on_unresolved='suppress', remaining singleton outlier is suppressed so k=2 holds!
    eng_sup = MaskingEngine(
        {
            "record_root": "$.patients[*]",
            "k_anonymity": {
                "k": 2,
                "strategy": "enforce",
                "on_unresolved": "suppress",
                "quasi_identifiers": [
                    {"selector": "$.zipcode", "hierarchy": "zipcode", "max_level": 2}
                ],
            },
        }
    )
    res_sup = eng_sup.mask(payload)
    assert res_sup.k_achieved is True
    assert res_sup.kanon_report is not None
    assert res_sup.kanon_report.suppressed_records == 1
    assert len(json.loads(res_sup.output_text)["patients"]) == 2


def test_kanon_suppress_strategy_on_xml_and_csv() -> None:
    xml_doc = b"""<patients>
      <patient><zip>10001</zip></patient>
      <patient><zip>10001</zip></patient>
      <patient><zip>99999</zip></patient>
    </patients>"""
    xml_engine = MaskingEngine(
        {
            "format": "xml",
            "record_root": "//patient",
            "k_anonymity": {
                "k": 2,
                "strategy": "suppress",
                "quasi_identifiers": ["//zip"],
            },
        }
    )
    res_xml = xml_engine.mask(xml_doc)
    assert res_xml.k_achieved is True
    root = etree.fromstring(res_xml.output_bytes)
    assert len(root.xpath("//patient")) == 2

    csv_doc = b"zip,dx\n10001,A\n10001,B\n99999,C\n"
    csv_engine = MaskingEngine(
        {
            "format": "csv",
            "record_root": "$[*]",
            "k_anonymity": {
                "k": 2,
                "strategy": "suppress",
                "quasi_identifiers": ["$.zip"],
            },
        }
    )
    res_csv = csv_engine.mask(csv_doc)
    assert res_csv.k_achieved is True
    rows = list(csv.DictReader(io.StringIO(res_csv.output_text)))
    assert len(rows) == 2
