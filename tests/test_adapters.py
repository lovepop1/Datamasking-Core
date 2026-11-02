"""Format adapter tests covering JSON, XML, YAML, CSV, selectors, and parser hardening."""

from __future__ import annotations

import csv
import io

import pytest
import yaml
from lxml import etree

from datamasking import (
    FormatParseError,
    MaskingEngine,
    SelectorEvaluationError,
    UnsupportedFormatError,
    detect_format_from_content,
    detect_format_from_filename,
    get_adapter,
)


def test_json_special_keys_and_filter_predicates() -> None:
    payload = {
        "user.profile": {"first name": "secret_user"},
        "patients": [
            {"name": "Minor Child", "age": 14},
            {"name": "Adult Patient", "age": 39},
        ],
    }
    engine = MaskingEngine(
        {
            "format": "json",
            "rules": [
                {"selector": "$['user.profile']['first name']", "technique": "redact"},
                {"selector": "$.patients[?(@.age < 18)].name", "technique": "redact"},
            ],
        }
    )
    masked = engine.mask_data(payload)
    assert masked["user.profile"]["first name"] == "[REDACTED]"
    assert masked["patients"][0]["name"] == "[REDACTED]"
    assert masked["patients"][1]["name"] == "Adult Patient"


def test_json_array_element_suppression_reindexes_cleanly() -> None:
    payload = {"items": [{"code": "DROP"}, {"code": "KEEP"}, {"code": "DROP"}]}
    engine = MaskingEngine(
        {
            "format": "json",
            "rules": [{"selector": "$.items[?(@.code == 'DROP')]", "technique": "suppress"}],
        }
    )
    assert engine.mask_data(payload) == {"items": [{"code": "KEEP"}]}


def test_xml_elements_attributes_and_default_namespace() -> None:
    xml_doc = b"""<?xml version="1.0" encoding="UTF-8"?>
    <Patient xmlns="http://hl7.org/fhir" id="MRN-77">
      <name value="Jane Doe"/>
      <ssn>999-88-7777</ssn>
      <note>Confidential</note>
      <status>active</status>
    </Patient>"""

    engine = MaskingEngine(
        {
            "format": "xml",
            "rules": [
                {"selector": "//Patient/@id", "technique": "redact", "replacement": "ANON"},
                {"selector": "//name/@value", "technique": "redact"},
                {"selector": "//ssn", "technique": "suppress"},
                {"selector": "//note", "technique": "nullify"},
            ],
        }
    )
    res = engine.mask(xml_doc, format="xml")
    root = etree.fromstring(res.output_bytes)
    ns = {"f": "http://hl7.org/fhir"}
    assert root.get("id") == "ANON"
    assert root.xpath("//f:name/@value", namespaces=ns) == ["[REDACTED]"]
    assert root.xpath("//f:ssn", namespaces=ns) == []
    assert root.xpath("//f:note", namespaces=ns)[0].text in ("", None)
    assert root.xpath("//f:status", namespaces=ns)[0].text == "active"


def test_xml_xxe_is_blocked() -> None:
    xxe_payload = b"""<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <root><secret>&xxe;</secret></root>"""

    adapter = get_adapter("xml")
    # Either rejected at parse time or entity left unexpanded (never resolves file:///etc/passwd)
    try:
        tree = adapter.parse(xxe_payload)
        serialized = adapter.serialize(tree)
        assert b"root:" not in serialized
    except FormatParseError:
        pass


def test_yaml_safe_load_blocks_python_tags_and_preserves_order() -> None:
    malicious_yaml = b"exploit: !!python/object/apply:os.system ['echo pwned']\n"
    adapter = get_adapter("yaml")
    with pytest.raises(FormatParseError):
        adapter.parse(malicious_yaml)

    clean_yaml = b"z_first: 1\na_second: secret\n"
    engine = MaskingEngine(
        {"format": "yaml", "rules": [{"selector": "$.a_second", "technique": "redact"}]}
    )
    res = engine.mask(clean_yaml, format="yaml")
    loaded = yaml.safe_load(res.output_bytes)
    assert list(loaded.keys()) == ["z_first", "a_second"]
    assert loaded["a_second"] == "[REDACTED]"


def test_csv_header_isolation_and_column_suppression(sample_csv: bytes) -> None:
    # Wildcard $..* must only touch cell values, NEVER corrupting CSV column headers!
    wildcard_engine = MaskingEngine(
        {
            "format": "csv",
            "rules": [{"selector": "$[*].*", "technique": "redact", "replacement": "X"}],
        }
    )
    res_wild = wildcard_engine.mask(sample_csv, format="csv")
    reader = csv.DictReader(io.StringIO(res_wild.output_text))
    assert reader.fieldnames == ["id", "name", "dob", "ssn", "email", "salary", "diagnosis"]
    rows = list(reader)
    assert all(val == "X" for row in rows for val in row.values())

    # Suppressing a column drops its header cleanly and uses \n line endings (no \r\r\n)
    col_engine = MaskingEngine(
        {
            "format": "csv",
            "rules": [{"selector": "$[*].ssn", "technique": "suppress"}],
        }
    )
    res_col = col_engine.mask(sample_csv, format="csv")
    assert b"\r\r\n" not in res_col.output_bytes
    col_reader = csv.DictReader(io.StringIO(res_col.output_text))
    assert "ssn" not in (col_reader.fieldnames or [])
    col_rows = list(col_reader)
    assert len(col_rows) == 2
    assert col_rows[0]["name"] == "Alice Smith"


def test_format_detection_and_error_cases() -> None:
    assert detect_format_from_filename("records.json") == "json"
    assert detect_format_from_filename("records.xml") == "xml"
    assert detect_format_from_filename("records.yaml") == "yaml"
    assert detect_format_from_filename("records.yml") == "yaml"
    assert detect_format_from_filename("records.csv") == "csv"

    with pytest.raises(UnsupportedFormatError):
        detect_format_from_filename("records.parquet")

    assert detect_format_from_content(b'  {"a": 1}') == "json"
    assert detect_format_from_content(b"  [1, 2]") == "json"
    assert detect_format_from_content(b"<?xml version='1.0'?><a/>") == "xml"
    assert detect_format_from_content(b"a,b,c\n1,2,3\n") == "csv"
    assert detect_format_from_content(b"key: value\n") == "yaml"
    assert detect_format_from_content(b"") == "json"

    with pytest.raises(FormatParseError):
        get_adapter("json").parse(b"{broken json")

    with pytest.raises(SelectorEvaluationError):
        get_adapter("json").select({"a": 1}, "   ")

    with pytest.raises(SelectorEvaluationError):
        get_adapter("xml").select(get_adapter("xml").parse(b"<r/>"), "   ")
