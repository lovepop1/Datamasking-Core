"""Shared hermetic fixtures and registry isolation helpers for ``datamasking-core`` tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import datamasking.adapters.registry as adapter_reg
import datamasking.hierarchies.base as hierarchy_reg
import datamasking.plugins as plugins_mod
import datamasking.techniques.base as tech_reg

SAMPLE_JSON_DOC = b"""{
  "export_batch": "B-100",
  "patients": [
    {
      "id": "P001",
      "name": "Alice Smith",
      "dob": "1985-07-23",
      "ssn": "111-22-3333",
      "email": "alice@biocorp.com",
      "salary": 95000,
      "diagnosis": "I10",
      "address": {
        "street": "123 Main St",
        "city": "Springfield",
        "zip": "10001"
      }
    },
    {
      "id": "P002",
      "name": "Bob Jones",
      "dob": "1982-03-14",
      "ssn": "444-55-6666",
      "email": "bob@biocorp.com",
      "salary": 120000,
      "diagnosis": "J45.909",
      "address": {
        "street": "456 Oak Ave",
        "city": "Chicago",
        "zip": "10009"
      }
    }
  ]
}"""

SAMPLE_XML_DOC = b"""<?xml version="1.0" encoding="UTF-8"?>
<patients batch="B-100">
  <patient id="P001">
    <name>Alice Smith</name>
    <dob>1985-07-23</dob>
    <ssn>111-22-3333</ssn>
    <email>alice@biocorp.com</email>
    <salary>95000</salary>
    <diagnosis>I10</diagnosis>
    <address>
      <street>123 Main St</street>
      <city>Springfield</city>
      <zip>10001</zip>
    </address>
  </patient>
</patients>"""

SAMPLE_YAML_DOC = b"""export_batch: B-100
patients:
  - id: P001
    name: Alice Smith
    dob: "1985-07-23"
    ssn: "111-22-3333"
    email: alice@biocorp.com
    salary: 95000
    diagnosis: I10
"""

SAMPLE_CSV_DOC = b"""id,name,dob,ssn,email,salary,diagnosis
P001,Alice Smith,1985-07-23,111-22-3333,alice@biocorp.com,95000,I10
P002,Bob Jones,1982-03-14,444-55-6666,bob@biocorp.com,120000,J45.909
"""


@pytest.fixture(autouse=True)
def isolate_registries() -> Iterator[None]:
    """Snapshot and restore global plugin registries around each test."""
    orig_techs = dict(tech_reg._REGISTRY)
    orig_adapters = dict(adapter_reg._REGISTRY)
    orig_exts = dict(adapter_reg._EXTENSION_MAP)
    orig_hierarchies = dict(hierarchy_reg._HIERARCHY_REGISTRY)
    orig_ep_loaded = plugins_mod._ENTRYPOINTS_LOADED
    try:
        yield
    finally:
        tech_reg._REGISTRY.clear()
        tech_reg._REGISTRY.update(orig_techs)
        adapter_reg._REGISTRY.clear()
        adapter_reg._REGISTRY.update(orig_adapters)
        adapter_reg._EXTENSION_MAP.clear()
        adapter_reg._EXTENSION_MAP.update(orig_exts)
        hierarchy_reg._HIERARCHY_REGISTRY.clear()
        hierarchy_reg._HIERARCHY_REGISTRY.update(orig_hierarchies)
        plugins_mod._ENTRYPOINTS_LOADED = orig_ep_loaded


@pytest.fixture
def sample_json() -> bytes:
    return SAMPLE_JSON_DOC


@pytest.fixture
def sample_xml() -> bytes:
    return SAMPLE_XML_DOC


@pytest.fixture
def sample_yaml() -> bytes:
    return SAMPLE_YAML_DOC


@pytest.fixture
def sample_csv() -> bytes:
    return SAMPLE_CSV_DOC
