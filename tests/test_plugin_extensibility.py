"""Tests for custom techniques, hierarchies, format adapters, file plugins, and entry_points."""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field

import datamasking.plugins as plugins_mod
from datamasking import (
    BaseTechnique,
    FormatAdapter,
    Hierarchy,
    MaskingContext,
    MaskingEngine,
    PluginLoadError,
    PolicyValidationError,
    discover_entrypoint_plugins,
    load_plugin,
    register_adapter,
    register_hierarchy,
    register_technique,
)
from datamasking.adapters.json_adapter import JSONAdapter


def test_custom_technique_with_plain_pydantic_basemodel_still_rejects_unknown_params() -> None:
    class UpperParams(BaseModel):
        suffix: str = Field(default="!")

    @register_technique("shout_mask")
    class ShoutTechnique(BaseTechnique):
        params_model = UpperParams

        def apply(
            self,
            adapter: FormatAdapter,
            node: Any,
            params: UpperParams,
            context: MaskingContext,
        ) -> None:
            val = adapter.get_value(node)
            if val is not None:
                adapter.set_value(node, f"{str(val).upper()}{params.suffix}")

    engine = MaskingEngine(
        {"rules": [{"selector": "$.msg", "technique": "shout_mask", "suffix": "?"}]}
    )
    assert engine.mask_data({"msg": "hello"}) == {"msg": "HELLO?"}

    # Even though UpperParams inherited plain BaseModel instead of TechniqueParams, typos fail fast!
    with pytest.raises(PolicyValidationError, match="sufix"):
        MaskingEngine({"rules": [{"selector": "$.msg", "technique": "shout_mask", "sufix": "?"}]})


def test_custom_hierarchy_decorator_in_generalize_and_kanon() -> None:
    @register_hierarchy("icd10_custom")
    class ICD10Custom(Hierarchy):
        @property
        def name(self) -> str:
            return "icd10_custom"

        @property
        def max_level(self) -> int:
            return 2

        def generalize(self, value: str, level: int) -> str:
            if level == 0:
                return value
            if level == 1:
                return value.split(".")[0]
            return "*"

    engine = MaskingEngine(
        {
            "record_root": "$.records[*]",
            "k_anonymity": {
                "k": 2,
                "strategy": "enforce",
                "quasi_identifiers": [{"selector": "$.code", "hierarchy": "icd10_custom"}],
            },
        }
    )
    out = engine.mask_data({"records": [{"code": "J45.901"}, {"code": "J45.100"}]})
    assert out == {"records": [{"code": "J45"}, {"code": "J45"}]}


def test_custom_adapter_decorator_with_extension(tmp_path: Path) -> None:
    @register_adapter("customjson", extensions=[".cjson"])
    class CustomJSONAdapter(JSONAdapter):
        @property
        def format_name(self) -> str:
            return "customjson"

    sample_file = tmp_path / "payload.cjson"
    sample_file.write_text('{"secret": "abc", "public": 1}', encoding="utf-8")

    engine = MaskingEngine({"rules": [{"selector": "$.secret", "technique": "redact"}]})
    res = engine.mask_file(sample_file)
    assert res.format_name == "customjson"
    assert '"[REDACTED]"' in res.output_text


def test_load_plugin_from_file_and_error_handling(tmp_path: Path) -> None:
    plugin_file = tmp_path / "reverse_plugin.py"
    plugin_file.write_text(
        "from datamasking import BaseTechnique, register_technique\n"
        "@register_technique('reverse_text')\n"
        "class ReverseTech(BaseTechnique):\n"
        "    def apply(self, adapter, node, params, context):\n"
        "        v = adapter.get_value(node)\n"
        "        if v is not None:\n"
        "            adapter.set_value(node, str(v)[::-1])\n",
        encoding="utf-8",
    )
    load_plugin(str(plugin_file))
    engine = MaskingEngine({"rules": [{"selector": "$.token", "technique": "reverse_text"}]})
    assert engine.mask_data({"token": "ABCD"}) == {"token": "DCBA"}

    with pytest.raises(PluginLoadError, match="not found"):
        load_plugin(str(tmp_path / "missing_plugin.py"))

    with pytest.raises(PluginLoadError, match="Failed to import"):
        load_plugin("nonexistent_module_xyz_12345")


def test_discover_entrypoint_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyTech(BaseTechnique):
        def apply(
            self, adapter: FormatAdapter, node: Any, params: Any, context: MaskingContext
        ) -> None:
            adapter.set_value(node, "EP_MASKED")

    class DummyHierarchy(Hierarchy):
        @property
        def name(self) -> str:
            return "ep_hier"

        @property
        def max_level(self) -> int:
            return 1

        def generalize(self, value: str, level: int) -> str:
            return "*" if level >= 1 else value

    class FakeEP:
        def __init__(self, name: str, target: Any) -> None:
            self.name = name
            self._target = target

        def load(self) -> Any:
            return self._target

    class FakeEPs:
        def select(self, *, group: str) -> list[FakeEP]:
            if group == "datamasking.techniques":
                return [FakeEP("ep_tech", DummyTech)]
            if group == "datamasking.adapters":
                return [FakeEP("ep_json", JSONAdapter)]
            if group == "datamasking.hierarchies":
                return [FakeEP("ep_hier", DummyHierarchy)]
            return []

    monkeypatch.setattr(importlib.metadata, "entry_points", lambda: FakeEPs())
    plugins_mod._ENTRYPOINTS_LOADED = False

    loaded = discover_entrypoint_plugins(force=True)
    assert loaded == [
        "datamasking.adapters:ep_json",
        "datamasking.hierarchies:ep_hier",
        "datamasking.techniques:ep_tech",
    ]

    # Importing a real Python module by dotted path also succeeds
    assert load_plugin("json") == "json"

    engine = MaskingEngine(
        {
            "format": "ep_json",
            "rules": [
                {"selector": "$.x", "technique": "ep_tech"},
                {"selector": "$.y", "technique": "generalize", "hierarchy": "ep_hier", "level": 1},
            ],
        }
    )
    assert json_loads_out(engine.mask('{"x": "orig", "y": "val"}').output_text) == {
        "x": "EP_MASKED",
        "y": "*",
    }


def json_loads_out(text: str) -> Any:
    import json

    return json.loads(text)
