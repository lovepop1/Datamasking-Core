# Extending `datamasking-core`

`datamasking-core` is built around three open registries:

1. **Techniques** (`BaseTechnique` + `@register_technique`)
2. **Generalization Hierarchies** (`Hierarchy` + `@register_hierarchy`)
3. **Format Adapters** (`FormatAdapter` + `@register_adapter`)

You never need to fork or edit `src/datamasking/pipeline/` to add new capabilities. Extensions can be registered in-process in Python, loaded dynamically on the CLI with `--plugin`, or distributed as independent pip packages via `entry_points`.

---

## 1. Custom Masking Technique

Subclass `BaseTechnique`, define a `TechniqueParams` subclass (`extra="forbid"`, `frozen=True` inherited automatically), and decorate with `@register_technique("...")`:

```python
from datetime import date, timedelta
from typing import Any
from pydantic import Field

from datamasking import (
    BaseTechnique,
    FormatAdapter,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class DateShiftParams(TechniqueParams):
    days: int = Field(..., description="Signed day offset applied to ISO-8601 dates.")
    preserve_null: bool = Field(default=True)


@register_technique("date_shift")
class DateShiftTechnique(BaseTechnique):
    name = "date_shift"
    params_model = DateShiftParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: DateShiftParams,
        context: MaskingContext,
    ) -> None:
        raw = adapter.get_value(node)
        if raw is None and params.preserve_null:
            return
        try:
            parsed = date.fromisoformat(str(raw).strip())
        except ValueError as exc:
            # Delegate domain mismatches to policy/rule on_error ('raise' | 'preserve' | 'redact' | 'nullify')
            context.handle_value_error(
                adapter,
                node,
                technique=self.name,
                reason=f"Invalid ISO date {raw!r}: {exc}",
            )
            return

        adapter.set_value(node, (parsed + timedelta(days=params.days)).isoformat())
```

### Best Practices for Technique Authors

- **Inherit from `TechniqueParams`**: Ensures misspelled rule parameters in `policy.yaml` are rejected at load time.
- **Use `context.rng` instead of global `random`**: Ensures `--seed` / `seed=` produces deterministic output without mutating global Python RNG state.
- **Use `context.salt` for keyed hashing**: Never hardcode static salts inside a technique.
- **Call `context.handle_value_error(...)` on bad inputs**: Never silently overwrite values with `"[REDACTED]"`; let the user's `on_error` policy setting decide.
- **Optional `auditor_label(self, params)` override**: `BaseTechnique` automatically generates `[WOULD APPLY: <name> | ...]` labels for `--dry-run`, which you can customize if desired.

---

## 2. Custom Generalization Hierarchy

Custom hierarchies work immediately in both `technique: "generalize"` rules and `k_anonymity` (`strategy: "enforce"`):

```python
from datamasking import Hierarchy, register_hierarchy


@register_hierarchy("icd10")
class ICD10Hierarchy(Hierarchy):
    """Coarsen ICD-10 diagnosis codes (e.g. 'J45.909' -> 'J45.9' -> 'J45' -> 'J' -> '*')."""

    @property
    def name(self) -> str:
        return "icd10"

    @property
    def max_level(self) -> int:
        return 4

    def generalize(self, value: str, level: int) -> str:
        if level < 0:
            raise ValueError("level must be >= 0")
        code = value.strip().upper()
        if not code or not code[0].isalpha():
            raise ValueError(f"Invalid ICD-10 code: {value!r}")

        if level == 0:
            return code
        if level == 1:
            return code[:5] if "." in code and len(code) >= 5 else code.split(".")[0]
        if level == 2:
            return code.split(".")[0]
        if level == 3:
            return code[0]
        return "*"
```

---

## 3. Custom Format Adapter

To mask an additional wire or file format (for example TOML, NDJSON, or FHIR Bundles), subclass `FormatAdapter` and register it along with its file extensions:

```python
from datamasking import FormatAdapter, register_adapter


@register_adapter("toml", extensions=[".toml"])
class TOMLAdapter(FormatAdapter):
    @property
    def format_name(self) -> str:
        return "toml"

    # Implement parse, serialize, select, get_identity, get_value,
    # set_value, remove_node, is_attached, get_path, is_leaf_node,
    # iter_nodes, and iter_subtree.
    ...
```

*(Tip: If your format deserializes into Python `dict`/`list` primitives, you can reuse `wrap_tree` and `unwrap_tree` from `datamasking.adapters.node_wrapper` — see `YAMLAdapter` in `src/datamasking/adapters/yaml_adapter.py` as a 45-line reference implementation.)*

---

## 4. Loading Plugins in CLI and Packaging via `entry_points`

### Option A: CLI `--plugin` Flag
Pass either a `.py` file path or an importable module path before policy validation runs:

```bash
datamasking validate -p policy.yaml --plugin ./examples/custom_plugin/date_shift.py
datamasking mask -i input.json -p policy.yaml --plugin ./examples/custom_plugin/date_shift.py
```

### Option B: Python `load_plugin`
```python
from datamasking import load_plugin

load_plugin("./examples/custom_plugin/date_shift.py")
```

### Option C: Zero-Config Python Package (`entry_points`)
Third-party packages can register plugins automatically upon installation by declaring entry points in their `pyproject.toml`:

```toml
[project.entry-points."datamasking.techniques"]
date_shift = "my_privacy_plugins.date_shift:DateShiftTechnique"

[project.entry-points."datamasking.hierarchies"]
icd10 = "my_privacy_plugins.icd10:ICD10Hierarchy"

[project.entry-points."datamasking.adapters"]
toml = "my_privacy_plugins.toml_adapter:TOMLAdapter"
```

`datamasking-core` discovers all three entry-point groups automatically via `importlib.metadata.entry_points` before validating policies.

