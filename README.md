# datamasking-core

[![CI](https://github.com/lovepop1/Datamasking-Core/actions/workflows/ci.yml/badge.svg)](https://github.com/lovepop1/Datamasking-Core/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Typed: PEP 561](https://img.shields.io/badge/typing-PEP_561-informational.svg)](src/datamasking/py.typed)

`datamasking-core` is a standalone, policy-driven Python library and CLI for deterministic and statistical de-identification of structured data (`JSON`, `XML`, `YAML`, and `CSV`) entirely in memory.

It separates **what** is masked (a declarative `MaskingPolicy` in YAML or Python) from **how** documents are parsed, indexed, conflict-resolved, and transformed in RAM.

---

## Design Principles

1. **The Policy Is the Single Source of Truth**
   `datamasking-core` never applies a hidden default policy, never invents fallback redactions, and contains no hardcoded role names.
   - Fields not matched by an active rule remain untouched by default (`unmatched_fields: "preserve"`).
   - Incompatible values raise an explicit `TechniqueExecutionError` by default (`on_error: "raise"`) unless your policy explicitly configures `"preserve"`, `"redact"`, or `"nullify"`.
2. **Fail-Fast Load-Time Validation**
   Unknown policy keys, unregistered techniques, misspelled technique parameters, unknown generalization hierarchies, and invalid format-specific selectors fail immediately with `PolicyValidationError` when the policy is loaded — before any payload is processed.
3. **Zero-Disk In-Memory Execution**
   Payloads are parsed into a mutable AST in memory, transformed in place across a deterministic multi-phase pipeline, and serialized back to UTF-8 bytes without writing temporary files.
4. **Open Registry Architecture**
   Custom techniques (`@register_technique`), format adapters (`@register_adapter`), and generalization hierarchies (`@register_hierarchy`) register cleanly from Python code, CLI `--plugin` files, or third-party packages via `entry_points` — without modifying core pipeline code.

---

## Installation

Requires Python 3.10+.

```bash
# Install directly from GitHub
pip install "git+https://github.com/lovepop1/Datamasking-Core.git"

# Or from a local source checkout
pip install .

# Editable install with development tools (pytest, hypothesis, ruff, mypy)
pip install -e ".[dev]"
```

Runtime dependencies are minimal: `pydantic`, `pyyaml`, `lxml`, and `jsonpath-ng`.

---

## Quickstart

### 1. Author a Policy (`policy.yaml`)

```yaml
# yaml-language-server: $schema=./schema/policy.schema.json
version: "1.0"
name: "patient-intake-export"
format: "json"
unmatched_fields: "preserve"
on_error: "raise"
record_root: "$.patients[*]"

rules:
  - id: "remove-ssn"
    selector: "$.patients[*].ssn"
    technique: "suppress"

  - id: "tokenize-mrn"
    selector: "$.patients[*].patient_id"
    technique: "pseudonymize"
    params:
      prefix: "PT_"
      token_length: 12

  - id: "redact-name"
    selector: "$.patients[*].name"
    technique: "redact"
    params:
      replacement: "[REDACTED]"

  - id: "generalize-dob"
    selector: "$.patients[*].dob"
    technique: "generalize"
    params:
      hierarchy: "date"
      level: 2

k_anonymity:
  k: 2
  strategy: "enforce"
  quasi_identifiers:
    - selector: "$.zipcode"
      hierarchy: "zipcode"
    - selector: "$.age"
      hierarchy: "age"
```

### 2. Python SDK

```python
from datamasking import MaskingEngine

engine = MaskingEngine.from_file("policy.yaml", salt="your-256-bit-secret-key")

payload = {
    "study_id": "CARDIO-04",
    "patients": [
        {
            "patient_id": "MRN-101",
            "name": "Alice Carter",
            "ssn": "123-45-6789",
            "dob": "1984-06-19",
            "zipcode": "94107",
            "age": 41,
            "diagnosis": "I10",
        },
        {
            "patient_id": "MRN-102",
            "name": "Brian Brooks",
            "ssn": "987-65-4321",
            "dob": "1981-11-03",
            "zipcode": "94109",
            "age": 44,
            "diagnosis": "J45.909",
        },
    ],
}

result = engine.mask(payload)
print(result.output_text)
assert result.k_achieved is True
```

Output (`study_id` and `diagnosis` are untouched because the policy did not target them):

```json
{
  "study_id": "CARDIO-04",
  "patients": [
    {
      "patient_id": "PT_6e4a8052ab9d",
      "name": "[REDACTED]",
      "dob": "1984",
      "zipcode": "9410*",
      "age": "40-44",
      "diagnosis": "I10"
    },
    {
      "patient_id": "PT_9f70f0d157ec",
      "name": "[REDACTED]",
      "dob": "1981",
      "zipcode": "9410*",
      "age": "40-44",
      "diagnosis": "J45.909"
    }
  ]
}
```

### 3. Command-Line Interface

```bash
# Validate a policy strictly before deployment
datamasking validate -p examples/quickstart/policy.yaml

# Preview which rules would apply without masking values (--dry-run)
datamasking mask -i examples/quickstart/patients.json -p examples/quickstart/policy.yaml --dry-run

# Mask a file (or pass '-i - -f json' to stream from stdin to stdout)
datamasking mask \
  -i examples/quickstart/patients.json \
  -p examples/quickstart/policy.yaml \
  -s "$DATAMASKING_SALT" \
  -o masked_patients.json \
  --report audit_report.json

# Export Draft 2020-12 JSON Schema for IDE YAML validation
datamasking schema -o schema/policy.schema.json
```

---

## Built-in Capabilities

| Category | Built-in Implementations |
| :--- | :--- |
| **Formats** | `json` (extended JSONPath + filter predicates), `xml` (XXE-hardened XPath for elements & `@attributes`), `yaml` (`safe_load`), `csv` (header-isolated row AST) |
| **Techniques** | `redact`, `suppress`, `nullify`, `pseudonymize` (HMAC-SHA256), `generalize`, `format_preserve`, `noise`, `mask_pattern`, `synthesize`, `deep_redact` |
| **Hierarchies** | `date` (day -> month -> year -> decade -> `*`), `zipcode` / `zip` (`10001` -> `1000*` -> ... -> `*****`), `age` (exact -> 5-yr -> 10-yr -> 20-yr -> `*`), `icd10` (`J45.909` -> `J45` -> `J**` -> `***`) |
| **Privacy Controls** | Subtree `scopes` & reusable `profiles`, user-defined `roles`, deterministic conflict resolution, record-level `k-anonymity` (`verify`, `enforce`, `suppress`) |

---

## Adding a Custom Technique

```python
from typing import Any
from pydantic import Field
from datamasking import (
    BaseTechnique,
    FormatAdapter,
    MaskingContext,
    TechniqueParams,
    register_technique,
)


class DomainRedactParams(TechniqueParams):
    keep_tld: bool = Field(default=True)


@register_technique("redact_email_user")
class RedactEmailUserTechnique(BaseTechnique):
    params_model = DomainRedactParams

    def apply(
        self,
        adapter: FormatAdapter,
        node: Any,
        params: DomainRedactParams,
        context: MaskingContext,
    ) -> None:
        raw = adapter.get_value(node)
        if raw is None:
            return
        text = str(raw)
        if "@" not in text:
            context.handle_value_error(
                adapter, node, technique=self.name, reason="Value is not an email address."
            )
            return
        _, domain = text.rsplit("@", 1)
        tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
        adapter.set_value(node, f"***@***.{tld}" if params.keep_tld else "***@***")
```

Save to a `.py` file and pass `--plugin ./my_plugin.py` on the CLI, import it in Python, or publish an independent plugin package via `[project.entry-points."datamasking.techniques"]`.

---

## Documentation

- [**Policy Specification & Execution Semantics**](docs/policy-reference.md) — Complete field-by-field reference for `policy.yaml`, how phases 0–4 transform a document, conflict resolution scoring, scopes, roles, and `k`-anonymity.
- [**Built-in Techniques & Hierarchies**](docs/techniques.md) — Exact parameter schemas, types, defaults, null handling, error behavior, and examples for all 10 techniques and 4 hierarchies.
- [**Selectors & Format Adapters**](docs/selectors-and-formats.md) — JSONPath, XPath, YAML, and CSV addressing rules, filter predicates, XML attributes/namespaces, and edge cases.
- [**Extending `datamasking-core`**](docs/extending.md) — Authoring custom techniques, format adapters, hierarchies, and installable `entry_points` plugins.
- [**Architecture & Memory Model**](docs/architecture.md) — Multi-phase AST compiler design, complexity, concurrency, and gateway integration boundaries.
- [**Security & Privacy Model**](docs/security-model.md) — Threat boundaries, HMAC key management, `k`-anonymity caveats, parser hardening, and Python memory lifecycle notes.

---

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
