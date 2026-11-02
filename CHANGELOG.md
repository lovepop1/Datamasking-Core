# Changelog

All notable changes to `datamasking-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-03

### Added
- Standalone `datamasking-core` Python library and `datamasking` CLI (`mask`, `validate`, `techniques`, `formats`, `schema`).
- Policy-as-single-source-of-truth execution model:
  - `unmatched_fields` policy control (`preserve` by default; optional `redact`, `nullify`, `suppress`).
  - `on_error` policy and per-rule error control (`raise` by default; optional `preserve`, `redact`, `nullify`).
  - Explicit `mode="dry_run"` (`--dry-run`) non-destructive preview mode.
  - User-defined `roles` (including explicit `passthrough: true`), `profiles`, `scopes`, and explicit rule `priority`.
- Four AST format adapters: JSON (extended JSONPath with filter predicates), XML (XXE-hardened `lxml` with element and `@attribute` XPath support), YAML (`yaml.safe_load`), and header-isolated CSV.
- Ten built-in masking techniques (`redact`, `suppress`, `nullify`, `pseudonymize`, `generalize`, `format_preserve`, `noise`, `mask_pattern`, `synthesize`, `deep_redact`) with strict `extra="forbid"` Pydantic parameter schemas.
- Built-in generalization hierarchies (`date`, `zipcode`/`zip`, `age`, `icd10`) and record-level `k-anonymity` (`verify`, iterative full-domain `enforce`, and outlier `suppress`).
- First-class plugin extensibility via `@register_technique`, `@register_adapter`, `@register_hierarchy`, `importlib.metadata.entry_points`, and CLI `--plugin`.
- Draft 2020-12 Policy JSON Schema (`schema/policy.schema.json`) and PEP 561 `py.typed` marker.

