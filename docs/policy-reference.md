# Policy Specification & Execution Semantics

The masking policy (`MaskingPolicy`) is the **single source of truth** in `datamasking-core`. Nothing in the engine masks, drops, redacts, or bypasses a field unless your policy explicitly declares it.

This document specifies every field in a policy file and explains step-by-step how `datamasking-core` evaluates a policy against an input document.

---

## 1. IDE Validation & Autocomplete

A Draft 2020-12 JSON Schema is shipped at [`schema/policy.schema.json`](../schema/policy.schema.json) (and can be regenerated anytime via `datamasking schema -o schema/policy.schema.json`).

Add this header line to the top of any YAML policy file to get live validation and autocomplete in VS Code (YAML extension), JetBrains IDEs, and Neovim (`yamlls`):

```yaml
# yaml-language-server: $schema=./schema/policy.schema.json
```

All structural objects in the policy enforce `extra="forbid"`: any misspelled key (for example `ruels:` instead of `rules:` or `unmatched_feilds:`) raises `PolicyValidationError` immediately when loading the policy.

---

## 2. Top-Level Policy Schema

```yaml
version: "1.0"                    # Optional ("1.0" default; "3.0" also accepted)
name: "clinical-export-policy"    # Optional identifier for documentation/auditing
description: "HIPAA export rules" # Optional human-readable description
format: "json"                    # Optional: "json" | "xml" | "yaml" | "csv"
unmatched_fields: "preserve"      # Optional: "preserve" | "redact" | "nullify" | "suppress"
unmatched_replacement: "[REDACTED]" # Used only when unmatched_fields == "redact"
on_error: "raise"                 # Optional: "raise" | "preserve" | "redact" | "nullify"
record_root: "$.patients[*]"      # Selector(s) for k-anonymity subject records

rules: [...]                      # Global element/subtree masking rules
roles: {...}                      # Optional user-defined caller roles
profiles: {...}                   # Optional reusable rule bundles for scopes
scopes: [...]                     # Optional path-bounded subtree governance rules
k_anonymity: {...}                # Optional equivalence-class verification/enforcement
```

### Top-Level Fields

| Field | Type | Default | Behavior |
| :--- | :--- | :--- | :--- |
| `version` | `str` | `"1.0"` | Policy schema version (`"1.0"` or `"3.0"`). |
| `name` | `str \| null` | `null` | Optional policy name. |
| `description` | `str \| null` | `null` | Optional description of the policy's purpose. |
| `format` | `str \| null` | `null` | Target format (`"json"`, `"xml"`, `"yaml"`, `"csv"`). When set, **every selector in the policy is syntax-checked at load time** against that format's adapter. Leave `null` only for multi-format policies mixing JSONPath and XPath rules. |
| `unmatched_fields` | `"preserve" \| "redact" \| "nullify" \| "suppress"` | `"preserve"` | Controls what happens to scalar leaf nodes **not** matched by any active rule or scope. `"preserve"` leaves them completely untouched. `"redact"` replaces them with `unmatched_replacement`. `"nullify"` sets them to `null`/empty. `"suppress"` removes them from the document. |
| `unmatched_replacement` | `str` | `"[REDACTED]"` | Replacement string applied only when `unmatched_fields: "redact"`. |
| `on_error` | `"raise" \| "preserve" \| "redact" \| "nullify"` | `"raise"` | Default error action when a technique receives an incompatible value (e.g. non-numeric text passed to `noise` or an invalid date passed to `generalize`). Can be overridden per rule. |
| `record_root` | `str \| list[str]` | `"$"` | Selector (or list of selectors) identifying individual subject records for `k_anonymity` (e.g., `"$.patients[*]"` in JSON/YAML, `"$[*]"` in CSV, `"//patient"` in XML). |
| `rules` | `list[MaskingRule]` | `[]` | Global rules evaluated across the document. If `rules` and `scopes` are empty and `unmatched_fields: "preserve"`, the payload passes through unchanged. |
| `roles` | `dict[str, RoleDefinition]` | `{}` | Optional caller role definitions. |
| `profiles` | `dict[str, MaskingProfile]` | `{}` | Named rule collections referenced by `scopes`. |
| `scopes` | `list[ScopeRule]` | `[]` | Subtree-level governance rules and per-role overrides. |
| `k_anonymity` | `KAnonConfig \| null` | `null` | Optional record-level `k`-anonymity verification or enforcement. |

---

## 3. Rules (`rules[*]`)

Each entry in `rules` (as well as rules inside `profiles.<name>.rules` and `scopes[*].rules`) is a `MaskingRule`:

```yaml
rules:
  - id: "mask-card"
    description: "Expose only last 4 digits of payment card"
    selector: "$.orders[*].card_number"
    technique: "mask_pattern"
    priority: 10
    roles: ["support", "billing_analyst"]
    on_error: "raise"
    params:
      pattern: "****-****-****-{digits_last4}"
      preserve_null: true
```

### Rule Fields

| Field | Type | Default | Behavior |
| :--- | :--- | :--- | :--- |
| `selector` | `str` | *(required)* | JSONPath (`$`-rooted or relative) or XPath (`/`-rooted or relative) expression selecting target AST nodes. |
| `technique` | `str` | *(required)* | Registered technique name (case-insensitive). Must be registered at load time. |
| `params` | `dict[str, Any]` | `{}` | Parameters validated strictly against the technique's `params_model`. Unknown parameter names raise `PolicyValidationError` at load time. |
| `id` | `str \| null` | `null` | Optional identifier surfaced in `result.conflict_log`. |
| `description` | `str \| null` | `null` | Optional human-readable rationale. |
| `priority` | `int` | `0` | Explicit conflict-resolution priority. Higher integers win before selector specificity is considered (can also be negative for low-priority catch-all rules). |
| `roles` | `list[str] \| null` | `null` | When omitted (`null`), the rule applies regardless of caller `role`. When set to a list of role names, the rule is evaluated **only** when `engine.mask(..., role=...)` matches an entry in `roles`. |
| `on_error` | `"raise" \| "preserve" \| "redact" \| "nullify" \| null` | `null` | Per-rule override for `policy.on_error`. |

### Nested `params` vs. Inline Shorthand

For concise YAML authoring, technique parameters may be written either inside `params:` or inline on the rule object:

```yaml
# Canonical form (recommended for clarity)
- selector: "$..email"
  technique: "redact"
  params:
    replacement: "[EMAIL HIDDEN]"

# Equivalent inline shorthand
- selector: "$..email"
  technique: "redact"
  replacement: "[EMAIL HIDDEN]"
```

Both forms undergo identical strict schema validation against `RedactParams`. Passing an unrecognized key in either position raises `PolicyValidationError`.

---

## 4. Roles, Profiles, and Scopes

### Caller Roles (`roles`)

`datamasking-core` has **no built-in or magic role names**. Every role name is chosen by you in the policy. If you do not need role-based differentiation, omit `roles` and `role=` entirely.

```yaml
roles:
  privacy_officer:
    description: "Authorized to export unmasked raw records"
    passthrough: true
  external_researcher:
    description: "Default fallback for unlisted scopes is deep redaction"
    default_scope_strategy: "deep_redact"
```

- `passthrough: true` (default `false`): Explicitly instructs the engine to skip all masking and `k`-anonymity processing when `role="privacy_officer"`.
- `default_scope_strategy`: Fallback strategy (`"masked"`, `"passthrough"`, `"drop_subtree"`, `"deep_redact"`, `"synthesize"`) used when a `ScopeRule` does not list this role or `"default"`.

### Profiles (`profiles`) and Scopes (`scopes`)

A **Scope** binds a subtree path (`path`) to a subtree strategy, optionally varying by caller `role`:

```yaml
profiles:
  clinical_strict:
    description: "Mask free-text clinical notes and attending physician"
    rules:
      - selector: "$..physician"
        technique: "pseudonymize"
      - selector: "$..free_text"
        technique: "redact"

scopes:
  - path: "$.patients[*].psychiatry_notes"
    apply_profile: "clinical_strict"
    roles:
      psychiatrist:
        strategy: "passthrough"
      clinical_researcher:
        strategy: "masked"
        profile: "clinical_strict"
      billing_clerk:
        strategy: "drop_subtree"
      qa_engineer:
        strategy: "synthesize"
        params:
          deterministic: true
      default:
        strategy: "deep_redact"
        params:
          replacement: "[RESTRICTED]"
```

### Subtree Strategies

| Strategy | Effect on Matched Subtree |
| :--- | :--- |
| `"masked"` | Evaluates rules from the resolved `profile` (`role.profile` or `scope.apply_profile`), inline `scope.rules`, and global `policy.rules` on nodes inside this subtree. |
| `"passthrough"` | Exempts all nodes inside this subtree from both scope rules and global `policy.rules` (values remain unmasked). *(Legacy alias `"default_allow"` is normalized to `"passthrough"`.)* |
| `"drop_subtree"` | Detaches and deletes the entire subtree node from its parent object/array/XML element. |
| `"deep_redact"` | Replaces every scalar leaf inside the subtree with `replacement` (default `"[REDACTED]"`). |
| `"synthesize"` | Replaces every scalar leaf inside the subtree with keyed synthetic values based on leaf field names. |

### Scope Resolution Rules

1. **Role Lookup Order**: Within each scope, the engine checks:
   1. `scope.roles[role]` (exact caller role match),
   2. `scope.roles["default"]` (explicit scope fallback),
   3. `policy.roles[role].default_scope_strategy` (if set on the role definition),
   4. `"masked"` if the scope declares `apply_profile` or inline `rules`,
   5. Otherwise, the scope does **not** apply to this caller and normal global `policy.rules` govern the subtree.
2. **Nested Scopes**: If a document has nested scopes (e.g., an outer scope at `$.department` and a narrower scope at `$.department.oncology`), membership is assigned by subtree containment size: the narrower inner scope always governs its own nodes over the broader outer scope.

---

## 5. How Masking Executes (The 5-Stage Pipeline)

Every call to `engine.mask(...)` runs an isolated, deterministic in-memory pipeline:

```text
Raw Bytes -> [Parse AST] -> [Phase 0: Scopes] -> [Phase 1: Index]
          -> [Phase 2: Conflict Resolution] -> [Phase 3: Apply]
          -> [Phase 4: k-Anonymity] -> [Serialize UTF-8 Bytes]
```

### Stage 1: Format Parsing
The format adapter (`json`, `xml`, `yaml`, or `csv`) parses the input bytes into a mutable in-memory AST where every node tracks its parent container, key/index, and canonical path. No rules have run yet.

### Stage 2: Phase 0 — Scope Evaluation
- Checks whether `policy.roles[role].passthrough` is `true` (if so, short-circuits cleanly with zero mutations).
- Evaluates each `scope.path` selector against the AST and assigns every node inside a matched scope its active `ScopeDecision`.

### Stage 3: Phase 1 — Scope-Aware Selector Indexing
- Evaluates active global `policy.rules` (skipping any rule whose `rule.roles` excludes the current `role`) and scope-expanded rules (restricted strictly to nodes inside that scope's subtree).
- Builds `rule_index: dict[node_id, list[MaskingRule]]` without mutating the AST, so filter predicates (such as `$.patients[?(@.age < 18)].name`) always inspect original unmasked values rather than partially mutated values.
- Catalogs scalar leaf nodes not covered by any rule or bulk/passthrough scope into `unmatched_index`.

### Stage 4: Phase 2 — Deterministic Conflict Resolution
Whenever two or more rules match the same AST node, `datamasking-core` picks a single winner and records the contest in `result.conflict_log`. Candidates are ranked by the tuple `(priority, specificity_score, -declaration_order)`:

1. **Explicit `priority` (highest wins)**: A rule with `priority: 10` always beats a rule with `priority: 0`.
2. **Selector Specificity Score (highest wins)**:
   - `+3` if anchored at root (`$` or `/`).
   - `+10` for each explicit named path segment (e.g. `patients`, `contact`, `email`).
   - `+5` for each attribute/filter predicate (e.g. `[@type='home']` or `[?(@.vip == true)]`).
   - `-2` for each recursive descent operator (`..` or `//`).
   - `-1` for each wildcard token (`*` or `**`).
   - `+5` locality bonus if the rule originated from a subtree scope/profile expansion.

   *Example*: `$.patients[*].email` scores `3 + 10 - 1 + 10 = 22`, beating catch-all `$..email` which scores `3 - 2 + 10 = 11`.
3. **Policy Declaration Order (earliest wins)**: If both `priority` and `specificity_score` are tied, the rule declared earlier in `policy.yaml` wins.

### Stage 5: Phase 3 — Technique Application & Error Handling
1. Bulk subtree scope strategies (`drop_subtree`, `deep_redact`, `synthesize`) execute from innermost subtrees outward.
2. Each remaining attached node with a winning rule is passed to its registered `BaseTechnique.apply(adapter, node, params, context)`.
3. If a value is incompatible with the technique's domain (for instance `"N/A"` in a `noise` field), `rule.on_error or policy.on_error` controls what happens:
   - `"raise"` *(default)*: Raises `TechniqueExecutionError` with exact `path`, `technique`, and `reason`.
   - `"preserve"`: Leaves the original value untouched and appends an entry to `result.warnings`.
   - `"redact"`: Replaces the value with `"[REDACTED]"` and appends an entry to `result.warnings`.
   - `"nullify"`: Sets the value to `None` (`null` / empty) and appends an entry to `result.warnings`.
4. Scalar leaves in `unmatched_index` are handled according to `policy.unmatched_fields` (`"preserve"` by default — completely untouched) and listed in `result.unmatched_paths`.

### Dry-Run Preview Mode (`mode="dry_run"` / `--dry-run`)
Passing `mode="dry_run"` in Python or `--dry-run` on the CLI runs Phases 0, 1, and 2 identically, then replaces only the nodes that **would** be modified by your policy with descriptive preview strings such as:
- `[WOULD APPLY: pseudonymize | consistent=True | prefix='PT_' | token_length=12]`
- `[WOULD DROP SUBTREE: $.patients[*].psychiatry_notes]`

Fields left untouched by the policy (`unmatched_fields: "preserve"`) remain untouched in dry-run output so you can visually diff exact policy impact.

---

## 6. Record-Level `k`-Anonymity (`k_anonymity`)

Direct identifiers (`name`, `ssn`, `email`) should be removed or pseudonymized in `rules`. Quasi-identifiers (`zipcode`, `dob`, `age`) can still re-identify individuals when combined if fewer than $k$ records share the same combination of values.

```yaml
record_root: "$.patients[*]"

k_anonymity:
  enabled: true
  k: 3
  strategy: "enforce"        # "verify" | "enforce" | "suppress"
  on_unresolved: "flag"      # "flag" | "suppress"
  quasi_identifiers:
    - selector: "$.zipcode"
      hierarchy: "zipcode"
      max_level: 4
    - selector: "$.dob"
      hierarchy: "date"
      max_level: 3
```

### Strategies

- `"verify"` *(default)*: Groups records selected by `record_root` into equivalence classes over `quasi_identifiers` **without modifying any values or deleting any records**. Sets `result.k_achieved` (`True` if every equivalence class has size $\ge k$, else `False`) and populates `result.kanon_report.violating_classes`.
- `"enforce"`: Iteratively generalizes quasi-identifier attributes across all records (full-domain generalization using Datafly's highest-cardinality heuristic) using each attribute's declared `hierarchy` up to `max_level` until every equivalence class has size $\ge k$.
  - If all hierarchies reach `max_level` and outlier classes with count $< k$ remain:
    - `on_unresolved: "flag"` *(default)* keeps all records intact, sets `result.k_achieved = False`, and reports the remaining violating classes.
    - `on_unresolved: "suppress"` removes the remaining outlier records so the released dataset strictly satisfies $k$-anonymity (`result.kanon_report.suppressed_records` reports how many records were removed).
- `"suppress"`: Directly removes records belonging to equivalence classes smaller than $k$ without generalizing quasi-identifiers.

---

## 7. Complete Format Examples

### XML Policy (Elements + Attributes)

```yaml
version: "1.0"
format: "xml"
record_root: "//patient"

rules:
  - selector: "//patient/@mrn"
    technique: "pseudonymize"
    params:
      prefix: "MRN_"
  - selector: "//patient/ssn"
    technique: "suppress"
  - selector: "//patient/contact/email"
    technique: "mask_pattern"
    params:
      pattern: "{first1}***@{domain}"
```

### CSV Policy

```yaml
version: "1.0"
format: "csv"
record_root: "$[*]"

rules:
  - selector: "$[*].ssn"
    technique: "suppress"      # Drops the 'ssn' column cleanly from CSV output
  - selector: "$[*].salary"
    technique: "noise"
    params:
      percentage: 5.0
```

