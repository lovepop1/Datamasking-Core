# Built-in Techniques & Hierarchies Reference

`datamasking-core` ships with 10 built-in masking techniques and 4 generalization hierarchies. Every technique validates its parameters using a strict Pydantic model (`extra="forbid"`), meaning unknown or misspelled parameter names raise `PolicyValidationError` at policy load time.

---

## Summary Matrix

| Technique | Mutates Structure? | Deterministic Option? | Default Null Behavior | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- |
| [`redact`](#1-redact) | No | Always constant | Replaces null (`preserve_null=False`) | Constant token replacement (`[REDACTED]`) |
| [`suppress`](#2-suppress) | Yes (removes node) | Always deterministic | Removes node | Removing keys, XML elements/attributes, CSV columns |
| [`nullify`](#3-nullify) | No | Always deterministic | Remains `null` | Replacing values with `null` / empty text |
| [`pseudonymize`](#4-pseudonymize) | No | Yes (`consistent=True`, HMAC-SHA256) | Preserves null (`preserve_null=True`) | Referential integrity across joins without exposing IDs |
| [`generalize`](#5-generalize) | No | Always deterministic | Preserves null (`preserve_null=True`) | Coarsening dates, postal codes, ages, or custom taxonomies |
| [`mask_pattern`](#6-mask_pattern) | No | Always deterministic | Preserves null (`preserve_null=True`) | Partial display (last 4 digits, email domain) |
| [`format_preserve`](#7-format_preserve) | No | Yes (`deterministic=True`, HMAC-SHA256) | Preserves null (`preserve_null=True`) | Preserving character classes and punctuation for QA schemas |
| [`noise`](#8-noise) | No | Via `seed` | Preserves null (`preserve_null=True`) | Bounded multiplicative perturbation of numeric fields |
| [`synthesize`](#9-synthesize) | No | Yes (`deterministic=True`, HMAC-SHA256) | Preserves null (`preserve_null=True`) | Realistic synthetic names, emails, phones, dates |
| [`deep_redact`](#10-deep_redact) | No | Always constant | Replaces null (`preserve_null=False`) | Redacting every scalar leaf inside nested containers |

---

## 1. `redact`

Replaces matched scalar values with a fixed string.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `replacement` | `str` | `"[REDACTED]"` | Any string | Replacement value written to matched nodes. |
| `preserve_null` | `bool` | `False` | `bool` | Keep `null`/`None` values as `null` when `True`. |

**Example:** `"Alice Carter"` -> `"[REDACTED]"`

---

## 2. `suppress`

Detaches and removes the matched node from its parent container:
- **JSON / YAML object key**: Deletes the key-value pair from the parent dictionary.
- **JSON / YAML array element**: Removes the element from the list and re-indexes remaining elements.
- **XML element or `@attribute`**: Removes the element from its parent tag or removes the attribute from its element.
- **CSV column (`$[*].ssn`)**: Removes the cell from every row and drops the `ssn` header column on serialization.

Takes **no parameters**.

---

## 3. `nullify`

Sets the matched scalar value to `None`:
- Serializes as `null` in JSON and YAML.
- Serializes as empty element text (`<tag></tag>`) or removes the attribute on XML `@attr` nodes.
- Serializes as an empty cell (`""`) in CSV.

Takes **no parameters**.

---

## 4. `pseudonymize`

Generates cryptographic tokens using `HMAC-SHA256(key=salt, msg=str(value))` when `consistent=True`, or isolated random hex tokens from `context.rng` when `consistent=False`.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `consistent` | `bool` | `True` | `bool` | When `True`, identical inputs under the same `salt` map to identical tokens. |
| `prefix` | `str` | `"ANON_"` | Any string | Prefix prepended to the hex digest slice. |
| `token_length` | `int` | `16` | `4 <= token_length <= 64` | Number of lowercase hex characters appended after `prefix`. |
| `salt` | `str \| null` | `null` | Optional string | Rule-specific HMAC secret overriding the engine/execution `salt`. |
| `preserve_null` | `bool` | `True` | `bool` | Leave `null`/`None` values untouched when `True`. |

**Example (`prefix="PT_"`, `token_length=12`):** `"MRN-9001"` -> `"PT_a8f49d20c3b1"`

> **Note:** At `token_length=16` (64 bits), the 50% birthday collision threshold is approximately $4.3 \times 10^9$ distinct identifiers. Increase `token_length` to `32` (128 bits) for multi-billion-key namespaces.

---

## 5. `generalize`

Reduces value precision using a registered `Hierarchy`.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `hierarchy` | `str` | *(required)* | Registered hierarchy name | Domain taxonomy (`"date"`, `"zipcode"`, `"zip"`, `"age"`, or custom). |
| `level` | `int` | `1` | `level >= 0` | Coarsening step (`0` = normalized original, `>= max_level` = coarsest `*`). |
| `preserve_null` | `bool` | `True` | `bool` | Leave `null`/`None` values untouched when `True`. |

**Domain Errors:** If the input value cannot be parsed by the hierarchy (for example `"not-a-date"` passed to `hierarchy: "date"`), `generalize` delegates to `on_error` (`"raise"` by default).

---

## 6. `mask_pattern`

Formats strings into a template exposing only selected characters or domain segments.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `pattern` | `str` | *(required)* | Non-empty string | Output template containing literal characters and placeholders. |
| `preserve_null` | `bool` | `True` | `bool` | Leave `null`/`None` values untouched when `True`. |

### Supported Placeholders

| Placeholder | Meaning | Input `"alice@biocorp.org"` | Input `"+1-415-555-0199"` |
| :--- | :--- | :--- | :--- |
| `{first1}` | First character | `"a"` | `"+"` |
| `{first2}` | First 2 characters | `"al"` | `"+1"` |
| `{first3}` | First 3 characters | `"ali"` | `"+1-"` |
| `{first4}` | First 4 characters | `"alic"` | `"+1-4"` |
| `{last2}` | Last 2 characters | `"rg"` | `"99"` |
| `{last4}` | Last 4 characters | `".org"` | `"0199"` |
| `{digits_last4}` | Last 4 ASCII digits (`0-9` only) | `""` | `"0199"` |
| `{domain}` | Substring after `@` (or `""` if no `@`) | `"biocorp.org"` | `""` |

**Examples:**
- `pattern: "****-****-****-{digits_last4}"` on `"4111 2222 3333 4444"` -> `"****-****-****-4444"`
- `pattern: "{first1}***@{domain}"` on `"alice@biocorp.org"` -> `"a***@biocorp.org"`

---

## 7. `format_preserve`

Scrambles ASCII digits (`0-9`), ASCII uppercase letters (`A-Z`), and ASCII lowercase letters (`a-z`) within their respective character classes while leaving punctuation, whitespace, hyphens, and non-ASCII characters in place.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `deterministic` | `bool` | `False` | `bool` | Seed per-value substitutions via `HMAC-SHA256(salt, value)` when `True`. |
| `preserve_prefix` | `int` | `0` | `>= 0` | Number of leading characters kept unchanged. |
| `preserve_suffix` | `int` | `0` | `>= 0` | Number of trailing characters kept unchanged. |
| `preserve_null` | `bool` | `True` | `bool` | Leave `null`/`None` values untouched when `True`. |

**Example (`preserve_prefix=3`):** `"ID-4829-X7"` -> `"ID-9104-Q2"`

---

## 8. `noise`

Perturbs numeric values (`int`, `float`, or numeric strings in XML/CSV) by multiplying by a uniform random factor in $[1 - p, 1 + p]$, where $p = \text{percentage} / 100$.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `percentage` | `float` | `10.0` | `0.0 <= percentage <= 100.0` | Symmetric perturbation range ($\pm\%$). |
| `precision` | `int` | `2` | `0 <= precision <= 10` | Decimal rounding places for floating-point values. |
| `preserve_null` | `bool` | `True` | `bool` | Leave `null`/`None` values untouched when `True`. |

- Integer inputs (`100000` or `"100000"`) remain rounded integers (`104312` or `"104312"`).
- Floating-point inputs (`98.6` or `"98.6"`) are rounded to `precision` decimal places.
- Booleans (`True`/`False`), `NaN`, `Infinity`, and non-numeric strings trigger `on_error` (`"raise"` by default).

---

## 9. `synthesize`

Replaces values with format-plausible synthetic substitutes keyed via `HMAC-SHA256(salt, f"{category}:{field_name}:{value}")` when `deterministic=True`, or drawn from `context.rng` when `deterministic=False`.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `category` | `SyntheticCategory \| null` | `null` | One of the 15 categories below | Explicit category; inferred from the leaf field name when `null`. |
| `deterministic` | `bool` | `True` | `bool` | Produce consistent replacements per `(category, field, value, salt)`. |
| `preserve_null` | `bool` | `True` | `bool` | Leave `null`/`None` values untouched when `True`. |

**Supported `category` values:**
`full_name`, `first_name`, `last_name`, `email`, `phone`, `street_address`, `city`, `state`, `zipcode`, `ssn`, `credit_card`, `cvv`, `date`, `clinical_note`, `generic`.

*(Synthetic emails always use the reserved `.invalid` TLD per RFC 2606; synthetic phone numbers use the North American `555-01XX` range; synthetic SSNs use the unassigned `900-XX-XXXX` prefix.)*

---

## 10. `deep_redact`

Walks every scalar leaf node within the matched node or container subtree (nested objects, arrays, or XML subtrees) and replaces each scalar leaf with `replacement`. Structural keys and container nesting remain intact.

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `replacement` | `str` | `"[REDACTED]"` | Any string | Static replacement token written to every scalar leaf. |
| `preserve_null` | `bool` | `False` | `bool` | Keep `null`/`None` scalar leaves as `null` when `True`. |

---

## Built-in Generalization Hierarchies

Used by both the `generalize` technique and `k_anonymity` (`strategy: "enforce"`).

### `date`
Accepts ISO-8601 calendar dates (`YYYY-MM-DD`) and ISO-8601 timestamps (`YYYY-MM-DDTHH:MM:SS...`), validating real calendar dates via `datetime.date`.

| Level | Precision | Example (`"1984-06-19"`) |
| :---: | :--- | :--- |
| `0` | Normalized day | `"1984-06-19"` |
| `1` | Year and month | `"1984-06"` |
| `2` | Year | `"1984"` |
| `3` | Decade interval | `"1980-1989"` |
| `4` | Top (`max_level`) | `"*"` |

### `zipcode` (alias: `zip`)
Accepts 5-digit US ZIP codes (`94107`) or 9-digit `ZIP+4` codes (`94107-1234`, normalized to the 5-digit base).

| Level | Precision | Example (`"94107"`) |
| :---: | :--- | :--- |
| `0` | 5-digit ZIP | `"94107"` |
| `1` | 4-digit prefix | `"9410*"` |
| `2` | 3-digit prefix | `"941**"` |
| `3` | 2-digit prefix | `"94***"` |
| `4` | 1-digit region | `"9****"` |
| `5` | Top (`max_level`) | `"*****"` |

### `age`
Accepts integer ages in `[0, 150]`.

| Level | Precision | Example (`"41"`) |
| :---: | :--- | :--- |
| `0` | Exact age | `"41"` |
| `1` | 5-year interval | `"40-44"` |
| `2` | 10-year interval | `"40-49"` |
| `3` | 20-year interval | `"40-59"` |
| `4` | Top (`max_level`) | `"*"` |

### `icd10`
Accepts ICD-10 diagnosis codes (`<letter><2 digits>` with optional `.` subcategory).

| Level | Precision | Example (`"J45.909"`) |
| :---: | :--- | :--- |
| `0` | Exact normalized code | `"J45.909"` |
| `1` | 3-character category | `"J45"` |
| `2` | Chapter wildcard | `"J**"` |
| `3` | Top (`max_level`) | `"***"` |

