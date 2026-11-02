# Selectors & Format Adapters Reference

`datamasking-core` parses each supported format into a mutable Abstract Syntax Tree (AST) behind the `FormatAdapter` interface. Selectors locate nodes in that AST without regex scanning or string-splitting raw text.

---

## 1. JSON & YAML (`JSONPath`)

Both `json` and `yaml` (`yml`) adapters wrap parsed structures in parent-tracking `NodeWrapper` nodes and evaluate **extended JSONPath** (`jsonpath_ng.ext`).

### Supported JSONPath Constructs

| Construct | Example | Matches |
| :--- | :--- | :--- |
| Root child | `$.export_id` | Top-level `export_id` field |
| Nested path | `$.patient.contact.email` | Exact nested `email` field |
| Bracket key (dots/spaces) | `$['user.profile']['first name']` | Keys containing punctuation or whitespace |
| Array index | `$.patients[0].ssn` | First element's `ssn` |
| Array wildcard | `$.patients[*].ssn` | `ssn` across all elements of `patients` |
| Recursive descent | `$..ssn` | Every `ssn` key at any nesting depth |
| Numeric filter predicate | `$.patients[?(@.age < 18)].name` | `name` only on records where `age < 18` |
| Equality filter predicate | `$.users[?(@.tier == "vip")].email` | `email` only on records where `tier == "vip"` |

> **Why Phase 1 Evaluates Before Mutation:** Because Phase 1 indexes all selectors *before* Phase 3 mutates any values, a filter predicate like `$.patients[?(@.age < 18)].name` always evaluates against the original integer `age` even if another rule generalizes `$.patients[*].age` to `"15-19"`.

### YAML Security Note
`YAMLAdapter` exclusively uses `yaml.safe_load` and `yaml.safe_dump(..., sort_keys=False)` so arbitrary Python object tags (`!!python/object`) are rejected and key ordering is preserved.

---

## 2. XML (`XPath 1.0`)

`XMLAdapter` uses `lxml.etree` with hardened parser flags (`resolve_entities=False`, `load_dtd=False`, `no_network=True`, `huge_tree=False`). Both XML elements and XML attributes (`XMLAttributeNode`) are first-class AST nodes.

### Supported XPath Constructs

| Construct | Example | Matches |
| :--- | :--- | :--- |
| Absolute element path | `/clinical_document/patient/name` | Exact element hierarchy |
| Recursive element search | `//ssn` | Every `<ssn>` element anywhere in the document |
| XML attribute | `//patient/@mrn` | `mrn` attribute on `<patient mrn="9001">` |
| Attribute predicate | `//telecom[@use="HP"]/@value` | `value` attribute on home-phone `<telecom>` tags |
| Positional predicate | `//patient[1]/dob` | First `<patient>` element's `<dob>` |

### Default XML Namespaces (`xmlns="..."`)
Standard XPath 1.0 treats unprefixed tag names in `/Patient/name` as belonging to the empty namespace, which normally fails to match HL7/FHIR XML documents declaring a default namespace (`<Patient xmlns="http://hl7.org/fhir">`). When an XML document declares a default namespace (`None in root.nsmap`) and a standard XPath returns no matches, `XMLAdapter` automatically rewrites unprefixed tag steps to `*[local-name()='...']` so policies work out-of-the-box without requiring namespace prefix boilerplate.

### Nullify vs. Suppress on XML Nodes

| Operation | On `<ssn>123</ssn>` Element | On `mrn="9001"` Attribute |
| :--- | :--- | :--- |
| `suppress` | Removes `<ssn>123</ssn>` from parent element | Removes `mrn="9001"` from element |
| `nullify` | Clears element text (`<ssn></ssn>`) | Removes `mrn="9001"` (XML has no null attribute literal) |

---

## 3. CSV (`Header-Isolated Row AST`)

`CSVAdapter` parses UTF-8 (including UTF-8 BOM) CSV files with a header row into a `CSVDocument(fieldnames=[...], root=wrap_tree(rows))`.

- **Rows** are addressed as a JSONPath array `$[*]` of dictionaries keyed by column header.
- **Header Isolation**: Column headers are stored separately from the row AST, so broad selectors (even `$..*`) only visit cell values (`$[0].email`, `$[1].email`) and never corrupt the CSV header row.
- **Column Addressing**: Both `$[*].email` and `$..email` select the `email` cell in every row.
- **Column Suppression**: Applying `suppress` to `$[*].ssn` removes `ssn` from every row and cleanly omits `ssn` from the serialized CSV header line.
- **Conditional Row Cell Masking**: Filter predicates work on CSV rows too (note that CSV cell values are parsed as strings, e.g. `$[?(@.country == "DE")].ip_address`).
- **`k`-Anonymity on CSV**: Set `record_root: "$[*]"` and list column selectors such as `quasi_identifiers: [{selector: "$.zipcode", hierarchy: "zipcode"}]`.

---

## 4. Single-Format vs. Multi-Format Policies

- **Single-Format Policy (`format: "json"` / `"xml"` / `"yaml"` / `"csv"`)**: Recommended whenever a policy targets one format. At policy load time, `MaskingPolicy` validates every rule, profile, scope, `record_root`, and `quasi_identifier` selector against that adapter's syntax checker — catching invalid JSONPath/XPath expressions before runtime.
- **Multi-Format Policy (`format: null`)**: Useful when a single shared policy contains both JSONPath (`$..ssn`) and XPath (`//ssn`) rules to handle heterogeneous payloads. At runtime, `JSONAdapter` skips `/`-prefixed XPath selectors, and `XMLAdapter` skips `$`-prefixed JSONPath selectors, while still raising `SelectorEvaluationError` if a selector targeting the active format has broken syntax.

