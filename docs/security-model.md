# Security & Privacy Model

This document states the exact security guarantees provided by `datamasking-core` as well as its cryptographic, statistical, and runtime boundaries.

---

## 1. Explicit Policy Guarantee (No Silent Fallbacks)

- **No Default Policy**: Constructing `MaskingEngine` requires an explicit policy. Calling `MaskingEngine(None)` raises `PolicyValidationError`.
- **No Unrequested Field Mutation**: By default (`unmatched_fields: "preserve"`), fields not matched by an active rule are preserved verbatim. If your threat model requires closed-world / allowlist behavior where newly added schema fields are automatically stripped or redacted, set `unmatched_fields: "redact"` or `unmatched_fields: "suppress"` explicitly in your policy.
- **No Silent Error Masking**: By default (`on_error: "raise"`), domain mismatches (such as malformed dates in `generalize` or non-numeric strings in `noise`) abort the run with `TechniqueExecutionError` rather than silently emitting partial or unexpected output.

---

## 2. Cryptographic Key Management (`salt`)

Deterministic techniques (`pseudonymize` with `consistent=True`, `synthesize` with `deterministic=True`, and `format_preserve` with `deterministic=True`) compute `HMAC-SHA256` keyed with `salt`:

1. **Never commit production salts to policy YAML or source control.** Pass `salt` at runtime via `MaskingEngine(..., salt=...)` or the `DATAMASKING_SALT` environment variable (populated from a secrets manager or KMS).
2. **Ephemeral Default Key**: When neither `salt` nor `DATAMASKING_SALT` is provided, `MaskingEngine` generates a fresh 256-bit key via `secrets.token_hex(32)`. That prevents rainbow-table or dictionary attacks against low-entropy domains (such as 9-digit SSNs or phone numbers) when cross-run linkability is not needed.
3. **Low-Entropy Input Warning**: Keyed `HMAC-SHA256` resists offline dictionary attacks **only as long as the HMAC key (`salt`) remains secret**. Any party who possesses `salt` can test candidate SSNs or emails to verify matches.

---

## 3. Privacy & Regulatory Boundaries

### Pseudonymization vs. Anonymization
Under frameworks such as GDPR (Article 4(5) and Recital 26) and HIPAA:
- Keyed tokenization (`pseudonymize`) produces **pseudonymized data**, which remains personal data whenever the secret key exists and re-identification via linkage is possible.
- Removing direct identifiers (`suppress`) is necessary but rarely sufficient on its own for irreversible anonymization if quasi-identifiers (`zipcode`, `dob`, `age`, `gender`) remain ungeneralized.

### `k`-Anonymity Limitations
`k_anonymity` ensures every equivalence class over declared `quasi_identifiers` contains at least $k$ records, mitigating **record linkage** (singling out via quasi-identifiers). However, classic $k$-anonymity alone does **not** prevent:
- **Homogeneity Attacks**: If all $k$ records in an equivalence class `(zipcode="9410*", age="40-44")` share the exact same sensitive attribute (`diagnosis="HIV+"`), an attacker learns the sensitive attribute without identifying which specific record belongs to the target.
- **Background Knowledge Attacks**: Skewed sensitive distributions combined with external knowledge can still leak attribute probabilities (addressed in literature by $\ell$-diversity and $t$-closeness).

### Numeric Perturbation (`noise`) vs. Differential Privacy
The built-in `noise` technique multiplies values by a bounded uniform random factor in $[1 - p, 1 + p]$. This is designed for **test-data realism and heuristic obfuscation**, **not** formal $\varepsilon$-differential privacy:
- Repeatedly masking and releasing the same record with independent uniform draws allows an observer to average out symmetric noise over many releases.
- Zero values (`0`) remain `0` under multiplicative noise.
- If your release requires formal $(\varepsilon, \delta)$-differential privacy (e.g. calibrated Laplace or Gaussian mechanisms with sensitivity bounds), register a custom plugin technique implementing your exact mechanism and sensitivity budget.

---

## 4. Parser Hardening

Untrusted inputs are hardened against common parser attacks out of the box:

- **XML (`XMLAdapter`)**: `lxml.etree.XMLParser` runs with `resolve_entities=False`, `load_dtd=False`, `no_network=True`, and `huge_tree=False`, blocking XML External Entity (XXE) file disclosure, SSRF via external DTDs, and Billion-Laughs entity amplification.
- **YAML (`YAMLAdapter`)**: Uses `yaml.safe_load` exclusively, blocking arbitrary code execution via `!!python/object/apply` tags.
- **Input Size Caps**: Callers handling untrusted network payloads should pass `max_input_bytes` to `engine.mask(..., max_input_bytes=...)` to reject oversized payloads before AST allocation.

---

## 5. In-Memory Lifecycle in CPython

`datamasking-core` performs zero temporary file writes (`tempfile`, swap files, or disk caches are never used). Note, however, standard CPython runtime behavior:
- Python `bytes` and `str` objects are immutable in managed heap memory; freed buffers remain in the Python allocator's arena until overwritten or process exit rather than being `memset`-zeroed immediately.
- Operating system swap should be disabled (`swapoff` / encrypted memory / `mlock` at container level) in high-assurance environments processing regulated PHI/PCI payloads.

