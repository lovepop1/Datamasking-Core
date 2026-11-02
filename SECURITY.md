# Security Policy

## Scope of `datamasking-core`

`datamasking-core` is an in-memory data transformation library. Security-relevant issues include:

- **Bypass of declared policy rules**: Cases where a selector or scope declared in a valid `MaskingPolicy` fails to transform matching nodes without raising an error.
- **Parser vulnerabilities**: XML External Entity (XXE), DTD network access, entity-expansion amplification, or unsafe YAML deserialization.
- **Cryptographic weaknesses in keyed operations**: Key-isolation failures or unkeyed deterministic hashing in `pseudonymize`, `synthesize`, or `format_preserve`.
- **Unintended disk persistence**: Any code path inside `datamasking-core` that writes payload data to temporary files on disk when using in-memory APIs.

Please read [`docs/security-model.md`](docs/security-model.md) for documented privacy and operational boundaries (such as the distinction between GDPR pseudonymization and irreversible anonymization, `k`-anonymity homogeneity attacks, and Python garbage-collection memory semantics).

## Reporting a Vulnerability

Do **not** open a public GitHub issue for suspected security vulnerabilities.

1. Use GitHub's **Report a vulnerability** button under the repository's **Security -> Advisories** tab to open a private security advisory.
2. Include:
   - Affected version of `datamasking-core` and Python version.
   - Minimal policy YAML and **synthetic** input payload reproducing the issue (never include real personal or clinical data).
   - Impact assessment.

Maintainers will acknowledge receipt within 72 hours and coordinate a fix and advisory disclosure.

