# Contributing to `datamasking-core`

Contributions are welcome. Before opening a pull request, please review the architectural principles and quality checks below.

## Core Design Invariants

1. **The Policy Is the Single Source of Truth**: Never introduce default policies, implicit field redaction, magic role names, or silent fallback mutations in library code. If a behavior mutates or skips data, it must be explicitly expressed in `MaskingPolicy`.
2. **Strict Validation at Load Time**: Misspelled policy keys, unregistered techniques, unknown technique parameters, and invalid format-specific selectors must fail fast with `PolicyValidationError` when loading the policy.
3. **Decoupled Extensibility**: Pipeline phases (`src/datamasking/pipeline/`) must never import concrete classes from `builtins/`. All techniques, format adapters, and generalization hierarchies interact exclusively through their abstract base classes and registries.
4. **Hermetic In-Memory Execution**: Library functions must not write temporary files, mutate global RNG state, or make network calls.

## Local Development Setup

```bash
git clone https://github.com/lovepop1/Datamasking-Core.git
cd Datamasking-Core

python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell:
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
```

## Quality Checks

Every pull request must pass all four checks locally:

```bash
# 1. Lint & import sorting
ruff check src tests examples

# 2. Code formatting
ruff format --check src tests examples

# 3. Strict static type checking
mypy --config-file pyproject.toml src

# 4. Unit, property, and documentation tests
pytest --cov=datamasking --cov-report=term-missing
```

If you modify any model in `src/datamasking/policy/models.py`, regenerate the JSON Schema before committing:

```bash
datamasking schema -o schema/policy.schema.json
```

## Extending vs. Modifying Core

New domain-specific techniques, formats, or hierarchies do not necessarily require modifying `datamasking-core` itself — see [`docs/extending.md`](docs/extending.md) for how to publish standalone plugin packages using Python `entry_points`. Pull requests adding general-purpose, zero-dependency techniques or hierarchies to `builtins/` should include parameter validation tests, error-mode tests (`on_error`), and documentation in [`docs/techniques.md`](docs/techniques.md).
