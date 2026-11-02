## Summary

<!-- Explain what changed and why. -->

## Checklist

- [ ] Policy remains the single source of truth (no implicit/forced masking outside policy configuration).
- [ ] `ruff check src tests examples` and `ruff format --check src tests examples` pass.
- [ ] `mypy --config-file pyproject.toml src` passes with zero errors.
- [ ] `pytest --cov=datamasking` passes with unit/property tests covering the change.
- [ ] Documentation (`docs/` and `schema/policy.schema.json` if policy models changed) is updated.

