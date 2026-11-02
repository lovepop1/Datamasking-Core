"""High-level Python SDK entrypoint (:class:`MaskingEngine`)."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

from datamasking.adapters.registry import detect_format_from_filename
from datamasking.exceptions import PolicyValidationError
from datamasking.pipeline.phase3_apply import ExecutionMode
from datamasking.pipeline.runner import PipelineResult, run_pipeline
from datamasking.policy.loader import (
    load_policy_from_dict,
    load_policy_from_file,
    load_policy_from_yaml,
)
from datamasking.policy.models import MaskingPolicy


class MaskingEngine:
    """Reusable, thread-safe in-memory data masking engine bound to a :class:`MaskingPolicy`.

    ``MaskingEngine`` never applies a hidden or built-in default policy: every
    transformation is governed strictly by *policy*.

    Args:
        policy: Validated :class:`MaskingPolicy`, policy dictionary, or YAML string.
        salt: Optional secret key for deterministic HMAC techniques. When omitted,
            reads ``DATAMASKING_SALT`` from the environment or generates a fresh
            256-bit cryptographically random key scoped to this engine instance.
    """

    def __init__(
        self,
        policy: MaskingPolicy | dict[str, Any] | str,
        *,
        salt: str | None = None,
    ) -> None:
        if policy is None:
            raise PolicyValidationError(
                "MaskingEngine requires an explicit policy; no default policy exists."
            )
        if isinstance(policy, MaskingPolicy):
            self.policy = policy
        elif isinstance(policy, dict):
            self.policy = load_policy_from_dict(policy)
        elif isinstance(policy, str):
            self.policy = load_policy_from_yaml(policy)
        else:
            raise TypeError(
                f"Expected MaskingPolicy, dict, or YAML string, got {type(policy).__name__}."
            )

        env_salt = os.environ.get("DATAMASKING_SALT")
        self._default_salt: str = (
            salt if salt is not None else (env_salt if env_salt else secrets.token_hex(32))
        )

    @classmethod
    def from_file(
        cls,
        policy_file_path: str | Path,
        *,
        salt: str | None = None,
    ) -> MaskingEngine:
        """Load a YAML policy file from disk and return a configured :class:`MaskingEngine`."""
        policy = load_policy_from_file(policy_file_path)
        return cls(policy, salt=salt)

    def mask(
        self,
        payload: bytes | str | dict[str, Any] | list[Any],
        *,
        format: str | None = None,
        role: str | None = None,
        mode: ExecutionMode = "mask",
        salt: str | None = None,
        seed: int | None = None,
        tenant_id: str | None = None,
        request_id: str | None = None,
        max_input_bytes: int | None = None,
    ) -> PipelineResult:
        """Mask an in-memory payload according to ``self.policy`` and return :class:`PipelineResult`."""
        fmt: str | None
        if isinstance(payload, (dict, list)):
            raw_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            fmt = format or "json"
        elif isinstance(payload, str):
            raw_bytes = payload.encode("utf-8")
            fmt = format
        elif isinstance(payload, bytes):
            raw_bytes = payload
            fmt = format
        else:
            raise TypeError(
                f"Unsupported payload type '{type(payload).__name__}'. "
                "Expected bytes, str, dict, or list."
            )

        effective_salt = salt if salt is not None else self._default_salt

        return run_pipeline(
            raw_bytes,
            self.policy,
            role=role,
            mode=mode,
            format_name=fmt,
            request_id=request_id,
            salt=effective_salt,
            seed=seed,
            tenant_id=tenant_id,
            max_input_bytes=max_input_bytes,
        )

    def mask_data(
        self,
        data: dict[str, Any] | list[Any],
        *,
        role: str | None = None,
        mode: ExecutionMode = "mask",
        salt: str | None = None,
        seed: int | None = None,
        tenant_id: str | None = None,
        request_id: str | None = None,
    ) -> Any:
        """Mask a Python ``dict`` or ``list`` in memory and return the masked Python object."""
        if not isinstance(data, (dict, list)):
            raise TypeError(f"mask_data expects a dict or list, got '{type(data).__name__}'.")
        result = self.mask(
            data,
            format="json",
            role=role,
            mode=mode,
            salt=salt,
            seed=seed,
            tenant_id=tenant_id,
            request_id=request_id,
        )
        return json.loads(result.output_bytes.decode("utf-8"))

    def mask_file(
        self,
        file_path: str | Path,
        *,
        format: str | None = None,
        role: str | None = None,
        mode: ExecutionMode = "mask",
        salt: str | None = None,
        seed: int | None = None,
        tenant_id: str | None = None,
        request_id: str | None = None,
        max_input_bytes: int | None = None,
    ) -> PipelineResult:
        """Read *file_path* into memory, infer format from extension if needed, and mask it."""
        path = Path(file_path)
        raw_bytes = path.read_bytes()
        fmt = format or self.policy.format or detect_format_from_filename(str(path))
        return self.mask(
            raw_bytes,
            format=fmt,
            role=role,
            mode=mode,
            salt=salt,
            seed=seed,
            tenant_id=tenant_id,
            request_id=request_id,
            max_input_bytes=max_input_bytes,
        )
