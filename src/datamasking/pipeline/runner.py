"""Pipeline runner — executes Phase 0 through k-anonymity completely in memory."""

from __future__ import annotations

import random
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.adapters.registry import detect_format_from_content, get_adapter
from datamasking.exceptions import FormatParseError
from datamasking.pipeline.kanon import KAnonReport, enforce_k_anonymity
from datamasking.pipeline.phase0_scope import evaluate_scopes
from datamasking.pipeline.phase1_index import build_index
from datamasking.pipeline.phase2_conflict import ConflictLog, resolve_conflicts
from datamasking.pipeline.phase3_apply import CoverageLog, ExecutionMode, apply_masking
from datamasking.policy.models import MaskingPolicy
from datamasking.techniques.base import MaskingContext


@dataclass(frozen=True)
class PipelineResult:
    """Immutable result of an in-memory ``datamasking-core`` pipeline execution."""

    output_bytes: bytes
    format_name: str
    conflict_log: ConflictLog
    coverage_log: CoverageLog
    kanon_report: KAnonReport | None
    request_id: str
    mode: ExecutionMode = "mask"
    role: str | None = None
    warnings: list[dict[str, Any]] = field(default_factory=list)
    scope_events: list[dict[str, str]] = field(default_factory=list)

    conflict_count: int = field(init=False)
    uncovered_count: int = field(init=False)
    unmatched_paths: list[str] = field(init=False)
    k_achieved: bool = field(init=False)
    scopes_evaluated: int = field(init=False)
    scopes_dropped: int = field(init=False)
    profiles_applied: list[str] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "conflict_count", len(self.conflict_log))
        unmatched = [
            str(entry["path"])
            for entry in self.coverage_log
            if "path" in entry and entry.get("reason") != "ancestor suppressed"
        ]
        object.__setattr__(self, "unmatched_paths", unmatched)
        object.__setattr__(self, "uncovered_count", len(unmatched))
        object.__setattr__(
            self,
            "k_achieved",
            self.kanon_report.achieved if self.kanon_report is not None else True,
        )
        object.__setattr__(self, "scopes_evaluated", len(self.scope_events))
        object.__setattr__(
            self,
            "scopes_dropped",
            sum(1 for e in self.scope_events if e.get("strategy") == "drop_subtree"),
        )
        seen_profiles: dict[str, None] = {}
        for event in self.scope_events:
            prof = event.get("profile", "")
            if prof:
                seen_profiles[prof] = None
        object.__setattr__(self, "profiles_applied", list(seen_profiles.keys()))

    @property
    def output_text(self) -> str:
        """Decode ``output_bytes`` as UTF-8 text."""
        return self.output_bytes.decode("utf-8")


def run_pipeline(
    raw_bytes: bytes,
    policy: MaskingPolicy,
    *,
    role: str | None = None,
    mode: ExecutionMode = "mask",
    format_name: str | None = None,
    request_id: str | None = None,
    salt: str | None = None,
    seed: int | None = None,
    tenant_id: str | None = None,
    max_input_bytes: int | None = None,
) -> PipelineResult:
    """Execute the complete multi-phase in-memory data masking pipeline."""
    if max_input_bytes is not None and len(raw_bytes) > max_input_bytes:
        raise FormatParseError(
            f"Input payload size ({len(raw_bytes)} bytes) exceeds max_input_bytes ({max_input_bytes} bytes).",
            detail={"input_bytes": len(raw_bytes), "max_input_bytes": max_input_bytes},
        )

    req_id = request_id or str(uuid.uuid4())
    fmt = (format_name or policy.format or detect_format_from_content(raw_bytes)).lower().strip()
    adapter: FormatAdapter = get_adapter(fmt)

    # 1. Parse payload into mutable AST
    tree = adapter.parse(raw_bytes)

    # 2. Phase 0: Subtree Scope Evaluation
    scope_plan = evaluate_scopes(adapter, tree, policy, role=role)

    # 3. Phase 1: Scope-Aware Selector Indexing
    rule_index, unmatched_index = build_index(
        adapter,
        tree,
        policy.rules,
        scope_plan=scope_plan,
        role=role,
    )

    # Capture human-readable paths for conflict records
    node_paths: dict[int, str] = {}
    for node in adapter.iter_nodes(tree):
        node_id = adapter.get_identity(node)
        if node_id in rule_index:
            node_paths[node_id] = adapter.get_path(node)

    # 4. Phase 2: Deterministic Conflict Resolution
    ordered_rules = list(policy.rules) + list(scope_plan.expanded_rules_ordered)
    decision_index, conflict_log = resolve_conflicts(
        rule_index,
        ordered_rules,
        node_paths=node_paths,
        expansion_rule_ids=scope_plan.expansion_rule_ids,
    )

    # 5. Phase 3: Pluggable Technique Execution (or Dry-Run Preview)
    effective_salt = salt if salt is not None else secrets.token_hex(32)
    rng = random.Random(seed) if seed is not None else random.Random()
    context = MaskingContext(
        role=role,
        tenant_id=tenant_id,
        salt=effective_salt,
        rng=rng,
        on_error=policy.on_error,
        conflict_log=conflict_log,
    )
    coverage_log = apply_masking(
        adapter,
        tree,
        policy,
        decision_index,
        unmatched_index,
        mode=mode,
        scope_plan=scope_plan,
        context=context,
    )

    # 6. Phase 4: Optional k-Anonymity Verification / Enforcement
    kanon_report = enforce_k_anonymity(
        adapter,
        tree,
        policy,
        role=role,
        mode=mode,
    )

    # 7. Serialize mutated AST back to UTF-8 bytes
    output_bytes = adapter.serialize(tree)

    return PipelineResult(
        output_bytes=output_bytes,
        format_name=fmt,
        conflict_log=conflict_log,
        coverage_log=coverage_log,
        kanon_report=kanon_report,
        request_id=req_id,
        mode=mode,
        role=role,
        warnings=list(context.warnings),
        scope_events=scope_plan.scope_events,
    )
