"""Phase 3 — Technique Application and Dry-Run Preview.

Applies resolved rules and subtree scope strategies via the pluggable technique
registry with:

- Zero imports of concrete built-in techniques.
- Zero hardcoded role names.
- Strict adherence to ``policy.unmatched_fields`` (default ``'preserve'``, leaving
  unmatched fields completely untouched).
- Explicit ``mode='mask' | 'dry_run'`` execution control.
"""

from __future__ import annotations

from typing import Any, Literal

from datamasking.adapters.base import FormatAdapter
from datamasking.pipeline.phase0_scope import ScopePlan
from datamasking.pipeline.phase1_index import UnmatchedIndex
from datamasking.pipeline.phase2_conflict import DecisionIndex
from datamasking.policy.models import MaskingPolicy
from datamasking.techniques.base import MaskingContext, get_technique
from datamasking.techniques.registry import validate_technique_params

ExecutionMode = Literal["mask", "dry_run"]
CoverageLog = list[dict[str, Any]]


def _label_subtree_leaves(adapter: FormatAdapter, subtree_root: Any, label: str) -> None:
    leaves = [n for n in adapter.iter_subtree(subtree_root) if adapter.is_leaf_node(n)]
    for leaf in leaves:
        if adapter.is_attached(leaf):
            adapter.set_value(leaf, label)


def apply_masking(
    adapter: FormatAdapter,
    tree: Any,
    policy: MaskingPolicy,
    decision_index: DecisionIndex,
    unmatched_index: UnmatchedIndex,
    *,
    mode: ExecutionMode = "mask",
    scope_plan: ScopePlan | None = None,
    context: MaskingContext | None = None,
) -> CoverageLog:
    """Execute resolved transformations (or dry-run preview labels) across *tree*."""
    if scope_plan is not None and scope_plan.global_passthrough:
        return []

    ctx = context or MaskingContext(on_error=policy.on_error)
    coverage_log: CoverageLog = []

    # 1. Bulk Subtree Scope Operations (inner/smaller subtrees processed before outer subtrees)
    if scope_plan and scope_plan.subtree_roots:
        ordered_roots = sorted(
            scope_plan.subtree_roots,
            key=lambda pair: len(list(adapter.iter_subtree(pair[0]))),
        )
        for root_node, decision in ordered_roots:
            if not adapter.is_attached(root_node):
                continue

            strat = decision.strategy
            if strat in ("passthrough", "masked"):
                continue

            if strat == "drop_subtree":
                if mode == "dry_run":
                    _label_subtree_leaves(
                        adapter,
                        root_node,
                        f"[WOULD DROP SUBTREE: {decision.scope_path}]",
                    )
                else:
                    adapter.remove_node(root_node)
                continue

            # Bulk technique strategy (e.g. 'deep_redact', 'synthesize') dispatched via registry
            tech = get_technique(strat)
            params = validate_technique_params(strat, decision.strategy_params)
            if mode == "dry_run":
                _label_subtree_leaves(adapter, root_node, tech.auditor_label(params))
            else:
                ctx.on_error = policy.on_error
                tech.apply_subtree(adapter, root_node, params, ctx)

    # 2. Per-Node Rule Applications and Explicit Unmatched-Field Policy
    all_nodes = list(adapter.iter_nodes(tree))
    unmatched_action = policy.unmatched_fields

    for node in all_nodes:
        if not adapter.is_attached(node):
            continue

        node_id = adapter.get_identity(node)

        if node_id in decision_index:
            rule = decision_index[node_id]
            ctx.node_path = adapter.get_path(node)
            ctx.on_error = rule.on_error if rule.on_error is not None else policy.on_error

            tech = get_technique(rule.technique)
            params = rule.validated_params()

            if mode == "dry_run":
                label = tech.auditor_label(params)
                if adapter.is_leaf_node(node):
                    adapter.set_value(node, label)
                else:
                    _label_subtree_leaves(adapter, node, label)
            else:
                tech.apply(adapter, node, params, ctx)

        elif node_id in unmatched_index:
            path = unmatched_index[node_id]
            coverage_log.append(
                {
                    "path": path,
                    "action": unmatched_action,
                    "reason": "No matching masking rule.",
                }
            )

            if unmatched_action == "preserve":
                # Policy is the sole source of truth: unmatched fields remain untouched.
                continue
            elif unmatched_action == "redact":
                if mode == "dry_run":
                    adapter.set_value(
                        node,
                        f"[WOULD APPLY UNMATCHED POLICY: redact | replacement={policy.unmatched_replacement!r}]",
                    )
                else:
                    adapter.set_value(node, policy.unmatched_replacement)
            elif unmatched_action == "nullify":
                if mode == "dry_run":
                    adapter.set_value(node, "[WOULD APPLY UNMATCHED POLICY: nullify]")
                else:
                    adapter.set_value(node, None)
            elif unmatched_action == "suppress":
                if mode == "dry_run":
                    adapter.set_value(node, "[WOULD APPLY UNMATCHED POLICY: suppress]")
                else:
                    adapter.remove_node(node)

    return coverage_log
