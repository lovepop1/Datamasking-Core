"""Phase 1 — Scope-Aware Selector Indexing.

Evaluates active global rules and scope-expanded profile rules against the AST
without mutating any values, producing:

- ``rule_index``: mapping from ``node_id`` to competing :class:`MaskingRule` objects.
- ``unmatched_index``: mapping from ``node_id`` to canonical path for scalar leaf
  nodes not matched by any rule or bulk/passthrough scope.
"""

from __future__ import annotations

from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.pipeline.phase0_scope import ScopeDecision, ScopePlan
from datamasking.policy.models import MaskingRule

RuleIndex = dict[int, list[MaskingRule]]
UnmatchedIndex = dict[int, str]

# Backwards-compatible type alias
CoverageIndex = UnmatchedIndex

_BULK_STRATEGIES = frozenset({"drop_subtree", "deep_redact", "synthesize"})


def build_index(
    adapter: FormatAdapter,
    tree: Any,
    rules: list[MaskingRule],
    scope_plan: ScopePlan | None = None,
    *,
    role: str | None = None,
) -> tuple[RuleIndex, UnmatchedIndex]:
    """Evaluate global and scope-expanded selectors against *tree*."""
    if scope_plan is not None and scope_plan.global_passthrough:
        return {}, {}

    members: dict[int, ScopeDecision] = scope_plan.members if scope_plan else {}

    def _is_exempt_from_element_rules(node_id: int) -> bool:
        decision = members.get(node_id)
        if decision is None:
            return False
        return decision.strategy in _BULK_STRATEGIES or decision.strategy == "passthrough"

    rule_index: RuleIndex = {}

    # 1. Global policy rules (filtered by rule.roles when specified)
    for rule in rules:
        if rule.roles is not None and (role is None or role not in rule.roles):
            continue

        matched_nodes = adapter.select(tree, rule.selector)
        for node in matched_nodes:
            node_id = adapter.get_identity(node)
            if _is_exempt_from_element_rules(node_id):
                continue
            rule_index.setdefault(node_id, []).append(rule)

    # 2. Scope-expanded rules for scopes with strategy == "masked"
    if scope_plan and scope_plan.subtree_roots:
        decision_member_sets: dict[int, set[int]] = {}
        for node_id, decision in members.items():
            decision_member_sets.setdefault(id(decision), set()).add(node_id)

        processed_decisions: set[int] = set()
        for root_node, decision in scope_plan.subtree_roots:
            dec_key = id(decision)
            if decision.strategy != "masked" or not decision.expanded_rules:
                continue

            allowed_ids = decision_member_sets.get(dec_key, set())
            if not allowed_ids:
                continue

            if dec_key not in processed_decisions:
                processed_decisions.add(dec_key)
                for exp_rule in decision.expanded_rules:
                    matched_nodes = adapter.select(tree, exp_rule.selector)
                    matched_in_scope = [
                        n for n in matched_nodes if adapter.get_identity(n) in allowed_ids
                    ]
                    if not matched_in_scope:
                        # Also support selectors written relative to the subtree root
                        rel_matches = adapter.select(root_node, exp_rule.selector)
                        matched_in_scope = [
                            n for n in rel_matches if adapter.get_identity(n) in allowed_ids
                        ]
                    for node in matched_in_scope:
                        node_id = adapter.get_identity(node)
                        if _is_exempt_from_element_rules(node_id):
                            continue
                        rule_index.setdefault(node_id, []).append(exp_rule)

    # 3. Unmatched leaf index (account for container nodes targeted by suppress/deep_redact)
    covered_by_ancestor: set[int] = set()
    for node in adapter.iter_nodes(tree):
        nid = adapter.get_identity(node)
        if nid in rule_index and not adapter.is_leaf_node(node):
            for desc in adapter.iter_subtree(node):
                covered_by_ancestor.add(adapter.get_identity(desc))

    unmatched_index: UnmatchedIndex = {}
    for node in adapter.iter_nodes(tree):
        if not adapter.is_leaf_node(node):
            continue
        node_id = adapter.get_identity(node)
        if _is_exempt_from_element_rules(node_id):
            continue
        if node_id not in rule_index and node_id not in covered_by_ancestor:
            unmatched_index[node_id] = adapter.get_path(node)

    return rule_index, unmatched_index
