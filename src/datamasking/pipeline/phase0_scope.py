"""Phase 0 — Subtree Scope Evaluation.

Resolves subtree governance boundaries, role strategies, and profile expansions
purely from the declarative :class:`MaskingPolicy` (with zero hardcoded role names).
Nested scopes are resolved by subtree containment size so narrower inner scopes
always override broader outer scopes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.policy.models import MaskingPolicy, MaskingRule, SubtreeStrategyType


@dataclass
class ScopeDecision:
    """Resolved handling decision for a matched subtree scope."""

    strategy: SubtreeStrategyType
    expanded_rules: list[MaskingRule]
    profile_name: str | None
    scope_path: str
    strategy_params: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScopePlan:
    """Complete output of Phase 0 scope evaluation."""

    members: dict[int, ScopeDecision] = field(default_factory=dict)
    subtree_roots: list[tuple[Any, ScopeDecision]] = field(default_factory=list)
    expanded_rules_ordered: list[MaskingRule] = field(default_factory=list)
    expansion_rule_ids: set[int] = field(default_factory=set)
    scope_events: list[dict[str, str]] = field(default_factory=list)
    global_passthrough: bool = False


def is_role_passthrough(policy: MaskingPolicy, role: str | None) -> bool:
    """Return ``True`` only if *policy* explicitly grants *role* global passthrough."""
    if role is None:
        return False
    role_def = policy.roles.get(role)
    return bool(role_def is not None and role_def.passthrough)


def evaluate_scopes(
    adapter: FormatAdapter,
    tree: Any,
    policy: MaskingPolicy,
    role: str | None = None,
) -> ScopePlan:
    """Evaluate all ``policy.scopes`` for *role* and return a :class:`ScopePlan`."""
    plan = ScopePlan()

    if is_role_passthrough(policy, role):
        plan.global_passthrough = True
        return plan

    if not policy.scopes:
        return plan

    # Track subtree size per node_id so narrower nested scopes take precedence over outer scopes.
    member_subtree_sizes: dict[int, int] = {}

    for scope_rule in policy.scopes:
        root_nodes = adapter.select(tree, scope_rule.path)
        if not root_nodes:
            continue

        role_strat = scope_rule.roles.get(role) if role is not None else None
        if role_strat is None:
            role_strat = scope_rule.roles.get("default")

        strategy: SubtreeStrategyType
        apply_profile: str | None
        strategy_params: dict[str, Any]

        if role_strat is not None:
            strategy = role_strat.strategy
            apply_profile = role_strat.profile or scope_rule.apply_profile
            strategy_params = dict(role_strat.params)
        else:
            role_def = policy.roles.get(role) if role is not None else None
            if role_def is not None and role_def.default_scope_strategy is not None:
                strategy = role_def.default_scope_strategy
                apply_profile = scope_rule.apply_profile
                strategy_params = {}
            elif scope_rule.apply_profile is not None or bool(scope_rule.rules):
                strategy = "masked"
                apply_profile = scope_rule.apply_profile
                strategy_params = {}
            else:
                # Scope only defines overrides for other roles; current caller inherits normal global rules.
                continue

        expanded_rules: list[MaskingRule] = []
        profile_name: str | None = None

        if strategy == "masked":
            if apply_profile and apply_profile in policy.profiles:
                profile = policy.profiles[apply_profile]
                profile_name = apply_profile
                for prule in profile.rules:
                    if prule.roles is not None and (role is None or role not in prule.roles):
                        continue
                    mr = prule.model_copy()
                    expanded_rules.append(mr)
                    plan.expanded_rules_ordered.append(mr)
                    plan.expansion_rule_ids.add(id(mr))

            for srule in scope_rule.rules:
                if srule.roles is not None and (role is None or role not in srule.roles):
                    continue
                mr = srule.model_copy()
                expanded_rules.append(mr)
                plan.expanded_rules_ordered.append(mr)
                plan.expansion_rule_ids.add(id(mr))

        decision = ScopeDecision(
            strategy=strategy,
            expanded_rules=expanded_rules,
            profile_name=profile_name,
            scope_path=scope_rule.path,
            strategy_params=strategy_params,
        )

        plan.scope_events.append(
            {
                "path": scope_rule.path,
                "profile": profile_name or "",
                "strategy": strategy,
                "role": role or "",
            }
        )

        for root_node in root_nodes:
            subtree_nodes = list(adapter.iter_subtree(root_node))
            subtree_size = len(subtree_nodes)
            plan.subtree_roots.append((root_node, decision))
            for member_node in subtree_nodes:
                member_id = adapter.get_identity(member_node)
                prev_size = member_subtree_sizes.get(member_id)
                if prev_size is None or subtree_size <= prev_size:
                    plan.members[member_id] = decision
                    member_subtree_sizes[member_id] = subtree_size

    return plan
