"""Phase 2 — Deterministic Conflict Resolution.

When multiple active rules match the same AST node, ``datamasking-core`` selects
a single winning rule using a strict three-tier precedence order:

1. **Explicit Rule Priority** (``rule.priority``, highest integer wins).
2. **Selector Specificity Score** (structural path depth, predicates, wildcard
   penalties, plus a ``+5`` scope-locality bonus for scope-expanded rules).
3. **Policy Declaration Order** (earliest rule declared in the policy wins ties).
"""

from __future__ import annotations

import re
from typing import Any

from datamasking.pipeline.phase1_index import RuleIndex
from datamasking.policy.models import MaskingRule

DecisionIndex = dict[int, MaskingRule]
ConflictRecord = dict[str, Any]
ConflictLog = list[ConflictRecord]

_SCOPE_BONUS = 5


def score_selector(selector: str) -> int:
    """Compute a deterministic integer specificity score for JSONPath or XPath *selector*."""
    score = 0
    stripped = selector.strip()

    if stripped.startswith("/") or stripped.startswith("$"):
        score += 3

    score -= 2 * (stripped.count("//") + stripped.count(".."))
    score += 5 * len(re.findall(r"\[@[^\]]+\]|\[\?\([^\)]+\)\]|\[(?!\d+\])[^\]]+\]", stripped))

    no_predicates = re.sub(r"\[[^\]]*\]", "", stripped)
    tokens = [t for t in re.split(r"[/.\[\]]+", no_predicates) if t]
    for token in tokens:
        if token in ("*", "**"):
            score -= 1
        elif token and not token.isdigit() and token not in ("", "$", "@"):
            score += 10

    return score


def resolve_conflicts(
    rule_index: RuleIndex,
    rules: list[MaskingRule],
    node_paths: dict[int, str] | None = None,
    expansion_rule_ids: set[int] | None = None,
) -> tuple[DecisionIndex, ConflictLog]:
    """Resolve multi-rule matches for each node and emit an audit ``ConflictLog``."""
    rule_order: dict[int, int] = {id(r): idx for idx, r in enumerate(rules)}
    expansion_ids = expansion_rule_ids or set()
    paths = node_paths or {}

    decision_index: DecisionIndex = {}
    conflict_log: ConflictLog = []

    for node_id, competing in rule_index.items():
        if len(competing) == 1:
            decision_index[node_id] = competing[0]
            continue

        scored_candidates: list[tuple[int, int, int, MaskingRule]] = []
        for idx, rule in enumerate(competing):
            specificity = score_selector(rule.selector)
            if id(rule) in expansion_ids:
                specificity += _SCOPE_BONUS
            order = rule_order.get(id(rule), len(rule_order) + idx)
            scored_candidates.append((rule.priority, specificity, order, rule))

        # Highest priority -> highest specificity -> lowest declaration order
        scored_candidates.sort(key=lambda item: (-item[0], -item[1], item[2]))
        winner = scored_candidates[0][3]
        decision_index[node_id] = winner

        conflict_log.append(
            {
                "node_id": node_id,
                "node_path": paths.get(node_id, "[path_unavailable]"),
                "winning_rule": {
                    "id": winner.id,
                    "selector": winner.selector,
                    "technique": winner.technique,
                    "priority": winner.priority,
                },
                "competing_rules": [
                    {
                        "id": cand.id,
                        "selector": cand.selector,
                        "technique": cand.technique,
                        "priority": prio,
                        "score": spec,
                    }
                    for prio, spec, _, cand in scored_candidates
                ],
            }
        )

    return decision_index, conflict_log
