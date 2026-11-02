"""k-Anonymity verification, full-domain hierarchy generalization, and outlier suppression."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from datamasking.adapters.base import FormatAdapter
from datamasking.hierarchies.base import Hierarchy, get_hierarchy
from datamasking.pipeline.phase0_scope import is_role_passthrough
from datamasking.pipeline.phase3_apply import ExecutionMode
from datamasking.policy.models import MaskingPolicy, QuasiIdentifier

QITuple = tuple[str, ...]


@dataclass(frozen=True)
class KAnonReport:
    """Outcome report for k-anonymity verification or enforcement."""

    achieved: bool
    iterations: int
    violating_classes: list[dict[str, Any]]
    final_qi_levels: dict[str, int]
    suppressed_records: int = 0
    total_records: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize report into a plain JSON-compatible dictionary."""
        return {
            "achieved": self.achieved,
            "iterations": self.iterations,
            "violating_classes": self.violating_classes,
            "final_qi_levels": self.final_qi_levels,
            "suppressed_records": self.suppressed_records,
            "total_records": self.total_records,
        }


def _normalize_relative_selector(adapter: FormatAdapter, selector: str) -> str:
    stripped = selector.strip()
    if adapter.format_name == "xml":
        if stripped.startswith("//"):
            return f".{stripped}"
        if stripped.startswith("/"):
            return f".{stripped}"
    return stripped


def _select_qi_nodes(adapter: FormatAdapter, record: Any, selector: str) -> list[Any]:
    rel_sel = _normalize_relative_selector(adapter, selector)
    matches = adapter.select(record, rel_sel)
    subtree_ids = {adapter.get_identity(n) for n in adapter.iter_subtree(record)}
    return [m for m in matches if adapter.is_attached(m) and adapter.get_identity(m) in subtree_ids]


def _extract_qi_tuple(
    adapter: FormatAdapter,
    record: Any,
    qis: list[QuasiIdentifier],
) -> QITuple:
    values: list[str] = []
    for qi in qis:
        matches = _select_qi_nodes(adapter, record, qi.selector)
        if matches:
            raw = adapter.get_value(matches[0])
            values.append("*" if raw is None else str(raw))
        else:
            values.append("*")
    return tuple(values)


def _group_by_qi(
    adapter: FormatAdapter,
    records: list[Any],
    qis: list[QuasiIdentifier],
) -> dict[QITuple, list[Any]]:
    groups: dict[QITuple, list[Any]] = {}
    for record in records:
        if not adapter.is_attached(record):
            continue
        key = _extract_qi_tuple(adapter, record, qis)
        groups.setdefault(key, []).append(record)
    return groups


def _format_violations(groups: dict[QITuple, list[Any]], k: int) -> list[dict[str, Any]]:
    return [
        {"qi_values": list(key), "count": len(members)}
        for key, members in groups.items()
        if len(members) < k
    ]


def enforce_k_anonymity(
    adapter: FormatAdapter,
    tree: Any,
    policy: MaskingPolicy,
    *,
    role: str | None = None,
    mode: ExecutionMode = "mask",
) -> KAnonReport | None:
    """Verify or enforce *policy.k_anonymity* across subject records in *tree*."""
    cfg = policy.k_anonymity
    if cfg is None or not cfg.enabled or is_role_passthrough(policy, role):
        return None

    k = cfg.k
    qis = cfg.quasi_identifiers
    levels: dict[str, int] = {qi.selector: 0 for qi in qis}

    record_selectors = (
        policy.record_root if isinstance(policy.record_root, list) else [policy.record_root]
    )
    records: list[Any] = []
    seen_record_ids: set[int] = set()
    for sel in record_selectors:
        for rec in adapter.select(tree, sel):
            rec_id = adapter.get_identity(rec)
            if rec_id not in seen_record_ids and adapter.is_attached(rec):
                seen_record_ids.add(rec_id)
                records.append(rec)

    if not records:
        return KAnonReport(
            achieved=True,
            iterations=0,
            violating_classes=[],
            final_qi_levels=levels,
            suppressed_records=0,
            total_records=0,
        )

    groups = _group_by_qi(adapter, records, qis)
    violations = _format_violations(groups, k)

    # Dry-run and verify strategies never mutate or suppress records
    if mode == "dry_run" or cfg.strategy == "verify":
        return KAnonReport(
            achieved=len(violations) == 0,
            iterations=1,
            violating_classes=violations,
            final_qi_levels=levels,
            suppressed_records=0,
            total_records=len(records),
        )

    # Direct outlier suppression strategy
    if cfg.strategy == "suppress":
        suppressed = 0
        for _key, members in groups.items():
            if len(members) < k:
                for rec in members:
                    adapter.remove_node(rec)
                    suppressed += 1
        remaining = [r for r in records if adapter.is_attached(r)]
        return KAnonReport(
            achieved=True,
            iterations=1,
            violating_classes=[],
            final_qi_levels=levels,
            suppressed_records=suppressed,
            total_records=len(remaining),
        )

    # Full-domain iterative generalization (Datafly / Samarati heuristic)
    hierarchies: dict[str, Hierarchy] = {
        qi.selector: get_hierarchy(qi.hierarchy) for qi in qis if qi.hierarchy is not None
    }
    max_levels: dict[str, int] = {
        qi.selector: (
            qi.max_level if qi.max_level is not None else hierarchies[qi.selector].max_level
        )
        for qi in qis
        if qi.selector in hierarchies
    }

    # Snapshot original QI node values so higher generalization levels always generalize
    # from the initial post-Phase-3 domain value rather than an intermediate string.
    original_qi_values: dict[tuple[int, str], list[tuple[Any, str]]] = {}
    for rec in records:
        rec_id = adapter.get_identity(rec)
        for qi in qis:
            if qi.selector not in hierarchies:
                continue
            nodes = _select_qi_nodes(adapter, rec, qi.selector)
            saved: list[tuple[Any, str]] = []
            for n in nodes:
                val = adapter.get_value(n)
                if val is not None:
                    saved.append((n, str(val)))
            original_qi_values[(rec_id, qi.selector)] = saved

    iterations = 1
    while violations:
        candidates: list[tuple[int, float, int, QuasiIdentifier]] = []
        for idx, qi in enumerate(qis):
            sel = qi.selector
            if sel not in hierarchies:
                continue
            cur_lvl = levels[sel]
            cap_lvl = max_levels[sel]
            if cur_lvl >= cap_lvl:
                continue

            distinct_vals = {key[idx] for key in groups}
            rel_progress = cur_lvl / cap_lvl if cap_lvl > 0 else 1.0
            # Prefer highest cardinality attribute first, then least generalized so far
            candidates.append((len(distinct_vals), -rel_progress, -idx, qi))

        if not candidates:
            break

        candidates.sort(reverse=True)
        chosen_qi = candidates[0][3]
        chosen_sel = chosen_qi.selector
        new_level = levels[chosen_sel] + 1
        levels[chosen_sel] = new_level
        hierarchy = hierarchies[chosen_sel]
        iterations += 1

        for rec in records:
            if not adapter.is_attached(rec):
                continue
            rec_id = adapter.get_identity(rec)
            for node, orig_text in original_qi_values.get((rec_id, chosen_sel), []):
                if not adapter.is_attached(node):
                    continue
                try:
                    gen_val = hierarchy.generalize(orig_text, new_level)
                except ValueError:
                    gen_val = "*"
                adapter.set_value(node, gen_val)

        groups = _group_by_qi(adapter, records, qis)
        violations = _format_violations(groups, k)

    suppressed = 0
    if violations and cfg.on_unresolved == "suppress":
        for _key, members in groups.items():
            if len(members) < k:
                for rec in members:
                    adapter.remove_node(rec)
                    suppressed += 1
        groups = _group_by_qi(adapter, records, qis)
        violations = _format_violations(groups, k)

    remaining = [r for r in records if adapter.is_attached(r)]
    return KAnonReport(
        achieved=len(violations) == 0,
        iterations=iterations,
        violating_classes=violations,
        final_qi_levels=levels,
        suppressed_records=suppressed,
        total_records=len(remaining),
    )
