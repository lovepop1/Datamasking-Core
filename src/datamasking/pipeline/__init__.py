"""Four-phase AST compilation and masking pipeline."""

from __future__ import annotations

from datamasking.pipeline.kanon import KAnonReport, enforce_k_anonymity
from datamasking.pipeline.phase0_scope import ScopeDecision, ScopePlan, evaluate_scopes
from datamasking.pipeline.phase1_index import (
    CoverageIndex,
    RuleIndex,
    UnmatchedIndex,
    build_index,
)
from datamasking.pipeline.phase2_conflict import (
    ConflictLog,
    DecisionIndex,
    resolve_conflicts,
    score_selector,
)
from datamasking.pipeline.phase3_apply import CoverageLog, ExecutionMode, apply_masking
from datamasking.pipeline.runner import PipelineResult, run_pipeline

__all__ = [
    "ConflictLog",
    "CoverageIndex",
    "CoverageLog",
    "DecisionIndex",
    "ExecutionMode",
    "KAnonReport",
    "PipelineResult",
    "RuleIndex",
    "ScopeDecision",
    "ScopePlan",
    "UnmatchedIndex",
    "apply_masking",
    "build_index",
    "enforce_k_anonymity",
    "evaluate_scopes",
    "resolve_conflicts",
    "run_pipeline",
    "score_selector",
]
