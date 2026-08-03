"""Deterministic promotion gate for human-governed Artemis improvements.

This module intentionally does not train or deploy models.  It converts immutable
evaluation and approval records into a reproducible promotion decision that an
Apollo deployment pipeline can enforce.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import json
from typing import Iterable, Mapping


class PromotionDecision(StrEnum):
    PROMOTE = "promote"
    REJECT = "reject"


@dataclass(frozen=True)
class CandidateChange:
    candidate_id: str
    artifact_digest: str
    baseline_version: str
    change_type: str
    risk_tier: int


@dataclass(frozen=True)
class Evaluation:
    suite: str
    passed: bool
    precision_delta: float
    recall_delta: float
    latency_delta_ms: float
    policy_violations: int = 0


@dataclass(frozen=True)
class Approval:
    approver_id: str
    role: str
    candidate_id: str
    artifact_digest: str


@dataclass(frozen=True)
class DecisionRecord:
    decision: PromotionDecision
    reasons: tuple[str, ...]
    evidence_digest: str


class ImprovementController:
    """Fail-closed gate: candidates can propose changes but cannot approve them."""

    def __init__(
        self,
        *,
        required_suites: Iterable[str],
        minimum_precision_delta: float = 0.0,
        maximum_latency_delta_ms: float = 50.0,
        approvals_by_risk: Mapping[int, int] | None = None,
    ) -> None:
        self.required_suites = frozenset(required_suites)
        self.minimum_precision_delta = minimum_precision_delta
        self.maximum_latency_delta_ms = maximum_latency_delta_ms
        self.approvals_by_risk = dict(approvals_by_risk or {1: 1, 2: 2, 3: 2})

    def decide(
        self,
        candidate: CandidateChange,
        evaluations: Iterable[Evaluation],
        approvals: Iterable[Approval],
    ) -> DecisionRecord:
        evals = tuple(evaluations)
        approvals = tuple(approvals)
        reasons: list[str] = []

        observed = {evaluation.suite for evaluation in evals}
        missing = sorted(self.required_suites - observed)
        if missing:
            reasons.append(f"missing evaluation suites: {', '.join(missing)}")
        if any(not evaluation.passed for evaluation in evals):
            reasons.append("one or more evaluation suites failed")
        if any(evaluation.policy_violations for evaluation in evals):
            reasons.append("policy violation detected")
        if any(
            evaluation.precision_delta < self.minimum_precision_delta
            for evaluation in evals
        ):
            reasons.append("precision regression exceeds threshold")
        if any(
            evaluation.latency_delta_ms > self.maximum_latency_delta_ms
            for evaluation in evals
        ):
            reasons.append("latency regression exceeds threshold")

        valid_approvers = {
            approval.approver_id
            for approval in approvals
            if approval.candidate_id == candidate.candidate_id
            and approval.artifact_digest == candidate.artifact_digest
            and approval.role in {"mission_owner", "model_risk", "security"}
        }
        required = self.approvals_by_risk.get(candidate.risk_tier)
        if required is None:
            reasons.append("unknown risk tier")
        elif len(valid_approvers) < required:
            reasons.append(f"requires {required} independent approvals")

        payload = {
            "candidate": asdict(candidate),
            "evaluations": [asdict(item) for item in evals],
            "approvals": [asdict(item) for item in approvals],
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        decision = PromotionDecision.REJECT if reasons else PromotionDecision.PROMOTE
        return DecisionRecord(decision, tuple(reasons), digest)
