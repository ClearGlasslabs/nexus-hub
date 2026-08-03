import unittest

from artemis.improvement import (
    Approval,
    CandidateChange,
    Evaluation,
    ImprovementController,
    PromotionDecision,
)


class ImprovementControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = ImprovementController(
            required_suites={"safety", "mission"}, approvals_by_risk={2: 2}
        )
        self.candidate = CandidateChange("c-1", "sha256:abc", "v12", "prompt", 2)
        self.evaluations = [
            Evaluation("safety", True, 0.0, 0.0, 10.0),
            Evaluation("mission", True, 0.03, 0.02, 20.0),
        ]

    def approval(self, user: str, digest: str = "sha256:abc") -> Approval:
        return Approval(user, "mission_owner", "c-1", digest)

    def test_promotes_only_complete_approved_evidence(self) -> None:
        result = self.controller.decide(
            self.candidate,
            self.evaluations,
            [self.approval("alice"), self.approval("bob")],
        )
        self.assertEqual(result.decision, PromotionDecision.PROMOTE)
        self.assertEqual(result.reasons, ())

    def test_rejects_stale_approval_and_policy_violation(self) -> None:
        evaluations = [*self.evaluations, Evaluation("red-team", False, 0, 0, 0, 1)]
        result = self.controller.decide(
            self.candidate,
            evaluations,
            [self.approval("alice"), self.approval("bob", "sha256:old")],
        )
        self.assertEqual(result.decision, PromotionDecision.REJECT)
        self.assertIn("policy violation detected", result.reasons)
        self.assertIn("requires 2 independent approvals", result.reasons)

    def test_decision_digest_is_deterministic(self) -> None:
        args = (self.candidate, self.evaluations, [self.approval("alice")])
        self.assertEqual(
            self.controller.decide(*args).evidence_digest,
            self.controller.decide(*args).evidence_digest,
        )


if __name__ == "__main__":
    unittest.main()
