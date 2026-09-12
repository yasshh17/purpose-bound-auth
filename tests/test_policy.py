"""Direct tests of auth.policy.check(), independent of tokens or agent
wrappers."""

import unittest

from agents import coordinator
from auth import policy
from auth.audit import AuditLog


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.approvals = policy.ApprovalRegistry()

    def test_unknown_agent_denied(self):
        decision, reason = policy.check(
            "ghost_agent", "search_flights", ("origin",), None, "task-1", self.approvals,
        )
        self.assertFalse(decision)
        self.assertIn("unknown agent", reason)

    def test_unknown_purpose_denied(self):
        decision, reason = policy.check(
            "flight_search", "steal_data", ("origin",), None, "task-1", self.approvals,
        )
        self.assertFalse(decision)

    def test_unknown_field_denied(self):
        decision, reason = policy.check(
            "flight_search", "search_flights", ("not_a_real_field",), None,
            "task-1", self.approvals,
        )
        self.assertFalse(decision)

    def test_unauthorized_tool_denied(self):
        decision, reason = policy.check(
            "flight_search", "search_flights", ("origin",), "charge_payment_api",
            "task-1", self.approvals,
        )
        self.assertFalse(decision)

    def test_empty_field_request_allowed(self):
        decision, reason = policy.check(
            "flight_search", "search_flights", (), None, "task-1", self.approvals,
        )
        self.assertTrue(decision, reason)

    def test_duplicate_field_request_allowed(self):
        decision, reason = policy.check(
            "flight_search", "search_flights",
            ("origin", "origin", "destination"), None, "task-1", self.approvals,
        )
        self.assertTrue(decision, reason)

    def test_purpose_scoped_forwarding_denied(self):
        # Coordinator holds every field but is only registered for
        # 'orchestration', so it can't forward as another agent's purpose.
        decision, reason = coordinator.forward_to_agent(
            "search_flights", ("payment_token",), "task-forward", self.approvals, AuditLog(),
        )
        self.assertFalse(decision, reason)


if __name__ == "__main__":
    unittest.main()
