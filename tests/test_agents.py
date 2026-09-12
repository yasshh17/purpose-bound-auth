"""Integration tests for the agent request wrappers: token validation,
policy enforcement, and cross-task token binding."""

import unittest

from agents import coordinator, flight_search, payment
from auth import token
from auth.audit import AuditLog
from auth.policy import ApprovalRegistry


class AgentRequestTests(unittest.TestCase):
    def setUp(self):
        token._reset_for_tests()
        self.audit_log = AuditLog()
        self.approvals = ApprovalRegistry()

    def tearDown(self):
        token._reset_for_tests()

    def test_valid_flight_search_request_allowed(self):
        task_id = "task-flight-1"
        token_str = coordinator.issue_token("flight_search", "search_flights", task_id)
        decision, reason = flight_search.request(
            token_str, ("origin", "destination"), "search_flights_api",
            task_id, self.approvals, self.audit_log,
        )
        self.assertTrue(decision, reason)

    def test_prohibited_sensitive_field_denied(self):
        task_id = "task-flight-2"
        token_str = coordinator.issue_token("flight_search", "search_flights", task_id)
        decision, reason = flight_search.request(
            token_str, ("payment_token",), None, task_id, self.approvals, self.audit_log,
        )
        self.assertFalse(decision, reason)

    def test_payment_before_approval_denied(self):
        task_id = "task-pay-1"
        token_str = coordinator.issue_token("payment", "process_payment", task_id)
        decision, reason = payment.request(
            token_str, ("payment_token",), "charge_payment_api",
            task_id, self.approvals, self.audit_log,
        )
        self.assertFalse(decision, reason)

    def test_payment_after_approval_allowed(self):
        task_id = "task-pay-2"
        coordinator.approve(self.approvals, task_id, "process_payment")
        token_str = coordinator.issue_token("payment", "process_payment", task_id)
        decision, reason = payment.request(
            token_str, ("payment_token",), "charge_payment_api",
            task_id, self.approvals, self.audit_log,
        )
        self.assertTrue(decision, reason)

    def test_cross_task_token_reuse_denied(self):
        # Token issued for unapproved task A, presented alongside a
        # different, already-approved task B's id -- must still be denied.
        task_a, task_b = "task-A-unapproved", "task-B-approved"
        coordinator.approve(self.approvals, task_b, "process_payment")
        token_for_a = coordinator.issue_token("payment", "process_payment", task_a)

        decision, reason = payment.request(
            token_for_a, ("payment_token",), "charge_payment_api",
            task_b, self.approvals, self.audit_log,
        )
        self.assertFalse(decision, reason)
        self.assertIn("task", reason)

    def test_token_presented_to_wrong_agent_denied(self):
        task_id = "task-wrong-agent"
        token_str = coordinator.issue_token("flight_search", "search_flights", task_id)
        decision, reason = payment.request(
            token_str, ("payment_token",), "charge_payment_api",
            task_id, self.approvals, self.audit_log,
        )
        self.assertFalse(decision, reason)

    def test_revoked_token_denied(self):
        task_id = "task-revoked"
        coordinator.approve(self.approvals, task_id, "process_payment")
        token_str = coordinator.issue_token("payment", "process_payment", task_id)
        coordinator.revoke(task_id)
        decision, reason = payment.request(
            token_str, ("payment_token",), "charge_payment_api",
            task_id, self.approvals, self.audit_log,
        )
        self.assertFalse(decision, reason)

    def test_approval_revocation_denies_subsequent_request(self):
        task_id = "task-approval-revoked"
        self.approvals.grant(task_id, "process_payment")
        self.approvals.revoke_approval(task_id, "process_payment")
        token_str = coordinator.issue_token("payment", "process_payment", task_id)
        decision, reason = payment.request(
            token_str, ("payment_token",), "charge_payment_api",
            task_id, self.approvals, self.audit_log,
        )
        self.assertFalse(decision, reason)

    def test_malformed_token_denied_without_crash(self):
        decision, reason = payment.request(
            "garbage-token", ("payment_token",), "charge_payment_api",
            "task-x", self.approvals, self.audit_log,
        )
        self.assertFalse(decision)

    def test_injection_case_denied(self):
        task_id = "task-injection"
        token_str = coordinator.issue_token("flight_search", "search_flights", task_id)
        decision, reason = flight_search.attempt_injected_request(
            token_str, task_id, self.approvals, self.audit_log,
        )
        self.assertFalse(decision, reason)

    def test_full_booking_workflow_completes(self):
        task_id = "task-booking"
        flight_token = coordinator.issue_token("flight_search", "search_flights", task_id)
        decision1, reason1 = flight_search.request(
            flight_token, ("origin", "destination", "dates", "passenger_count"),
            "search_flights_api", task_id, self.approvals, self.audit_log,
        )
        self.assertTrue(decision1, reason1)

        coordinator.approve(self.approvals, task_id, "process_payment")
        payment_token = coordinator.issue_token("payment", "process_payment", task_id)
        decision2, reason2 = payment.request(
            payment_token, ("payment_token",), "charge_payment_api",
            task_id, self.approvals, self.audit_log,
        )
        self.assertTrue(decision2, reason2)


if __name__ == "__main__":
    unittest.main()
