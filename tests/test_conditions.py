"""Conformance test: every (case, condition) pair must produce its
documented expected outcome. Same assertion run_experiment.py makes,
as a unit test so `python3 -m unittest discover` alone catches a
regression."""

import unittest

from auth import token
from auth.audit import AuditLog
from experiments.cases import CASES
from experiments.run_experiment import run_case

CONDITIONS = ("no_auth", "role_based", "purpose_bound")


class ConditionMatrixTests(unittest.TestCase):
    def setUp(self):
        token._reset_for_tests()

    def tearDown(self):
        token._reset_for_tests()

    def test_all_cases_match_expected_outcome_per_condition(self):
        for case in CASES:
            for condition in CONDITIONS:
                with self.subTest(case=case.number, condition=condition):
                    task_id = f"unittest-case{case.number}-{condition}"
                    decision, reason = run_case(case, condition, task_id, AuditLog())
                    self.assertEqual(
                        decision, case.expected[condition],
                        f"case {case.number} ({case.description!r}) / {condition}: {reason!r}",
                    )


if __name__ == "__main__":
    unittest.main()
