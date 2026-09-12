"""Baseline 1: no authorization layer. Every request succeeds, no checks.

Same call signature as auth.policy.check() so run_experiment.py can swap
conditions with one parameter.
"""


def check(agent_id, requested_purpose, requested_fields, requested_tool, task_id, approvals):
    return True, "no_auth: all requests allowed, no checks performed"
