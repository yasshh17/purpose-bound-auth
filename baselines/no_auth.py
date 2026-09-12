"""Baseline: no authorization layer. Every request succeeds, no checks."""


def check(agent_id, requested_purpose, requested_fields, requested_tool, task_id, approvals):
    return True, "no_auth: all requests allowed, no checks performed"
