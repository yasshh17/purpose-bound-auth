"""Payment agent — validate token, check policy, log. Nothing else."""

from auth import policy, token

AGENT_ID = "payment"


def request(token_str: str, fields, tool, task_id: str, approvals, audit_log):
    try:
        payload = token.validate(token_str)
    except token.TokenError as exc:
        decision, reason, purpose = False, str(exc), None
        audit_log.record(
            task_id=task_id, agent_id=AGENT_ID, purpose=purpose,
            fields=fields, tool=tool, decision=decision, reason=reason,
        )
        return decision, reason

    purpose = payload["purpose"]
    if payload["agent_id"] != AGENT_ID:
        decision, reason = False, (
            f"token issued to '{payload['agent_id']}', not '{AGENT_ID}'"
        )
    elif payload["task_id"] != task_id:
        decision, reason = False, (
            f"token issued for task '{payload['task_id']}', not '{task_id}'"
        )
    elif not set(fields).issubset(payload["allowed_fields"]) or (
        tool is not None and tool not in payload["allowed_tools"]
    ):
        decision, reason = False, "requested field/tool exceeds token grant"
    else:
        decision, reason = policy.check(
            AGENT_ID, purpose, fields, tool, task_id, approvals
        )

    audit_log.record(
        task_id=task_id, agent_id=AGENT_ID, purpose=purpose,
        fields=fields, tool=tool, decision=decision, reason=reason,
    )
    return decision, reason
