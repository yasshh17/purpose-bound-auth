"""Coordinator — trust root for the user's profile. Never calls external
tools directly; only issues tokens, grants approvals, and revokes.
"""

from auth import identity, policy, token

AGENT_ID = "coordinator"


def issue_token(agent_id: str, purpose: str, task_id: str, ttl_seconds: float = 300) -> str:
    target = identity.PERMITTED_PURPOSES.get(agent_id)
    if target is None or purpose not in target.purposes:
        raise ValueError(
            f"cannot issue token: agent '{agent_id}' not permitted for purpose '{purpose}'"
        )
    permission = identity.PURPOSE_PERMISSIONS[purpose]
    return token.issue(
        agent_id=agent_id,
        purpose=purpose,
        allowed_fields=permission.fields,
        allowed_tools=permission.tools,
        task_id=task_id,
        ttl_seconds=ttl_seconds,
    )


def approve(approvals, task_id: str, action: str) -> None:
    approvals.grant(task_id, action)


def revoke(task_id: str) -> None:
    token.revoke(task_id)


def forward_to_agent(target_purpose: str, fields, task_id: str, approvals, audit_log):
    # No token here — the coordinator holds the data directly and is
    # requesting as itself, so this goes straight through policy.check(),
    # which denies it because "coordinator" is never registered for any
    # purpose but "orchestration".
    decision, reason = policy.check(
        AGENT_ID, target_purpose, fields, "forward_to_agent", task_id, approvals
    )
    audit_log.record(
        task_id=task_id, agent_id=AGENT_ID, purpose=target_purpose,
        fields=fields, tool="forward_to_agent", decision=decision, reason=reason,
    )
    return decision, reason
