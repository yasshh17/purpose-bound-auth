"""Coordinator — trust root for the user's profile.

Holds the full profile as source of truth and never calls external tools
directly (spec Sec. 2: "orchestration only"). Its jobs: issue tokens scoped
to what the *receiving* agent's own identity entry permits, grant per-task
approvals for sensitive actions, revoke tokens mid-task, and — the one
place it does go through the policy layer itself — attempt to forward a
field to another agent's purpose scope (test case 5). No token is needed
for that: the coordinator holds the data directly, but any field leaving
its control must still clear `policy.check()` the same as any other
outbound request.
"""

from auth import identity, policy, token

AGENT_ID = "coordinator"


def issue_token(agent_id: str, purpose: str, task_id: str, ttl_seconds: float = 300) -> str:
    """Issue a token scoped to `agent_id`'s own permitted-purpose grant.

    The coordinator can only issue what the target agent's identity registry
    entry already allows for that purpose — it cannot grant more.
    """
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
    """Grant explicit per-task approval for a sensitive action (e.g. payment)."""
    approvals.grant(task_id, action)


def revoke(task_id: str) -> None:
    """Invalidate an in-flight token for this task, effective immediately."""
    token.revoke(task_id)


def forward_to_agent(target_purpose: str, fields, task_id: str, approvals, audit_log):
    """Attempt to hand `fields` directly to whichever agent owns
    `target_purpose`, bypassing normal token issuance (test case 5).

    The coordinator itself is only ever registered for "orchestration" — it
    has no other purpose in its identity entry — so this is denied at
    policy.check() step (a) regardless of whether the coordinator's own
    field view happens to include the requested fields. No token is used
    here: the coordinator is requesting *as itself*, not presenting a
    credential, so this exercises the policy layer directly.
    """
    decision, reason = policy.check(
        AGENT_ID, target_purpose, fields, "forward_to_agent", task_id, approvals
    )
    audit_log.record(
        task_id=task_id, agent_id=AGENT_ID, purpose=target_purpose,
        fields=fields, tool="forward_to_agent", decision=decision, reason=reason,
    )
    return decision, reason
