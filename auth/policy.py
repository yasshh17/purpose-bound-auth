"""The policy engine. Pure decision logic over static config (auth.identity)
and per-task approval state — no I/O, no token parsing.
"""

from dataclasses import dataclass, field

from auth.identity import PERMITTED_PURPOSES, PURPOSE_PERMISSIONS, REQUIRES_APPROVAL


@dataclass
class ApprovalRegistry:
    _granted: set = field(default_factory=set)

    def grant(self, task_id: str, action: str) -> None:
        self._granted.add((task_id, action))

    def is_granted(self, task_id: str, action: str) -> bool:
        return (task_id, action) in self._granted

    def revoke_approval(self, task_id: str, action: str) -> None:
        self._granted.discard((task_id, action))


def check(
    agent_id: str,
    requested_purpose: str,
    requested_fields,
    requested_tool: str | None,
    task_id: str,
    approvals: ApprovalRegistry,
) -> tuple[bool, str]:
    """Deny-by-default: allow only if purpose, fields/tools, and (where
    required) approval all check out."""

    identity = PERMITTED_PURPOSES.get(agent_id)
    if identity is None:
        return False, f"unknown agent '{agent_id}'"
    if requested_purpose not in identity.purposes:
        return False, (
            f"purpose '{requested_purpose}' not permitted for agent '{agent_id}'"
        )

    permission = PURPOSE_PERMISSIONS.get(requested_purpose)
    if permission is None:
        return False, f"purpose '{requested_purpose}' has no declared permissions"

    for requested_field in requested_fields:
        if requested_field not in permission.fields:
            return False, (
                f"field '{requested_field}' not in allowed set for purpose "
                f"'{requested_purpose}'"
            )

    if requested_tool is not None and requested_tool not in permission.tools:
        return False, (
            f"tool '{requested_tool}' not in allowed set for purpose "
            f"'{requested_purpose}'"
        )

    if requested_purpose in REQUIRES_APPROVAL:
        if not approvals.is_granted(task_id, requested_purpose):
            return False, (
                f"approval not granted for task '{task_id}', "
                f"action '{requested_purpose}'"
            )
        return True, "purpose, fields, and tools authorized; approval confirmed"

    return True, "purpose, fields, and tools authorized"
