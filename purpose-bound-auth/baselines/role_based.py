"""Baseline 2: role-based only — checks agent role's static field/tool set,
with no purpose or per-task field restriction and no approval gating.

Same call signature as auth.policy.check() so run_experiment.py can swap
conditions with one parameter. `requested_purpose` and `approvals` are
accepted but deliberately ignored — that's the point of this baseline: it
can't express "payment agent may access payment_token, but only after
approval for this task" or "this field belongs to a different agent's
purpose scope" — it only knows "does this role generally touch this
field/tool," full stop. This is what makes the purpose-bound condition's
advantage visible in the results table.

Role == agent_id in this scenario (each agent has exactly one role), so
this is keyed by agent_id directly rather than introducing a separate role
layer that would just be an alias.
"""

ROLE_FIELDS: dict[str, frozenset] = {
    "coordinator": frozenset(
        {
            "origin", "destination", "dates", "passenger_count",
            "name", "address", "phone", "email",
            "passport_number", "payment_token",
        }
    ),
    "flight_search": frozenset({"origin", "destination", "dates", "passenger_count"}),
    "payment": frozenset({"payment_token"}),
}

ROLE_TOOLS: dict[str, frozenset] = {
    "coordinator": frozenset({"forward_to_agent"}),
    "flight_search": frozenset({"search_flights_api"}),
    "payment": frozenset({"charge_payment_api"}),
}


def check(agent_id, requested_purpose, requested_fields, requested_tool, task_id, approvals):
    allowed_fields = ROLE_FIELDS.get(agent_id)
    if allowed_fields is None:
        return False, f"unknown agent '{agent_id}'"

    for requested_field in requested_fields:
        if requested_field not in allowed_fields:
            return False, (
                f"field '{requested_field}' not in role '{agent_id}''s allowed set"
            )

    allowed_tools = ROLE_TOOLS.get(agent_id, frozenset())
    if requested_tool is not None and requested_tool not in allowed_tools:
        return False, (
            f"tool '{requested_tool}' not in role '{agent_id}''s allowed set"
        )

    return True, "role_based: field/tool within role's static allowed set (no purpose or approval check)"
