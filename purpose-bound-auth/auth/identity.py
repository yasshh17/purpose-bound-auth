"""Static identity + permission config (spec Section 2's scenario table).

Not learned, not dynamic — this is deliberately just data. Two registries:

- PERMITTED_PURPOSES: agent_id -> role -> list of purposes that agent may request.
- PURPOSE_PERMISSIONS: purpose -> declared field set / tool set / whether the
  purpose gates on explicit per-task approval.

`policy.py` reads both but owns neither — keeps the policy engine as pure
decision logic over config it's handed (see plan ambiguity #2).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentIdentity:
    role: str
    purposes: frozenset


@dataclass(frozen=True)
class PurposePermission:
    fields: frozenset
    tools: frozenset
    requires_approval: bool = False


PERMITTED_PURPOSES: dict[str, AgentIdentity] = {
    "coordinator": AgentIdentity(
        role="coordinator",
        purposes=frozenset({"orchestration"}),
    ),
    "flight_search": AgentIdentity(
        role="flight_search",
        purposes=frozenset({"search_flights"}),
    ),
    "payment": AgentIdentity(
        role="payment",
        purposes=frozenset({"process_payment"}),
    ),
}

# NOTE: keyed globally by purpose, not per-agent. This is only correct
# because this scenario has a strict 1:1 mapping between purposes and
# agents (orchestration -> coordinator, search_flights -> flight_search,
# process_payment -> payment) — see PERMITTED_PURPOSES above. If a future
# scenario ever lets two agents share one purpose with different field
# grants (e.g. two payment-like agents both requesting "process_payment"
# but scoped to different fields), this global keying breaks and
# PURPOSE_PERMISSIONS must be re-keyed by (agent_id, purpose) instead.
PURPOSE_PERMISSIONS: dict[str, PurposePermission] = {
    "orchestration": PurposePermission(
        # Coordinator holds the full profile as source of truth; it never
        # calls external tools directly (spec Sec. 2), so no tools are
        # granted here even though its field view is unrestricted.
        fields=frozenset(
            {
                "origin",
                "destination",
                "dates",
                "passenger_count",
                "name",
                "address",
                "phone",
                "email",
                "passport_number",
                "payment_token",
            }
        ),
        tools=frozenset(),
        requires_approval=False,
    ),
    "search_flights": PurposePermission(
        fields=frozenset({"origin", "destination", "dates", "passenger_count"}),
        tools=frozenset({"search_flights_api"}),
        requires_approval=False,
    ),
    "process_payment": PurposePermission(
        fields=frozenset({"payment_token"}),
        tools=frozenset({"charge_payment_api"}),
        requires_approval=True,
    ),
}

# Actions requiring explicit coordinator approval for the specific task
# instance (policy check (c)). Sourced from PURPOSE_PERMISSIONS above, kept
# as an explicit derived set so policy.py can check it directly.
REQUIRES_APPROVAL: frozenset = frozenset(
    purpose
    for purpose, perm in PURPOSE_PERMISSIONS.items()
    if perm.requires_approval
)

# Enforce the 1:1 purpose<->agent assumption above at import time, so a
# future edit that violates it fails loudly here instead of silently
# corrupting field grants via the global PURPOSE_PERMISSIONS keying.
def _assert_one_agent_per_purpose() -> None:
    owners: dict[str, str] = {}
    for agent_id, identity in PERMITTED_PURPOSES.items():
        for purpose in identity.purposes:
            if purpose in owners:
                raise AssertionError(
                    f"purpose '{purpose}' is claimed by both '{owners[purpose]}' "
                    f"and '{agent_id}' — PURPOSE_PERMISSIONS is keyed globally "
                    "by purpose and assumes exactly one agent per purpose; "
                    "re-key it by (agent_id, purpose) before adding this."
                )
            owners[purpose] = agent_id


_assert_one_agent_per_purpose()
