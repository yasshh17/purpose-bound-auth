"""Static identity + permission config. Two registries:

- PERMITTED_PURPOSES: agent_id -> role -> purposes that agent may request.
- PURPOSE_PERMISSIONS: purpose -> declared field set / tool set / whether
  it gates on explicit per-task approval.
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

# Keyed globally by purpose, not (agent_id, purpose) -- only correct while
# each purpose has exactly one owning agent (enforced below). Two agents
# sharing a purpose with different field grants would need re-keying.
PURPOSE_PERMISSIONS: dict[str, PurposePermission] = {
    "orchestration": PurposePermission(
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

REQUIRES_APPROVAL: frozenset = frozenset(
    purpose
    for purpose, perm in PURPOSE_PERMISSIONS.items()
    if perm.requires_approval
)


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
