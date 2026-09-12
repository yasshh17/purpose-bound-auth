"""Structured user-data object for the travel-booking scenario.

Field split follows spec Section 2's protected-fields list exactly:
sensitive_fields == protected fields (never leave the coordinator except
under explicit authorization).
"""

from dataclasses import dataclass, fields

# Fields flight-search is permitted to request for `search_flights`.
PUBLIC_FIELDS = frozenset({"origin", "destination", "dates", "passenger_count"})

SENSITIVE_FIELDS = frozenset(
    {"name", "address", "phone", "email", "passport_number", "payment_token"}
)


@dataclass(frozen=True)
class UserProfile:
    origin: str
    destination: str
    dates: str
    passenger_count: int

    name: str
    address: str
    phone: str
    email: str
    passport_number: str
    payment_token: str

    public_fields = PUBLIC_FIELDS
    sensitive_fields = SENSITIVE_FIELDS

    def as_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def subset(self, field_names) -> dict:
        """Return only the requested fields, by name, as a plain dict."""
        data = self.as_dict()
        return {name: data[name] for name in field_names if name in data}


def sample_profile() -> UserProfile:
    return UserProfile(
        origin="SFO",
        destination="JFK",
        dates="2026-10-01/2026-10-08",
        passenger_count=1,
        name="Jordan Rivera",
        address="123 Market St, San Francisco, CA",
        phone="+1-555-0100",
        email="jordan.rivera@example.com",
        passport_number="X1234567",
        payment_token="tok_live_abc123",
    )
