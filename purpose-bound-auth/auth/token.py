"""Short-lived signed tokens (plain HMAC-signed JSON — no JWT infra needed).

Token payload carries exactly the six fields the spec names:
agent_id, allowed_fields, allowed_tools, purpose, expires_at, task_id.

Validated on every simulated tool call / inter-agent handoff. Expired or
revoked tokens fail closed (raise, never silently downgrade to a partial
grant).
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

# Per-process secret. Regenerated each run — no distributed state needed
# per spec Phase 3 ("in-memory revocation list is fine").
_SECRET_KEY = secrets.token_bytes(32)

_REVOKED_TASK_IDS: set[str] = set()


class TokenError(Exception):
    """Raised on any validation failure — expired, revoked, or tampered."""


def _sign(payload_b64: bytes) -> str:
    return hmac.new(_SECRET_KEY, payload_b64, hashlib.sha256).hexdigest()


def issue(
    agent_id: str,
    purpose: str,
    allowed_fields,
    allowed_tools,
    task_id: str,
    ttl_seconds: float,
) -> str:
    """Issue a short-lived signed token. Returns 'base64(json).hex_hmac'."""
    payload = {
        "agent_id": agent_id,
        "allowed_fields": sorted(allowed_fields),
        "allowed_tools": sorted(allowed_tools),
        "purpose": purpose,
        "expires_at": time.time() + ttl_seconds,
        "task_id": task_id,
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
    signature = _sign(payload_b64)
    return f"{payload_b64.decode('ascii')}.{signature}"


def validate(token_str: str) -> dict:
    """Validate signature, expiry, and revocation. Raises TokenError on any
    failure — fails closed, never returns a partial/degraded payload."""
    try:
        payload_b64_str, signature = token_str.rsplit(".", 1)
    except ValueError:
        raise TokenError("malformed token: missing signature separator")

    payload_b64 = payload_b64_str.encode("ascii")
    expected_signature = _sign(payload_b64)
    if not hmac.compare_digest(signature, expected_signature):
        raise TokenError("invalid signature: token tampered or forged")

    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise TokenError(f"malformed token payload: {exc}")

    if payload["task_id"] in _REVOKED_TASK_IDS:
        raise TokenError(f"token revoked for task '{payload['task_id']}'")

    if time.time() >= payload["expires_at"]:
        raise TokenError(f"token expired for task '{payload['task_id']}'")

    return payload


def revoke(task_id: str) -> None:
    """Coordinator invalidates an in-flight token. Subsequent validate()
    calls for this task_id fail immediately (in-memory set, no distributed
    state needed)."""
    _REVOKED_TASK_IDS.add(task_id)


def is_revoked(task_id: str) -> bool:
    return task_id in _REVOKED_TASK_IDS


def _reset_for_tests() -> None:
    """Test-only helper: clear revocation state between hand-verification
    runs so cases don't bleed into each other."""
    _REVOKED_TASK_IDS.clear()
