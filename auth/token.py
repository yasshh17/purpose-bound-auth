"""Short-lived signed tokens (plain HMAC-signed JSON — no JWT infra needed).

Prototype scope: `_SECRET_KEY` is random and per-process, and
`_REVOKED_TASK_IDS` is a plain in-memory set. Fine for a single-process
prototype, but a restart forgets every revocation and invalidates every
outstanding token. A real deployment needs a persisted/rotated key and a
shared revocation store.
"""

import base64
import hashlib
import hmac
import json
import math
import secrets
import time

_SECRET_KEY = secrets.token_bytes(32)

_REVOKED_TASK_IDS: set[str] = set()

_REQUIRED_CLAIMS = (
    "agent_id",
    "allowed_fields",
    "allowed_tools",
    "purpose",
    "expires_at",
    "task_id",
)
_STRING_CLAIMS = ("agent_id", "purpose", "task_id")
_STRING_LIST_CLAIMS = ("allowed_fields", "allowed_tools")


class TokenError(Exception):
    pass


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


def _validate_claim_shapes(payload) -> None:
    if not isinstance(payload, dict):
        raise TokenError(
            f"malformed token payload: expected a JSON object, got {type(payload).__name__}"
        )

    for claim in _REQUIRED_CLAIMS:
        if claim not in payload:
            raise TokenError(f"malformed token payload: missing claim '{claim}'")

    for claim in _STRING_CLAIMS:
        value = payload[claim]
        if not isinstance(value, str) or not value:
            raise TokenError(
                f"malformed token payload: claim '{claim}' must be a non-empty string"
            )

    for claim in _STRING_LIST_CLAIMS:
        value = payload[claim]
        if not isinstance(value, list):
            raise TokenError(f"malformed token payload: claim '{claim}' must be a list")
        for element in value:
            if not isinstance(element, str) or not element:
                raise TokenError(
                    f"malformed token payload: claim '{claim}' must contain only "
                    "non-empty strings"
                )

    expires_at = payload["expires_at"]
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
        raise TokenError("malformed token payload: claim 'expires_at' must be numeric")
    if not math.isfinite(expires_at):
        raise TokenError(
            "malformed token payload: claim 'expires_at' must be a finite number"
        )


def validate(token_str: str) -> dict:
    if not isinstance(token_str, str) or not token_str:
        raise TokenError("malformed token: expected a non-empty string")

    try:
        payload_b64_str, signature = token_str.rsplit(".", 1)
    except ValueError:
        raise TokenError("malformed token: missing signature separator")

    if not payload_b64_str or not signature:
        raise TokenError("malformed token: empty payload or signature segment")

    try:
        payload_b64 = payload_b64_str.encode("ascii")
    except UnicodeEncodeError:
        raise TokenError("malformed token: payload segment is not valid ASCII")

    expected_signature = _sign(payload_b64)
    if not hmac.compare_digest(signature, expected_signature):
        raise TokenError("invalid signature: token tampered or forged")

    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        # ValueError also catches binascii.Error and json.JSONDecodeError,
        # both subclasses of it.
        raise TokenError(f"malformed token payload: {exc}")

    _validate_claim_shapes(payload)

    if payload["task_id"] in _REVOKED_TASK_IDS:
        raise TokenError(f"token revoked for task '{payload['task_id']}'")

    if time.time() >= payload["expires_at"]:
        raise TokenError(f"token expired for task '{payload['task_id']}'")

    return payload


def revoke(task_id: str) -> None:
    _REVOKED_TASK_IDS.add(task_id)


def is_revoked(task_id: str) -> bool:
    return task_id in _REVOKED_TASK_IDS


def _reset_for_tests() -> None:
    _REVOKED_TASK_IDS.clear()
