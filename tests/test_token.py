"""Tests for auth.token: signing, expiry, revocation, and fail-closed
handling of malformed input."""

import base64
import json
import time
import unittest

from auth import token


class TokenTests(unittest.TestCase):
    def setUp(self):
        token._reset_for_tests()

    def tearDown(self):
        token._reset_for_tests()

    def _issue(self, **overrides):
        kwargs = dict(
            agent_id="flight_search",
            purpose="search_flights",
            allowed_fields=["origin", "destination"],
            allowed_tools=["search_flights_api"],
            task_id="task-1",
            ttl_seconds=300,
        )
        kwargs.update(overrides)
        return token.issue(**kwargs)

    def _forge(self, payload: dict) -> str:
        # A correctly-signed token around an arbitrary payload, to test
        # claim-shape validation in isolation from signature verification.
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        signature = token._sign(payload_b64.encode("ascii"))
        return f"{payload_b64}.{signature}"

    def test_valid_token_round_trips(self):
        token_str = self._issue()
        payload = token.validate(token_str)
        self.assertEqual(payload["agent_id"], "flight_search")
        self.assertEqual(payload["task_id"], "task-1")

    def test_expired_token_denied(self):
        token_str = self._issue(ttl_seconds=-1)
        with self.assertRaises(token.TokenError):
            token.validate(token_str)

    def test_revoked_token_denied(self):
        token_str = self._issue(task_id="task-revoke")
        token.revoke("task-revoke")
        with self.assertRaises(token.TokenError):
            token.validate(token_str)

    def test_tampered_signature_denied(self):
        token_str = self._issue()
        payload_b64, signature = token_str.rsplit(".", 1)
        tampered = f"{payload_b64}.{'0' * len(signature)}"
        with self.assertRaises(token.TokenError):
            token.validate(tampered)

    def test_tampered_payload_denied(self):
        # Payload edited (widened allowed_fields) but signature kept as-is.
        token_str = self._issue()
        payload_b64, signature = token_str.rsplit(".", 1)
        raw = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")))
        raw["allowed_fields"] = ["payment_token"]
        forged_b64 = base64.urlsafe_b64encode(json.dumps(raw).encode("utf-8")).decode("ascii")
        forged = f"{forged_b64}.{signature}"
        with self.assertRaises(token.TokenError):
            token.validate(forged)

    def test_malformed_token_missing_separator(self):
        with self.assertRaises(token.TokenError):
            token.validate("not-a-token-at-all")

    def test_malformed_token_bad_base64(self):
        with self.assertRaises(token.TokenError):
            token.validate("not!valid!base64.deadbeef")

    def test_malformed_token_bad_json(self):
        garbage_b64 = base64.urlsafe_b64encode(b"not json").decode("ascii")
        signature = token._sign(garbage_b64.encode("ascii"))
        with self.assertRaises(token.TokenError):
            token.validate(f"{garbage_b64}.{signature}")

    def test_malformed_token_non_object_json(self):
        payload_b64 = base64.urlsafe_b64encode(json.dumps([1, 2, 3]).encode("utf-8")).decode("ascii")
        signature = token._sign(payload_b64.encode("ascii"))
        with self.assertRaises(token.TokenError):
            token.validate(f"{payload_b64}.{signature}")

    def test_missing_claim_denied(self):
        payload = {
            "agent_id": "flight_search",
            "allowed_fields": ["origin"],
            "allowed_tools": [],
            "purpose": "search_flights",
            "expires_at": time.time() + 300,
            # task_id omitted
        }
        with self.assertRaises(token.TokenError):
            token.validate(self._forge(payload))

    def test_wrong_claim_types_denied(self):
        base_payload = dict(
            agent_id="flight_search",
            allowed_fields=["origin"],
            allowed_tools=[],
            purpose="search_flights",
            expires_at=time.time() + 300,
            task_id="task-1",
        )
        bad_overrides = [
            {"expires_at": "soon"},
            {"expires_at": float("nan")},
            {"expires_at": True},
            {"allowed_fields": "origin"},
            {"allowed_fields": [1, 2]},
            {"allowed_tools": {"search_flights_api": True}},
            {"agent_id": ""},
            {"agent_id": 123},
            {"task_id": 123},
            {"purpose": None},
        ]
        for override in bad_overrides:
            with self.subTest(override=override):
                payload = {**base_payload, **override}
                with self.assertRaises(token.TokenError):
                    token.validate(self._forge(payload))

    def test_non_string_token_denied(self):
        with self.assertRaises(token.TokenError):
            token.validate(None)

    def test_empty_string_token_denied(self):
        with self.assertRaises(token.TokenError):
            token.validate("")


if __name__ == "__main__":
    unittest.main()
