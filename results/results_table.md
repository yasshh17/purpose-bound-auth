# Results Table

## Correctness (primary)

| Condition | Unauthorized disclosures blocked | Legitimate requests incorrectly denied | Task completion (case 8) | Injection case (6) |
|---|---|---|---|---|
| no_auth | 0/20 | 0/15 | 5/5 (100%) | NOT BLOCKED (0/5 denied) |
| role_based | 10/20 | 0/15 | 5/5 (100%) | BLOCKED (5/5 denied) |
| purpose_bound | 20/20 | 0/15 | 5/5 (100%) | BLOCKED (5/5 denied) |

These counts are deterministic — every rerun of the 120-run harness (8 cases × 3 conditions × 5 repeats) reproduces exactly these numbers, since they are outcomes of fixed decision logic, not timings. **This table is a conformance check against previously hand-verified expected outcomes, not an independent empirical measurement of the hypothesis** — see `docs/experiment-protocol.md` Section 4 for why that distinction matters, and what the 8-case design does and doesn't prove.

**Note on case 6 (prompt injection):** `role_based` also blocks the injected request, denying it for the same reason it denies case 2 — the demanded fields (`passport_number`, `payment_token`) fall outside `flight_search`'s static role field set, independent of purpose. **This should not be read as purpose-bound's unique advantage:** on this specific attack, a coarser role check happens to produce the same outcome, because the injected fields are outside *any* purpose flight_search could plausibly claim. Purpose-bound's actual distinguishing outcomes are cases 3 (approval gating, which role-based has no concept of) and 5 (purpose-scoped forwarding, which this role-based implementation cannot express because it only checks the acting role's own field access — see `docs/experiment-protocol.md` Section 2 for why case 5's result is a property of this specific coordinator-to-recipient purpose model, not a proof that every RBAC design would fail it). `no_auth` fails to block the injection, as it fails to block everything.

## Timing (supplementary)

| Condition | Auth-check latency — median [p10, p90] µs | Case-8 total latency — median [p10, p90] µs | Token/policy overhead vs no_auth — median delta, µs |
|---|---|---|---|
| no_auth | 0.13 [0.08, 0.17] | 2.54 [2.50, 2.67] | +0.00 |
| role_based | 0.33 [0.29, 0.38] | 3.17 [3.08, 3.25] | +0.62 |
| purpose_bound | 0.54 [0.38, 0.63] | 49.08 [47.72, 52.70] | +46.54 |

**This section is supplementary and should not be quoted as a production-latency claim.** All figures are local, in-memory, single-process Python timings (20 discarded warm-up iterations followed by 101 measured repeats per figure; the bracketed range is the [p10, p90] spread across those repeats — a variability measure, not a confidence interval). They shift somewhat on every rerun even with warm-up and 101 repeats, because they are dominated by interpreter/OS scheduling noise at microsecond scale, not by anything architecturally meaningful.

**The three conditions do not execute identical pipelines, so this is not an apples-to-apples microbenchmark of one code path under three policies.** `purpose_bound`'s case-8 total includes real HMAC token issuance and verification, the agent request wrappers, `policy.check()`, and audit logging on every step. Both baselines skip token issuance/verification and the agent wrapper entirely, calling a single direct `check()` function instead. The auth-check column isolates `policy.check()`/baseline `check()` alone (no token issuance, agent wrapper, or audit logging, for any condition) so its three numbers are comparable to each other; the case-8 column is each condition's full real pipeline end-to-end, so its numbers are NOT comparable to the auth-check column, and the difference between the two columns for `purpose_bound` is itself informative (it isolates roughly what token issuance and verification cost on top of the decision logic). Token/policy overhead is computed from the case-8 total delta against `no_auth`, not the isolated auth-check delta, because the isolated call excludes token cost for every condition by construction — a delta computed from it would silently omit the token layer this metric is named for. Read the *relative* ordering (no_auth ≤ role_based ≪ purpose_bound on case-8 total, attributable to real HMAC signing/verification per step) as the qualitative finding, not the absolute microsecond values.
