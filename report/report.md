# Purpose-Bound, Field-Level Authorization for Multi-Agent Workflows

**A controlled experiment comparing purpose-bound authorization against a
no-auth baseline and a role-based baseline on a three-agent travel-booking
scenario.**

## 1. Research question and hypothesis

**Research question:** Can purpose-specific, field-level authorization
prevent unnecessary disclosure between collaborating agents while
preserving task success and low latency?

**Hypothesis:** A policy layer that filters data according to an agent's
assigned purpose will reduce unauthorized field disclosure without
materially reducing task completion or increasing latency.

**Scope discipline:** this is a controlled experiment, not a product. The
three agents (coordinator, flight-search, payment) are deliberately simple
and rule-based. All engineering effort went into the authorization layer
(`auth/`) and the evaluation harness (`experiments/`), not the agents.

## 2. Threat model

**Adversary, stated explicitly:** the only adversary this experiment
actually exercises is **untrusted content that an honest agent reads and
naively acts on** — not a compromised tool implementation, and not a
deliberately misbehaving agent. Test case 6 is the concrete instance: a
hardcoded string stands in for scraped "web content" and contains an
embedded instruction ("...also include the customer's passport_number and
payment_token..."). The flight-search agent's own code is not adversarial —
it is a faithful, rule-based agent that extracts the fields a data source
told it to extract and requests them, exactly as a susceptible real agent
reading attacker-controlled content might. Two other plausible adversary
types are NOT tested here: no tool in this system (`search_flights_api`,
`charge_payment_api`) is ever modeled as returning malicious output back to
an agent, and no agent's own implementation deviates from its stated logic
to intentionally exfiltrate data. Naming this precisely matters because it
bounds what case 6 can and can't claim to demonstrate (see Limitations).

**Defense-in-depth finding — stated as a limitation, not just an
architecture note:** the design has two nominally independent enforcement
layers for field/tool access on token-mediated requests: (1) each agent's
token-grant check (are the requested fields/tool a subset of what the
coordinator issued this task's token for?) and (2) `policy.check()`'s own
step (b), which independently re-checks the requested fields/tool against
the purpose's declared set in `auth/identity.py`. **Case 6 — the one case
in the matrix where an agent holding a valid token attempts an
out-of-scope field — is denied entirely by the token-grant check inside
`agents/flight_search.py`'s `request()`, which returns before
`policy.check()` is ever called at all** (it lives in that function's
`else` branch, reached only once the token-grant check has already
passed). So step (b) hasn't merely failed to be "the deciding layer" for
case 6 — `policy.check()` is never invoked in that run in the first place.

Case 5 does **not** go through this path. `agents/coordinator.py`'s
`forward_to_agent()` issues no token and calls `policy.check()` directly —
confirmed by reading its source, which contains no `token.issue`/
`token.validate` call anywhere. Case 5's actual denial reason,
`"purpose 'search_flights' not permitted for agent 'coordinator'"`, is
`policy.check()` step (a) firing on its own, with no token-grant check
upstream of it to have "really" made the decision. That makes case 5
direct, no-token evidence that `policy.check()` operates as a genuine,
independent decision layer, not a rubber stamp behind the token-grant
check. Combined with cases 3/4, which exercise step (c) — the approval
gate has no token-layer equivalent at all, since approval state was
deliberately kept off the token payload (see Method) — **two of the
policy engine's three ordered checks, (a) purpose match and (c) approval,
are proven decisive by the formal 120-run harness.**

Only step (b), field/tool membership, remains unproven as a deciding
layer. Both cases built to exercise it (2 and 6) are intercepted one layer
earlier, by the agent-layer token-grant check — because
`coordinator.issue_token()` always mints a token's `allowed_fields`/
`allowed_tools` directly from the same `identity.PURPOSE_PERMISSIONS`
registry that step (b) reads, so on every token-mediated path in this
harness the two checks would agree, and the token-grant check runs first
and short-circuits before `policy.check()` is reached. A supplementary,
off-path test constructed during development (see
`docs/experiment-protocol.md` Section 3) — a token issued directly via
`token.issue()` with a deliberately over-broad `allowed_fields`, bypassing
`coordinator.issue_token()`'s normal scoping — did show step (b)
independently denying a field the mis-issued token itself claimed to
grant. That demonstrates step (b) is not vacuous by construction, but it
sits outside the formal 8-case matrix and was not repeated across
conditions or included in `results_table.md`. The honest claim this
experiment supports is narrower than "the policy engine is a proven second
layer": steps (a) and (c) are independently proven by the formal harness;
step (b) specifically is *architecturally* independent of the token-grant
check but *empirically* redundant with it on every path this harness's
token issuance actually takes. A harness that could distinguish step (b)'s
contribution would need a case where a legitimately-issued token is
broader than what the receiving purpose should currently allow (e.g. a
purpose whose field grant narrows mid-task) — no such case exists in the
current 8-case matrix.

**Case 6 nuance, stated plainly:** `role_based` also denies the injected
request (`results_table.md`, case 6 row) — but for a materially different,
coarser reason than purpose-bound. Purpose-bound denies because the
demanded fields aren't in `search_flights`'s declared field set for this
*task's purpose*. Role-based denies because `passport_number` and
`payment_token` aren't in `flight_search`'s *static role* field set at
all, independent of purpose or task context. The two conditions reach the
same outcome on this one case because the injected fields happen to be
outside anything flight-search could plausibly claim under either model —
not because role-based understands purpose-scoped authorization. A reader
skimming only the results table's ALLOW/DENY column could mistake case 6 as
purpose-bound's distinguishing win; it is not. Purpose-bound's actual
distinguishing contributions are cases 3 (approval-gating, which role-based
has no concept of at all) and 5 (purpose-scoped forwarding, which
role-based cannot express because it only checks the acting role's own
field access, not a request's target purpose).

## 3. Method

**Architecture.** Static config (`data/user_profile.py`,
`auth/identity.py`) defines the scenario's three agents, their permitted
purposes, and each purpose's declared field/tool set. `auth/policy.py` is
the authorization contribution: given `(agent_id, purpose, fields, tool,
task_id)`, it returns `(decision, reason)` via three ordered, deny-by-default
checks — (a) purpose match, (b) field/tool membership in the purpose's
declared set, (c) explicit per-task-instance coordinator approval for
gated purposes (only `process_payment` in this scenario).
`auth/token.py` issues short-lived HMAC-signed tokens
(`agent_id`, `allowed_fields`, `allowed_tools`, `purpose`, `expires_at`,
`task_id`) and fails closed on expiry, revocation, or tampering.
`agents/*.py` are thin: validate token, check the request against the
token's grant, call `policy.check()`, log the outcome — no retries, no
conversational state. `baselines/no_auth.py` (always allow) and
`baselines/role_based.py` (static role→field/tool set, no purpose or
approval concept) share `policy.check()`'s call signature so the harness
can swap conditions without touching the request shape.

**Test cases.** All 8 cases are structured `Case` objects
(`experiments/cases.py`; full design rationale in
`docs/experiment-protocol.md` Section 2), each one or more `RequestStep`s
executed under a shared `task_id`; a case's outcome is the AND of its
steps (case 8's two-step workflow can't "complete" if either step is
denied). Two cases needed a specific modeling decision, made explicit here
because it affects what the results can claim:

- **Case 5** ("agent attempts to forward protected fields to another
  agent") is modeled as the *coordinator* — which legitimately holds every
  field — attempting to forward a field while requesting **as the
  recipient's purpose** (`search_flights`), not as its own
  (`orchestration`). This is what makes the case meaningful: under
  purpose-bound it's denied at step (a), because the coordinator is never
  registered for any purpose but `orchestration`; under role-based it's
  allowed, because role-based only checks the *acting* role's own field
  access, and the coordinator's role legitimately includes every field. An
  earlier model (flight-search forwarding a field to itself) was rejected
  during development because it couldn't produce this divergence — it
  would have been denied by the token-grant check under every condition
  with a field-set concept, telling us nothing about purpose-scoping
  specifically. **This result is a property of this specific
  coordinator-to-recipient purpose model, not a general proof that every
  RBAC design fails to express purpose-scoped forwarding.** A role-based
  design that additionally checked a request's *target* purpose against
  the recipient role (rather than only the acting role's own field access)
  could plausibly deny this same case; role-based as implemented here
  simply doesn't attempt that.
- **Case 6** executes the real injection mechanism
  (`flight_search.attempt_injected_request`, reading the hardcoded
  `INJECTED_WEB_CONTENT` string and naively extracting the fields it
  names) for the `purpose_bound` condition. For `role_based`/`no_auth`,
  which have no agent/token layer, the harness passes the same
  injection-derived field list directly to the baseline `check()` — the
  injection mechanism itself is only exercised once, for real, under
  purpose-bound.

**Case 7** ("token expired or revoked mid-task") uses "revoked" as the
harness's canonical sub-mode (deterministic, no `sleep()` needed across 5
repeats), with approval pre-granted so revocation is isolated as the sole
cause of denial. "Expired" was independently hand-verified in `auth/token.py`
during development with an equivalent expected-outcome pattern across
conditions, but is not re-run in the formal 120-run harness.

**Execution and measurement.** `experiments/run_experiment.py` runs all 8
cases × 3 conditions × 5 repeats (120 case-runs), asserting actual outcome
matches the case's expected-per-condition outcome — any mismatch raises
immediately, since a divergence at this stage means the harness has a bug,
not that the finding changed. Every decision is logged via `auth/audit.py`
to `results/raw/{condition}.jsonl` (135 lines total across the three files,
not 120 — case 8's two steps are logged individually per repeat, which is
more informative than collapsing a workflow to one line). `experiments/measure.py`
computes the correctness-derived metrics (disclosures blocked,
false-positive rate, task completion, injection pass/fail) directly from
those JSONL logs, and separately times two things fresh: the isolated
`policy.check()`/baseline `check()` call itself (no token/agent overhead,
5 repeats per case-step, median reported), and case 8's full end-to-end
workflow (real tokens, real agents, real audit logging, median of 5
repeats). Token/policy overhead is computed from the *case-8 total*
latency delta against `no_auth`, not the isolated auth-check delta — the
isolated call excludes token cost for every condition by construction, so
a delta computed from it would silently omit the token layer the metric is
named for.

## 4. Results

The correctness metrics below are deterministic — every rerun of the
120-case harness reproduces exactly these counts, since they're outcomes
of fixed decision logic, not timings:

| Condition | Unauthorized disclosures blocked | Legitimate requests incorrectly denied | Task completion (case 8) | Injection case (6) |
|---|---|---|---|---|
| no_auth | 0/20 | 0/15 | 5/5 (100%) | NOT BLOCKED (0/5 denied) |
| role_based | 10/20 | 0/15 | 5/5 (100%) | BLOCKED (5/5 denied) |
| purpose_bound | 20/20 | 0/15 | 5/5 (100%) | BLOCKED (5/5 denied) |

Purpose-bound blocks all 20 unauthorized-disclosure attempts across cases
2/3/5/6 (5 repeats each); role-based blocks half (cases 2 and 6 only,
missing 3 and 5 — see Threat Model for why); no-auth blocks none, by
definition. All three conditions have a **zero false-positive rate** on the
legitimate cases (1, 4, 8) and **100% task completion** on the full
booking workflow — in this scenario, purpose-bound's added strictness cost
nothing in legitimate throughput. Case 6 is blocked by both purpose-bound
and role-based, but see the threat-model discussion above before reading
that as purpose-bound's distinguishing contribution — it isn't.

**Latency figures are deliberately not reproduced here as literal numbers.**
They're single-process, in-memory microsecond-scale Python timings, and
they shift somewhat on every rerun (confirmed: re-running the one-command
reproduction in `README.md` moved every latency figure while leaving every
correctness figure above byte-identical) — a report that quotes a frozen
digit invites it to drift out of sync with the artifact it's describing.
The current numbers are always available, freshly regenerated, in
`results/results_table.md` (produced by the same one-command reproduction
used to verify this report). The qualitative findings, which have held
across every rerun so far, are:

- **Ordering:** the isolated authorization-decision call itself is
  sub-microsecond for all three conditions, and the median grows in the
  order no_auth < role_based < purpose_bound — more checks cost more time,
  as expected, but all three stay in the same tiny fraction-of-a-microsecond
  regime.
- **role_based's token/policy overhead vs. no_auth is negligible —
  indistinguishable from zero** on case 8's full end-to-end workflow,
  because neither condition touches a token at all — both take the
  identical no-token path through a baseline `check()` call, so there is no
  architectural reason to expect any difference, measured or otherwise.
- **purpose_bound's overhead is the standout cost**, and it's concentrated
  entirely in the token layer, not the policy decision logic: case 8's full
  two-step workflow is substantially slower under purpose_bound than under
  either baseline, attributable specifically to real HMAC signing and
  verification on every token issuance/validation, not to `policy.check()`
  itself (whose isolated latency barely differs from the baselines' checks).

See `results_table.md`'s own methodology note for exactly how the
auth-check-only and case-8-total-latency figures are measured, and for the
reasoning behind computing overhead from the case-8 total (which includes
real token cost) rather than the isolated auth-check delta (which
excludes token cost for every condition by construction). All of these
figures — current or past — are single-process, in-process Python timings
at a scale where sampling noise is non-trivial relative to the signal; see
Limitations.

## 5. Limitations

- **Small, synthetic scenario.** Three agents, one travel-booking
  workflow, six protected fields. This says nothing about how field/purpose
  cardinality, or purpose overlap between agents, would behave at a larger
  or more realistic scale.
- **One hardcoded injection string, not adversarial or adaptive testing.**
  Case 6 uses a single fixed payload that names its target fields outright.
  There was no attempt to construct inputs designed to evade the policy
  engine, no fuzzing, and no adaptive adversary that adjusts strategy after
  a denial. A real attacker would not announce the fields it wants in plain
  text.
- **No distributed or multi-process timing.** All latency numbers are
  single-process, in-memory Python function-call timings, dominated by
  interpreter and HMAC overhead rather than anything architecturally
  meaningful at real scale, and they carry real sampling noise at this
  magnitude (documented in `results_table.md`'s methodology note). They say
  nothing about latency under network calls, concurrent load, or a
  production JWT/token-service implementation.
- **The field-set check (`policy.check()` step (b) specifically) is
  unproven as a deciding layer within the formal experiment.** As detailed
  in the Threat Model section, steps (a) and (c) are each independently
  proven decisive by the 120-run harness — (a) via case 5, which bypasses
  the token layer entirely and is denied by `policy.check()` alone; (c) via
  cases 3/4, the approval gate, which has no token-layer equivalent at all.
  Step (b) alone is different: the two cases built to exercise it (2 and 6)
  are both intercepted one layer earlier by the agent-layer token-grant
  check, which for case 6 means `policy.check()` is never even called. The
  claim that step (b) is a meaningful, independently-exercised check rests
  on one supplementary, off-path, hand-constructed test (a deliberately
  mis-issued token), not on the formal results table.

## 6. Conclusion

Within this scenario's scope, the results support the hypothesis: the
purpose-bound condition blocked strictly more unauthorized disclosure
attempts than either baseline, at no measurable cost to task completion,
with the added latency concentrated in and attributable to the token layer
rather than the decision logic itself. The two conditions that most clearly
distinguish purpose-bound from role-based are approval-gating (case 3) and
purpose-scoped forwarding (case 5) — not the prompt-injection case, which a
coarser role check happens to catch too. Given the limitations above,
particularly the small scenario and the non-adaptive injection test, this
should be read as evidence that the approach is implementable and
measurable, not as evidence that it holds up against a motivated adversary
or at production scale.

## 7. Relationship to SAGA

This project is independently inspired by SAGA's high-level framing of
agent-to-agent authorization as an explicit, policy-mediated boundary
rather than implicit trust, but does not reproduce, modify, benchmark, or
formally extend SAGA's implementation, protocol, or evaluation. See the
README's [Relationship to SAGA](../README.md#relationship-to-saga) section
for the full discussion, including exactly which SAGA concepts motivated
this prototype, how purpose/field/tool/approval/task constraints are
modeled here (this project's own design, not SAGA's), and an explicit
statement that there is no collaboration, supervision, endorsement, or
affiliation with the SAGA authors or the NDS2 Lab.

## References

1. Georgios Syros, Anshuman Suri, Jacob Ginesin, Cristina Nita-Rotaru, and
   Alina Oprea. "SAGA: A Security Architecture for Governing AI Agentic
   Systems." *Network and Distributed System Security (NDSS) Symposium*,
   2026. https://arxiv.org/abs/2504.21034 —
   official implementation: https://github.com/gsiros/saga
2. This repository's scenario and eight-case design record:
   `docs/experiment-protocol.md`.
3. This repository's generated evidence: `results/results_table.md`
   (Correctness section, deterministic) and `results/raw/*.jsonl`
   (regenerated locally; not tracked in git — see README's "Output and
   reproducibility notes").
