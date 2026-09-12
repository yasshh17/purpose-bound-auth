# Purpose-Bound Field-Level Authorization for Multi-Agent Workflows

An independent, SAGA-inspired **controlled research prototype** exploring
whether purpose-specific, field-level authorization reduces unauthorized
field disclosure between collaborating agents, on a small synthetic
travel-booking workflow — without hurting task completion or introducing
unacceptable latency.

**This is not a production system, and it is not a reproduction,
modification, or benchmark of SAGA.** See [Relationship to
SAGA](#relationship-to-saga) below for exactly what that means.

## Research question

Can purpose-specific, field-level authorization prevent unnecessary
disclosure between collaborating agents while preserving task success and
low latency?

## Hypothesis

A policy layer that filters data according to an agent's assigned purpose
will reduce unauthorized field disclosure without materially reducing task
completion or increasing latency, on a small synthetic scenario.

## Requirements

- Python 3.10+ (the codebase uses `str | None` union-type annotations).
- No third-party dependencies — pure standard library throughout (no
  pydantic, no JWT library, no web framework, no database).

## Architecture summary

Three deliberately simple, rule-based agents collaborate on one synthetic
user's travel booking: `coordinator` (orchestration, holds the full
profile, issues tokens, grants approvals), `flight_search` (public trip
fields only), and `payment` (payment field, gated on explicit per-task
approval). Static config (`data/user_profile.py`, `auth/identity.py`)
defines the agents, their permitted purposes, and each purpose's declared
field/tool set.

`auth/policy.py` is the research contribution: given `(agent_id, purpose,
fields, tool, task_id)`, it returns `(decision, reason)` via three ordered,
deny-by-default checks — (a) purpose match, (b) field/tool membership in
the purpose's declared set, (c) explicit per-task-instance coordinator
approval for gated purposes. `auth/token.py` issues short-lived
HMAC-signed tokens (`agent_id`, `allowed_fields`, `allowed_tools`,
`purpose`, `expires_at`, `task_id`) and fails closed on expiry, revocation,
tampering, or any malformed input. `agents/*.py` are thin: validate the
token — including that the **token's own signed `task_id` matches the
request's `task_id`** (see Threat model) — check the request against the
token's grant, call `policy.check()`, log the outcome. `baselines/` holds
two comparison conditions with the same call signature so the harness can
swap conditions without touching the request shape.

Full design rationale for the scenario and the eight test cases lives in
[`docs/experiment-protocol.md`](docs/experiment-protocol.md); the complete
3–5 page writeup (method, full results discussion, limitations) is in
[`report/report.md`](report/report.md).

## Threat model

The only adversary this experiment actually exercises is **untrusted
content that an honest agent reads and naively acts on** — not a
compromised tool implementation, and not a deliberately misbehaving agent.
Test case 6 is the concrete instance: a hardcoded string stands in for
scraped "web content" containing an embedded instruction to exfiltrate
fields the agent was never granted. See `report/report.md` Section 2 for
the full discussion, including why the field/tool-membership check (policy
step (b)) is architecturally independent of, but empirically redundant
with, the agent-layer token-grant check on every path this harness's token
issuance takes.

**Cross-task token binding.** An authenticated token's claims — not any
caller-supplied value — must be authoritative. A previously reported
vulnerability let a request's caller-supplied `task_id` diverge from the
`task_id` signed inside the presented token: a payment token issued for an
unapproved task A could be presented alongside a *different*, already
approved task B's ID, and the approval check (keyed on the caller-supplied
`task_id`) would incorrectly allow it. `agents/payment.py` and
`agents/flight_search.py` now require `payload["task_id"] == task_id`
after validating the token, denying and auditing any mismatch;
`tests/test_agents.py::test_cross_task_token_reuse_denied` reproduces the
exact scenario and asserts it is now denied.

## Baselines

`baselines/no_auth.py` allows every request unconditionally.
`baselines/role_based.py` checks a static role → field/tool set, with no
purpose or per-task concept and no approval gating.

**The three conditions do not execute identical pipelines.**
`purpose_bound` includes real token issuance, token validation, the agent
request wrappers, `policy.check()`, and audit logging on every step. Both
baselines skip token issuance/validation and the agent wrapper entirely,
calling a single direct `check()` function. This matters for reading the
results (below) correctly — the conditions differ in more than just
"amount of policy," and the baselines are not the purpose-bound
architecture with the policy logic swapped out.

Role-based also blocks the fixed prompt-injection case (case 6) — for a
coarser, purpose-independent reason (see Results). Purpose-bound's actual
distinguishing outcomes are **approval gating** (case 3) and
**purpose-scoped forwarding** (case 5). Case 5's outcome is a property of
this repository's specific coordinator-to-recipient purpose model, not a
proof that every RBAC design would fail to express purpose-scoped
forwarding — see `docs/experiment-protocol.md` Section 2.

## Experiment design

Eight scenario cases (`experiments/cases.py`; full rationale in
[`docs/experiment-protocol.md`](docs/experiment-protocol.md)) are each run
under **three authorization conditions** (`no_auth`, `role_based`,
`purpose_bound`) for **five deterministic repetitions**, giving **120
total case-runs** — not 120 independent experiments. The five repeats
exist to demonstrate the harness is deterministic and reproducible, not to
provide statistical breadth; every case is a fixed, hand-constructed
scenario against fixed decision logic, so repeating it does not sample
different conditions. `experiments/run_experiment.py` asserts every
actual outcome matches its previously hand-verified expected outcome for
that (case, condition) pair and fails loudly on any mismatch.

This conformance check should not be read as the experiment "proving" the
hypothesis merely by rerunning stored expectations — see
`docs/experiment-protocol.md` Section 4 for the explicit separation
between (a) conformance to hand-verified expected outcomes and (b) the
actual evidentiary basis for the hypothesis, which is the case design and
manual source-level verification, not the rerun itself.

## Results summary

The table below is `results/results_table.md`'s Correctness section,
current as of the last run in this repository (regenerate with the
reproduction command below to reproduce these exact numbers):

| Condition | Unauthorized disclosures blocked | Legitimate requests incorrectly denied | Task completion (case 8) | Injection case (6) |
|---|---|---|---|---|
| no_auth | 0/20 | 0/15 | 5/5 (100%) | NOT BLOCKED (0/5 denied) |
| role_based | 10/20 | 0/15 | 5/5 (100%) | BLOCKED (5/5 denied) |
| purpose_bound | 20/20 | 0/15 | 5/5 (100%) | BLOCKED (5/5 denied) |

These correctness counts are deterministic. `results/results_table.md`
also has a **Timing** section, deliberately presented as supplementary:
single-process, in-memory Python microbenchmarks with warm-up iterations,
101 measured repeats, and a reported [p10, p90] spread as a variability
measure — not a production-latency claim. See that file's own methodology
note, and `report/report.md`'s Limitations, before quoting any latency
number from this repository.

## Limitations

- Small, synthetic scenario: three agents, one workflow, six protected
  fields. Says nothing about behavior at larger purpose/field cardinality.
- One hardcoded, non-adaptive injection string (case 6) — not adversarial
  or fuzzed input, and not a compromised-tool or malicious-agent scenario.
- No distributed or multi-process timing; all latency figures are
  single-process Python function-call timings with real sampling noise at
  microsecond scale.
- The field-set check (`policy.check()` step (b)) is architecturally
  independent of, but empirically unproven as a distinct deciding layer
  from, the agent-layer token-grant check within the formal 8-case matrix
  (see `report/report.md` Threat Model / Limitations).
- The 120-run harness is a conformance/regression check against
  hand-verified expected outcomes, not independent statistical evidence —
  see `docs/experiment-protocol.md` Section 4.
- Case 5's result is specific to this repository's coordinator-to-
  recipient purpose model, not a general claim about role-based designs.

Full discussion: [`report/report.md`](report/report.md) Section 5.

## Layout

```
purpose-bound-auth/
├── data/user_profile.py          # user profile dataclass, public/sensitive field split
├── auth/                         # identity registry, policy engine, tokens, audit log
├── agents/                       # coordinator, flight_search, payment — thin request/log wrappers
├── baselines/                    # no_auth and role_based comparison conditions
├── experiments/                  # the 8 test cases, harness, and measurement
├── tests/                        # unittest suite (auth, agents, policy, condition matrix)
├── docs/experiment-protocol.md   # scenario + 8-case design rationale (self-contained)
├── results/                      # generated: raw JSONL logs (untracked) + results_table.md (tracked)
├── scripts/check_results_fresh.py# CI staleness gate for results_table.md's Correctness section
├── report/report.md              # the full 3–5 page writeup
└── .github/workflows/ci.yml      # tests + experiment rerun + staleness check
```

## Running the experiment (one command)

From this directory:

```bash
python3 -m experiments.run_experiment && python3 -m experiments.measure
```

This runs all 8 test cases × 3 conditions (`no_auth`, `role_based`,
`purpose_bound`) × 5 repeats = 120 case-runs, asserting every actual
outcome matches its expected outcome (fails loudly on any mismatch — that
would indicate a code regression, not a changed finding), then generates
`results/results_table.md` from the resulting logs.

Expected output:

```
OK: 120 runs, all matched hand-verified expected outcomes.
Raw logs written to <path>/results/raw
Wrote <path>/results/results_table.md
```

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

Uses only Python's built-in `unittest` — no third-party test runner. Every
test resets the global token-revocation state (`auth.token._reset_for_tests()`)
in `setUp`/`tearDown` and builds its own `ApprovalRegistry`/`AuditLog`, so
no approval, token, or revocation state leaks between tests.

## Re-running just the measurement step

If `results/raw/*.jsonl` already exist and you only want to regenerate the
table (e.g. after editing `experiments/measure.py`):

```bash
python3 -m experiments.measure
```

## Output and reproducibility notes

- `results/raw/{no_auth,role_based,purpose_bound}.jsonl` — one structured
  decision record per authorization check, regenerated on every run.
  **Not tracked in git**: each entry carries a wall-clock `timestamp`
  that changes on every deterministic rerun, which would otherwise make
  every rerun look like a content change with nothing substantive
  different. `results/results_table.md` — the aggregation that matters
  for auditing — **is** tracked.
- `results/results_table.md` — Correctness (primary, deterministic) and
  Timing (supplementary, expected to vary) sections. CI
  (`scripts/check_results_fresh.py`) regenerates this file and fails only
  if the Correctness section has gone stale relative to the code; it does
  not gate on the Timing section.
- `report/report.md` — the full 3–5 page writeup (research question,
  threat model, method, results, limitations, conclusion).

## Relationship to SAGA

This repository is independently inspired by, but does **not** reproduce,
modify, benchmark, or formally extend:

> Georgios Syros, Anshuman Suri, Jacob Ginesin, Cristina Nita-Rotaru, and
> Alina Oprea. **"SAGA: A Security Architecture for Governing AI Agentic
> Systems."** *Network and Distributed System Security (NDSS) Symposium*,
> 2026.

Official implementation: <https://github.com/gsiros/saga> (NDS2 Lab,
Northeastern University).

**What inspired this prototype.** SAGA's high-level framing — that
autonomous, LLM-based agents interacting and delegating tasks on a user's
behalf need explicit, enforceable authorization boundaries rather than
implicit trust, and that a central, policy-holding entity can mediate and
cryptographically attest to what one agent is allowed to hand another —
motivated this project's starting question: what does the *simplest*
possible version of "purpose-scoped, field-level, task-bound" enforcement
look like, and does it measurably change disclosure outcomes on a toy
scenario?

**What this prototype independently explores.** A minimal, dependency-free
reduction of that idea to three rule-based agents, one synthetic user
profile, and a single-process policy/token layer — small enough to
hand-verify every decision path (see `docs/experiment-protocol.md`) and
compare directly against a no-auth and a role-based baseline on the same
eight hand-constructed scenarios. This is a controlled experiment on a toy
system, not an implementation of SAGA's actual protocol, threat model, or
cryptographic architecture.

**How purpose, field, tool, approval, and task constraints are modeled
here** (this repository's own design, not SAGA's): a *purpose* is a static
string an agent's identity entry permits it to request
(`auth/identity.py`); each purpose declares a *field* set and *tool* set
an agent may access under it (`policy.check()` steps (a)/(b)); certain
purposes additionally require an explicit, coordinator-granted per-task
*approval* before they're allowed (`policy.check()` step (c),
`ApprovalRegistry`); and every issued credential is bound to one *task*
instance via a signed `task_id` claim inside a short-lived HMAC token
(`auth/token.py`), which the receiving agent must confirm matches the
task it is actually processing a request for (see Threat model above).

**What this repository is not.** It does not reproduce, modify, benchmark
against, or formally extend the complete SAGA implementation linked above;
it does not use SAGA's code, cryptographic protocol, or evaluation
harness; and its "purpose"/"approval"/"task" constructs are this
project's own simplified modeling choices, not a claim of fidelity to
SAGA's actual design. **There is no collaboration, supervision,
endorsement, or affiliation with the SAGA authors or the NDS2 Lab
(Northeastern University) — this is an independent, unaffiliated student
research exercise that cites SAGA as motivating prior work.**

## References

- Georgios Syros, Anshuman Suri, Jacob Ginesin, Cristina Nita-Rotaru, and
  Alina Oprea. "SAGA: A Security Architecture for Governing AI Agentic
  Systems." *NDSS Symposium*, 2026.
  [arXiv:2504.21034](https://arxiv.org/abs/2504.21034) ·
  [NDSS listing](https://www.ndss-symposium.org/ndss-paper/saga-a-security-architecture-for-governing-ai-agentic-systems/) ·
  [official implementation](https://github.com/gsiros/saga)
- This repository's own design record:
  [`docs/experiment-protocol.md`](docs/experiment-protocol.md)
- This repository's full writeup: [`report/report.md`](report/report.md)

## License

MIT — see [`LICENSE`](LICENSE).
