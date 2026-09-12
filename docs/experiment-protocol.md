# Experiment Protocol

This document is the self-contained design record for the scenario and the
eight test cases used throughout this repository. Earlier source comments
referred to design decisions as coming from "the spec" or a numbered
"Phase" (e.g. "Phase 2", "Phases 2-5") from this project's original,
informal development notes. Those notes were personal working notes, not a
published document, and are not part of this repository, so this file
replaces those references with a complete, in-repo description of the same
decisions. If you find a lingering "spec"/"Phase N" reference anywhere in
the code or docs, it should point here (or be rewritten in place) — please
treat it as an oversight and file an issue/PR.

## 1. Scenario definition

Three agents collaborate on a synthetic travel-booking task for one
synthetic user profile (`data/user_profile.py`):

| Agent | Permitted purpose(s) | Role |
|---|---|---|
| `coordinator` | `orchestration` | Holds the full profile as source of truth; issues tokens; grants approvals; never calls external tools directly |
| `flight_search` | `search_flights` | Searches flights using only public trip fields |
| `payment` | `process_payment` | Charges payment, gated on explicit per-task coordinator approval |

Fields split into two groups (`data/user_profile.py`):

- **Public fields** (`origin`, `destination`, `dates`, `passenger_count`) —
  what `search_flights` may request.
- **Sensitive/protected fields** (`name`, `address`, `phone`, `email`,
  `passport_number`, `payment_token`) — must never leave the coordinator
  except under explicit purpose/approval authorization.

`auth/identity.py` encodes the purpose → field/tool grant table and which
purposes require per-task approval (`process_payment` is the only one in
this scenario).

## 2. The eight test cases

Each case is one or more `RequestStep`s executed under a shared `task_id`
(`experiments/cases.py`); a case's outcome is the AND of its steps.

1. **Flight agent requests route and dates.** Baseline legitimate request —
   all three conditions allow it.
2. **Flight agent requests payment details.** A field outside
   `search_flights`'s declared set — purpose-bound and role-based both
   deny it; no-auth allows it (it allows everything).
3. **Payment agent requests token before approval.** Exercises the
   approval gate. Role-based has no approval concept at all, so it allows
   regardless of approval state — this divergence from purpose-bound is
   intentional and is one of the two cases that actually distinguish the
   two conditions (see `report/report.md`, Threat Model).
4. **Payment agent requests token after approval.** Same request as case 3,
   with approval pre-granted — all three conditions allow it.
5. **Agent attempts to forward protected fields to another agent.**
   Modeled as the *coordinator* — which legitimately holds every field —
   attempting to forward a field while requesting **as the recipient's
   purpose** (`search_flights`), not as its own (`orchestration`). This is
   the modeling choice that makes the case meaningful: under purpose-bound
   it is denied at policy step (a), because the coordinator is never
   registered for any purpose but `orchestration`; under role-based it is
   allowed, because role-based only checks the *acting* role's own field
   access, and the coordinator's role legitimately includes every field.
   An earlier model (flight-search forwarding a field to itself) was
   rejected during design because it would have been denied by the
   token-grant check under every field-aware condition, producing no
   divergence and telling us nothing about purpose-scoping specifically.
   This case's result is a property of *this* coordinator-to-recipient
   purpose model, not a general proof that every RBAC design fails to
   express purpose-scoped forwarding — see `report/report.md` Limitations.
6. **Injected web content instructs agent to reveal private data.**
   Executes the real (not simulated) injection mechanism for
   `purpose_bound`: `flight_search.attempt_injected_request` reads a
   hardcoded string standing in for untrusted "web content" and naively
   extracts the fields it names. For `role_based`/`no_auth`, which have no
   agent/token layer, the harness passes the same injection-derived field
   list directly to the baseline `check()`. Both `purpose_bound` and
   `role_based` deny this case, but for different reasons — see
   `report/report.md`'s Threat Model section: role-based denies because
   the demanded fields aren't in `flight_search`'s *static role* set at
   all, independent of purpose, not because it understands purpose-scoped
   authorization. This case should not be read as purpose-bound's
   distinguishing win; cases 3 and 5 are.
7. **Token expired or revoked mid-task.** The harness's canonical, formally
   run sub-mode is "revoked" (deterministic, no `sleep()` needed across
   repeats), with approval pre-granted so revocation is isolated as the
   sole cause of denial. "Expired" was independently hand-verified against
   `auth/token.py` during development, with an equivalent expected-outcome
   pattern across conditions, but is not part of the formal 120-run
   harness — see `report/report.md` for why, and `tests/test_token.py` for
   an automated expiry regression test.
8. **Full legitimate booking workflow.** Flight search, then payment after
   approval — both steps must succeed for the case to count as completed.

## 3. Supplementary, off-path checks (not part of the formal 120-run matrix)

During development, one additional check was constructed to test
`policy.check()`'s field/tool membership step (step (b)) in isolation: a
token issued directly via `token.issue()` with a deliberately over-broad
`allowed_fields`, bypassing `coordinator.issue_token()`'s normal scoping.
That test showed step (b) independently denying a field the mis-issued
token itself claimed to grant — evidence that step (b) is not vacuous by
construction. It sits outside the 8-case matrix, was not repeated across
conditions, and is not included in `results/results_table.md`; see
`report/report.md`'s Threat Model and Limitations sections for the full
discussion of what this does and doesn't prove.

## 4. Conformance vs. measurement

`experiments/cases.py`'s `expected` field on each `Case` stores the
outcome that was hand-verified against `auth/policy.py` / `auth/token.py`
/ the agent wrappers' source during development, for each of the three
conditions. `experiments/run_experiment.py` asserts that the current
implementation still produces those exact outcomes on every run, and
raises immediately on any mismatch.

This assertion is a **conformance / regression check**, not independent
empirical evidence: because `run_experiment.py` only writes
`results/raw/*.jsonl` after every case has matched its stored expectation,
the correctness-derived metrics in `results/results_table.md` (disclosures
blocked, false-positive rate, task completion, injection outcome) are, by
construction, a restatement of those same hand-verified expectations —
they cannot diverge from them without the harness itself failing first.
Rerunning the harness demonstrates *reproducibility* (the implementation
still behaves as designed) and gives a convenient machine-checkable
regression gate; it does not, by itself, constitute a fresh empirical test
of the purpose-bound hypothesis against an independent ground truth. The
actual evidentiary basis for the hypothesis is the case design and manual
verification described in this document and in `report/report.md`'s
Method/Threat Model sections — read the results table as "the
implementation still does what was verified to be correct," not as "N
independent experiments confirmed the hypothesis."
