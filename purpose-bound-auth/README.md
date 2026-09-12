# Purpose-Bound Field-Level Authorization for Multi-Agent Workflows

A controlled experiment testing whether purpose-specific, field-level
authorization reduces unauthorized field disclosure between collaborating
agents without hurting task completion or latency. See `report/report.md`
for the full writeup (threat model, method, results, limitations).

## Requirements

- Python 3.10+ (the codebase uses `str | None` union-type annotations).
- No third-party dependencies — pure standard library throughout (no
  pydantic, no JWT library, no web framework, no database).

## Layout

```
purpose-bound-auth/
├── data/user_profile.py        # user profile dataclass, public/sensitive field split
├── auth/                       # identity registry, policy engine, tokens, audit log
├── agents/                     # coordinator, flight_search, payment — thin request/log wrappers
├── baselines/                  # no_auth and role_based comparison conditions
├── experiments/                # the 8 test cases, harness, and measurement
├── results/                    # generated: raw JSONL logs + results_table.md
└── report/                     # report.md, sop_paragraph.md, oprea_discussion.md
```

## Running the experiment (one command)

From this directory:

```bash
python3 -m experiments.run_experiment && python3 -m experiments.measure
```

This runs all 8 test cases × 3 conditions (`no_auth`, `role_based`,
`purpose_bound`) × 5 repeats = 120 case-runs, asserting every actual
outcome matches its expected outcome (fails loudly on any mismatch — that
would indicate a harness bug, not a changed finding), then generates
`results/results_table.md` from the resulting logs.

Expected output:

```
OK: 120 runs, all matched hand-verified expected outcomes.
Raw logs written to <path>/results/raw
Wrote <path>/results/results_table.md
```

## Output

- `results/raw/{no_auth,role_based,purpose_bound}.jsonl` — one structured
  decision record per authorization check (135 lines total — case 8's
  two-step workflow logs each step individually).
- `results/results_table.md` — the three conditions side by side across all
  measured metrics, with prose notes on the case 6 nuance and latency
  methodology.
- `report/report.md` — the full 3–5 page writeup.

## Re-running just the measurement step

If `results/raw/*.jsonl` already exist and you only want to regenerate the
table (e.g. after editing `experiments/measure.py`):

```bash
python3 -m experiments.measure
```
