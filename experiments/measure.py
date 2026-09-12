"""Correctness metrics from the JSONL logs run_experiment.py wrote, plus a
fresh timing pass (the correctness logs carry latency_us=None)."""

import json
import pathlib
import re
import statistics
import time
from collections import defaultdict

from auth.audit import AuditLog
from auth.policy import ApprovalRegistry, check as policy_check
from baselines import no_auth, role_based
from experiments import run_experiment as exp
from experiments.cases import CASES

RESULTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "results"
RAW_DIR = RESULTS_DIR / "raw"
RESULTS_TABLE_PATH = RESULTS_DIR / "results_table.md"

CONDITIONS = ("no_auth", "role_based", "purpose_bound")

# Independent of run_experiment.py's DEFAULT_REPEATS, which must stay
# fixed for correctness reproducibility. Timing has no such constraint.
LATENCY_WARMUP = 20
LATENCY_REPEATS = 101

_CHECK_FN = {
    "no_auth": no_auth.check,
    "role_based": role_based.check,
    "purpose_bound": policy_check,
}

_TASK_ID_CASE_RE = re.compile(r"^[^-]+-case(\d+)-")


def _load_jsonl(path) -> list:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _case_number(task_id: str) -> int:
    match = _TASK_ID_CASE_RE.match(task_id)
    if not match:
        raise ValueError(f"could not parse case number from task_id '{task_id}'")
    return int(match.group(1))


def _group_by_task(entries: list) -> dict:
    grouped = defaultdict(list)
    for entry in entries:
        grouped[entry["task_id"]].append(entry)
    return grouped


def unauthorized_disclosures_blocked(entries: list) -> tuple:
    # Cases 2, 3, 5, 6 are the single-step cases that each represent a
    # real disclosure or approval-bypass risk if allowed.
    relevant = [e for e in entries if _case_number(e["task_id"]) in (2, 3, 5, 6)]
    denied = sum(1 for e in relevant if e["decision"] == "deny")
    return denied, len(relevant)


def legitimate_incorrectly_denied(entries: list) -> tuple:
    # Case 8 has 2 steps per run; it counts as one incorrectly-denied
    # event if any step was denied.
    incorrect = 0
    total_runs = 0
    for task_id, task_entries in _group_by_task(entries).items():
        if _case_number(task_id) not in (1, 4, 8):
            continue
        total_runs += 1
        if any(e["decision"] == "deny" for e in task_entries):
            incorrect += 1
    return incorrect, total_runs


def task_completion_rate(entries: list) -> tuple:
    case8_runs = [
        task_entries
        for task_id, task_entries in _group_by_task(entries).items()
        if _case_number(task_id) == 8
    ]
    if not case8_runs:
        return 0.0, 0, 0
    completed = sum(1 for run in case8_runs if all(e["decision"] == "allow" for e in run))
    return completed / len(case8_runs), completed, len(case8_runs)


def injection_pass_fail(entries: list) -> tuple:
    case6 = [e for e in entries if _case_number(e["task_id"]) == 6]
    denied = sum(1 for e in case6 if e["decision"] == "deny")
    passed = len(case6) > 0 and denied == len(case6)
    return passed, denied, len(case6)


def _timed_stats(timings: list) -> dict:
    median = statistics.median(timings)
    if len(timings) >= 10:
        deciles = statistics.quantiles(timings, n=10)
        p10, p90 = deciles[0], deciles[-1]
    else:
        p10, p90 = min(timings), max(timings)
    return {"median_us": median, "p10_us": p10, "p90_us": p90}


def measure_authcheck_latency(
    repeats: int = LATENCY_REPEATS, warmup: int = LATENCY_WARMUP
) -> dict:
    # Only the check() call itself -- no token issuance, no agent wrapper.
    results = {}
    for condition in CONDITIONS:
        check_fn = _CHECK_FN[condition]
        timings = []
        for case in CASES:
            for step in case.steps:
                approvals = ApprovalRegistry()
                if step.approval_granted_before:
                    approvals.grant("measure-task", step.requested_purpose)
                args = (
                    step.agent_id, step.requested_purpose,
                    step.requested_fields, step.requested_tool,
                    "measure-task", approvals,
                )
                for _ in range(warmup):
                    check_fn(*args)
                for _ in range(repeats):
                    start = time.perf_counter()
                    check_fn(*args)
                    timings.append((time.perf_counter() - start) * 1_000_000)
        results[condition] = _timed_stats(timings)
    return results


def measure_case8_total_latency(
    repeats: int = LATENCY_REPEATS, warmup: int = LATENCY_WARMUP
) -> dict:
    # Full case-8 workflow end-to-end: real token issuance/validation,
    # agent wrappers, audit logging.
    case8 = next(c for c in CASES if c.number == 8)
    results = {}
    for condition in CONDITIONS:
        for _ in range(warmup):
            exp.run_case(case8, condition, f"measure-warmup-{condition}", AuditLog())
        timings = []
        for repeat in range(repeats):
            task_id = f"measure-case8-{condition}-rep{repeat}"
            throwaway_audit_log = AuditLog()
            start = time.perf_counter()
            exp.run_case(case8, condition, task_id, throwaway_audit_log)
            timings.append((time.perf_counter() - start) * 1_000_000)
        results[condition] = _timed_stats(timings)
    return results


def generate_results_table() -> str:
    entries_by_condition = {c: _load_jsonl(RAW_DIR / f"{c}.jsonl") for c in CONDITIONS}
    authcheck_latency = measure_authcheck_latency()
    case8_latency = measure_case8_total_latency()

    correctness_rows = []
    for condition in CONDITIONS:
        entries = entries_by_condition[condition]
        blocked, blocked_total = unauthorized_disclosures_blocked(entries)
        fp, fp_total = legitimate_incorrectly_denied(entries)
        completion_rate, completed, completion_total = task_completion_rate(entries)
        inj_passed, inj_denied, inj_total = injection_pass_fail(entries)
        correctness_rows.append(
            {
                "condition": condition,
                "blocked": f"{blocked}/{blocked_total}",
                "fp": f"{fp}/{fp_total}",
                "completion": f"{completed}/{completion_total} ({completion_rate * 100:.0f}%)",
                "injection": "BLOCKED" if inj_passed else "NOT BLOCKED",
                "injection_detail": f"{inj_denied}/{inj_total} denied",
            }
        )

    correctness_header = (
        "| Condition | Unauthorized disclosures blocked | Legitimate requests "
        "incorrectly denied | Task completion (case 8) | Injection case (6) |\n"
        "|---|---|---|---|---|\n"
    )
    correctness_body = "\n".join(
        f"| {r['condition']} | {r['blocked']} | {r['fp']} | {r['completion']} | "
        f"{r['injection']} ({r['injection_detail']}) |"
        for r in correctness_rows
    )
    correctness_note = (
        "\n\nThese counts are deterministic — every rerun of the 120-run "
        "harness (8 cases × 3 conditions × 5 repeats) reproduces exactly "
        "these numbers, since they are outcomes of fixed decision logic, "
        "not timings. **This table is a conformance check against "
        "previously hand-verified expected outcomes, not an independent "
        "empirical measurement of the hypothesis** — see "
        "`docs/experiment-protocol.md` Section 4 for why that distinction "
        "matters, and what the 8-case design does and doesn't prove.\n\n"
        "**Note on case 6 (prompt injection):** `role_based` also blocks "
        "the injected request, denying it for the same reason it denies "
        "case 2 — the demanded fields (`passport_number`, `payment_token`) "
        "fall outside `flight_search`'s static role field set, independent "
        "of purpose. **This should not be read as purpose-bound's unique "
        "advantage:** on this specific attack, a coarser role check happens "
        "to produce the same outcome, because the injected fields are "
        "outside *any* purpose flight_search could plausibly claim. "
        "Purpose-bound's actual distinguishing outcomes are cases 3 "
        "(approval gating, which role-based has no concept of) and 5 "
        "(purpose-scoped forwarding, which this role-based implementation "
        "cannot express because it only checks the acting role's own field "
        "access — see `docs/experiment-protocol.md` Section 2 for why case "
        "5's result is a property of this specific coordinator-to-recipient "
        "purpose model, not a proof that every RBAC design would fail it). "
        "`no_auth` fails to block the injection, as it fails to block "
        "everything.\n"
    )

    timing_rows = []
    for condition in CONDITIONS:
        ac, c8 = authcheck_latency[condition], case8_latency[condition]
        overhead_us = c8["median_us"] - case8_latency["no_auth"]["median_us"]
        timing_rows.append(
            {
                "condition": condition,
                "authcheck": f"{ac['median_us']:.2f} [{ac['p10_us']:.2f}, {ac['p90_us']:.2f}]",
                "case8": f"{c8['median_us']:.2f} [{c8['p10_us']:.2f}, {c8['p90_us']:.2f}]",
                "overhead": f"{overhead_us:+.2f}",
            }
        )

    timing_header = (
        "| Condition | Auth-check latency — median [p10, p90] µs | "
        "Case-8 total latency — median [p10, p90] µs | Token/policy "
        "overhead vs no_auth — median delta, µs |\n"
        "|---|---|---|---|\n"
    )
    timing_body = "\n".join(
        f"| {r['condition']} | {r['authcheck']} | {r['case8']} | {r['overhead']} |"
        for r in timing_rows
    )
    timing_note = (
        f"\n\n**This section is supplementary and should not be quoted as a "
        "production-latency claim.** All figures are local, in-memory, "
        f"single-process Python timings ({LATENCY_WARMUP} discarded warm-up "
        f"iterations followed by {LATENCY_REPEATS} measured repeats per "
        "figure; the bracketed range is the [p10, p90] spread across those "
        "repeats — a variability measure, not a confidence interval). They "
        "shift somewhat on every rerun even with warm-up and 101 repeats, "
        "because they are dominated by interpreter/OS scheduling noise at "
        "microsecond scale, not by anything architecturally meaningful.\n\n"
        "**The three conditions do not execute identical pipelines, so "
        "this is not an apples-to-apples microbenchmark of one code path "
        "under three policies.** `purpose_bound`'s case-8 total includes "
        "real HMAC token issuance and verification, the agent request "
        "wrappers, `policy.check()`, and audit logging on every step. Both "
        "baselines skip token issuance/verification and the agent wrapper "
        "entirely, calling a single direct `check()` function instead. The "
        "auth-check column isolates `policy.check()`/baseline `check()` "
        "alone (no token issuance, agent wrapper, or audit logging, for any "
        "condition) so its three numbers are comparable to each other; the "
        "case-8 column is each condition's full real pipeline end-to-end, "
        "so its numbers are NOT comparable to the auth-check column, and "
        "the difference between the two columns for `purpose_bound` is "
        "itself informative (it isolates roughly what token issuance and "
        "verification cost on top of the decision logic). Token/policy "
        "overhead is computed from the case-8 total delta against "
        "`no_auth`, not the isolated auth-check delta, because the isolated "
        "call excludes token cost for every condition by construction — a "
        "delta computed from it would silently omit the token layer this "
        "metric is named for. Read the *relative* ordering (no_auth ≤ "
        "role_based ≪ purpose_bound on case-8 total, attributable to real "
        "HMAC signing/verification per step) as the qualitative finding, "
        "not the absolute microsecond values.\n"
    )

    return (
        "# Results Table\n\n"
        "## Correctness (primary)\n\n"
        + correctness_header + correctness_body + correctness_note
        + "\n## Timing (supplementary)\n\n"
        + timing_header + timing_body + timing_note
    )


def main():
    table_md = generate_results_table()
    RESULTS_TABLE_PATH.write_text(table_md)
    print(f"Wrote {RESULTS_TABLE_PATH}")


if __name__ == "__main__":
    main()
