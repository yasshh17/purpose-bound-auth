"""Measurement (Phase 7): latency + overhead instrumentation, plus the
correctness-derived metrics computed from the JSONL logs run_experiment.py
already wrote.

Metrics 1/2/3/7 are pure aggregations over results/raw/*.jsonl -- no new
runs. Metrics 4/5/6 require fresh timing (the correctness logs deliberately
carry latency_us=None -- see run_experiment.py's docstring / Phase 6 report
-- so timing is a separate pass here, not a re-read).
"""

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
LATENCY_REPEATS = 5  # matches run_experiment.py's DEFAULT_REPEATS

_CHECK_FN = {
    "no_auth": no_auth.check,
    "role_based": role_based.check,
    "purpose_bound": policy_check,
}

_TASK_ID_CASE_RE = re.compile(r"^[^-]+-case(\d+)-")


# ---------------------------------------------------------------------------
# Metrics 1/2/3/7: derived from the JSONL logs already written.
# ---------------------------------------------------------------------------

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
    """Deny count on cases 2, 3, 5, 6 -- the single-step cases that each
    represent a real disclosure or approval-bypass risk if allowed."""
    relevant = [e for e in entries if _case_number(e["task_id"]) in (2, 3, 5, 6)]
    denied = sum(1 for e in relevant if e["decision"] == "deny")
    return denied, len(relevant)


def legitimate_incorrectly_denied(entries: list) -> tuple:
    """False-positive count on cases 1, 4, 8. Case 8 has 2 steps per run --
    a run counts as one incorrectly-denied event if ANY step was denied."""
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
    """Case 8 full-workflow success rate: fraction of case-8 runs where
    every step in that run was allowed."""
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
    """Case 6 pass/fail: PASS means every injected-content run was denied."""
    case6 = [e for e in entries if _case_number(e["task_id"]) == 6]
    denied = sum(1 for e in case6 if e["decision"] == "deny")
    passed = len(case6) > 0 and denied == len(case6)
    return passed, denied, len(case6)


# ---------------------------------------------------------------------------
# Metrics 4/5/6: fresh timing pass.
# ---------------------------------------------------------------------------

def measure_authcheck_latency(repeats: int = LATENCY_REPEATS) -> dict:
    """Time ONLY the check() call itself -- policy.check() for purpose_bound,
    the baseline's check() for the other two -- bypassing token issuance and
    agent wrappers entirely. Pools `repeats` timings per case-step across all
    8 cases and returns the median per condition, in microseconds."""
    results = {}
    for condition in CONDITIONS:
        check_fn = _CHECK_FN[condition]
        timings = []
        for case in CASES:
            for step in case.steps:
                approvals = ApprovalRegistry()
                if step.approval_granted_before:
                    approvals.grant("measure-task", step.requested_purpose)
                for _ in range(repeats):
                    start = time.perf_counter()
                    check_fn(
                        step.agent_id, step.requested_purpose,
                        step.requested_fields, step.requested_tool,
                        "measure-task", approvals,
                    )
                    timings.append((time.perf_counter() - start) * 1_000_000)
        results[condition] = statistics.median(timings)
    return results


def measure_case8_total_latency(repeats: int = LATENCY_REPEATS) -> dict:
    """Time the FULL case-8 workflow end-to-end (both steps, through the
    real path -- token issuance/validation, agent wrappers, audit logging).
    Returns the median total latency per condition, in microseconds."""
    case8 = next(c for c in CASES if c.number == 8)
    results = {}
    for condition in CONDITIONS:
        timings = []
        for repeat in range(repeats):
            task_id = f"measure-case8-{condition}-rep{repeat}"
            throwaway_audit_log = AuditLog()
            start = time.perf_counter()
            exp.run_case(case8, condition, task_id, throwaway_audit_log)
            timings.append((time.perf_counter() - start) * 1_000_000)
        results[condition] = statistics.median(timings)
    return results


# ---------------------------------------------------------------------------
# results_table.md generation.
# ---------------------------------------------------------------------------

def generate_results_table() -> str:
    entries_by_condition = {c: _load_jsonl(RAW_DIR / f"{c}.jsonl") for c in CONDITIONS}
    authcheck_latency = measure_authcheck_latency()
    case8_latency = measure_case8_total_latency()

    rows = []
    for condition in CONDITIONS:
        entries = entries_by_condition[condition]
        blocked, blocked_total = unauthorized_disclosures_blocked(entries)
        fp, fp_total = legitimate_incorrectly_denied(entries)
        completion_rate, completed, completion_total = task_completion_rate(entries)
        inj_passed, inj_denied, inj_total = injection_pass_fail(entries)
        # Token/policy overhead must include actual token cost, so it's the
        # case-8 *total* latency delta, not the isolated auth-check delta --
        # the isolated check() call never touches tokens for any condition
        # (that's the point of isolating it), so a delta computed from it
        # would silently exclude the token layer this metric is named for.
        overhead_us = case8_latency[condition] - case8_latency["no_auth"]

        rows.append(
            {
                "condition": condition,
                "blocked": f"{blocked}/{blocked_total}",
                "fp": f"{fp}/{fp_total}",
                "completion": f"{completed}/{completion_total} ({completion_rate * 100:.0f}%)",
                "authcheck_us": f"{authcheck_latency[condition]:.2f}",
                "case8_us": f"{case8_latency[condition]:.2f}",
                "overhead_us": f"{overhead_us:+.2f}",
                "injection": "BLOCKED" if inj_passed else "NOT BLOCKED",
                "injection_detail": f"{inj_denied}/{inj_total} denied",
            }
        )

    header = (
        "| Condition | Unauthorized disclosures blocked | Legitimate requests "
        "incorrectly denied | Task completion (case 8) | Auth-check latency, "
        "policy/baseline call only (median, µs) | Case-8 total latency "
        "(median, µs) | Token/policy overhead vs no_auth (µs) | Injection "
        "case (6) |\n"
        "|---|---|---|---|---|---|---|---|\n"
    )
    body = "\n".join(
        f"| {r['condition']} | {r['blocked']} | {r['fp']} | {r['completion']} | "
        f"{r['authcheck_us']} | {r['case8_us']} | {r['overhead_us']} | "
        f"{r['injection']} ({r['injection_detail']}) |"
        for r in rows
    )

    note = (
        "\n\n**Note on case 6 (prompt injection):** `role_based` also blocks "
        "the injected request, denying it for the same reason it denies case "
        "2 — the demanded fields (`passport_number`, `payment_token`) fall "
        "outside `flight_search`'s static role field set, independent of "
        "purpose. This should not be read as purpose-bound's unique "
        "advantage: on this specific attack, a coarser role check happens to "
        "produce the same outcome, because the injected fields are outside "
        "*any* purpose flight_search could plausibly claim. Purpose-bound's "
        "distinguishing advantage shows up elsewhere in this table — cases 3 "
        "(approval gating) and 5 (purpose-scoped forwarding) — where "
        "`role_based` allows what purpose-bound denies. `no_auth` fails to "
        "block the injection, as it fails to block everything.\n\n"
        "**Note on latency methodology:** auth-check latency isolates the "
        "`policy.check()`/baseline `check()` call itself (5 repeats per "
        "case-step, pooled across all 8 cases, median reported) — no token "
        "issuance, agent wrapper, or audit logging included; this column "
        "never touches tokens for *any* condition, by construction. Case-8 "
        "total latency is the full end-to-end workflow (both steps, real "
        "tokens for purpose_bound, real agents, real audit logging), median "
        "of 5 repeats. Token/policy overhead is deliberately computed from "
        "the case-8 total latency delta against `no_auth`, not from the "
        "isolated auth-check delta — the isolated check() call excludes "
        "token cost for every condition, so a delta computed from it would "
        "silently omit the token layer this metric is named for. In this "
        "toy scenario the absolute numbers are tiny (single-digit to "
        "low-double-digit microseconds) and dominated by Python function-"
        "call and HMAC overhead rather than anything architecturally "
        "meaningful — read the *relative* ordering (no_auth < role_based < "
        "purpose_bound, and purpose_bound's case-8 total is substantially "
        "higher due to real HMAC signing/verification per step), not the "
        "absolute values, as measurements at this scale carry real "
        "sampling noise from a single process.\n"
    )

    return "# Results Table\n\n" + header + body + note


def main():
    table_md = generate_results_table()
    RESULTS_TABLE_PATH.write_text(table_md)
    print(f"Wrote {RESULTS_TABLE_PATH}")


if __name__ == "__main__":
    main()
