"""Runs all 8 cases x 3 conditions x N repeats, logging every decision via
auth.audit and asserting actual == expected for each (case, condition).

A mismatch here means the harness has a bug, not that the finding changed —
every expected value was already hand-verified directly against
auth.policy / auth.token / the agents in Phases 2-5. So this raises
AssertionError immediately rather than collecting failures to report later.
"""

import pathlib

from agents import coordinator, flight_search, payment
from auth.audit import AuditLog
from auth.policy import ApprovalRegistry
from baselines import no_auth, role_based
from experiments.cases import CASES

CONDITIONS = ("no_auth", "role_based", "purpose_bound")
DEFAULT_REPEATS = 5

RESULTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "results" / "raw"

_BASELINE_MODULES = {"no_auth": no_auth, "role_based": role_based}
_AGENT_MODULES = {"flight_search": flight_search, "payment": payment}


class HarnessMismatch(AssertionError):
    pass


def _execute_step_purpose_bound(step, task_id, approvals, audit_log):
    if step.approval_granted_before:
        coordinator.approve(approvals, task_id, step.requested_purpose)

    if step.is_forward:
        return coordinator.forward_to_agent(
            step.requested_purpose, step.requested_fields, task_id, approvals, audit_log
        )

    token_str = coordinator.issue_token(
        step.agent_id, step.requested_purpose, task_id, ttl_seconds=300
    )
    if step.token_state == "revoked":
        coordinator.revoke(task_id)

    agent_module = _AGENT_MODULES[step.agent_id]
    if step.is_injection:
        return flight_search.attempt_injected_request(token_str, task_id, approvals, audit_log)

    return agent_module.request(
        token_str, step.requested_fields, step.requested_tool, task_id, approvals, audit_log
    )


def _execute_step_baseline(step, task_id, approvals, module, audit_log):
    decision, reason = module.check(
        step.agent_id, step.requested_purpose, step.requested_fields,
        step.requested_tool, task_id, approvals,
    )
    audit_log.record(
        task_id=task_id, agent_id=step.agent_id, purpose=step.requested_purpose,
        fields=step.requested_fields, tool=step.requested_tool,
        decision=decision, reason=reason,
    )
    return decision, reason


def run_case(case, condition, task_id, audit_log):
    """Run one case's steps under one condition/task_id. Returns (decision, reason)."""
    approvals = ApprovalRegistry()
    overall_decision = True
    last_reason = None
    for step in case.steps:
        if condition == "purpose_bound":
            decision, reason = _execute_step_purpose_bound(step, task_id, approvals, audit_log)
        else:
            decision, reason = _execute_step_baseline(
                step, task_id, approvals, _BASELINE_MODULES[condition], audit_log
            )
        overall_decision = overall_decision and decision
        last_reason = reason
        if not decision:
            break
    return overall_decision, last_reason


def run_cases(cases, conditions, repeats, run_tag):
    """Core runner: executes every (case, condition, repeat), asserting actual
    == expected. Returns {condition: AuditLog}. Does not touch disk."""
    audit_logs = {condition: AuditLog() for condition in conditions}
    for case in cases:
        for condition in conditions:
            for repeat in range(repeats):
                task_id = f"{run_tag}-case{case.number}-{condition}-rep{repeat}"
                decision, reason = run_case(case, condition, task_id, audit_logs[condition])
                expected = case.expected[condition]
                if decision != expected:
                    raise HarnessMismatch(
                        f"case {case.number} ({case.description!r}) under "
                        f"condition '{condition}' repeat {repeat}: expected "
                        f"{'ALLOW' if expected else 'DENY'}, got "
                        f"{'ALLOW' if decision else 'DENY'} (reason: {reason!r})"
                    )
    return audit_logs


def write_results(audit_logs, results_dir=RESULTS_DIR):
    results_dir.mkdir(parents=True, exist_ok=True)
    for condition, audit_log in audit_logs.items():
        path = results_dir / f"{condition}.jsonl"
        contents = audit_log.to_jsonl()
        path.write_text(contents + "\n" if contents else "")


def main():
    audit_logs = run_cases(CASES, CONDITIONS, DEFAULT_REPEATS, run_tag="full")
    write_results(audit_logs)
    total_runs = len(CASES) * len(CONDITIONS) * DEFAULT_REPEATS
    print(f"OK: {total_runs} runs, all matched hand-verified expected outcomes.")
    print(f"Raw logs written to {RESULTS_DIR}")


if __name__ == "__main__":
    main()
