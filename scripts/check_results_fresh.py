#!/usr/bin/env python3
"""CI staleness gate for results/results_table.md. Only checks the
Correctness section (deterministic) -- Timing is expected to vary between
runs and is skipped.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_TABLE = ROOT / "results" / "results_table.md"
CORRECTNESS_START = "## Correctness (primary)"
TIMING_START = "## Timing (supplementary)"


def _extract_correctness_section(text: str) -> str:
    if CORRECTNESS_START not in text or TIMING_START not in text:
        raise ValueError(
            f"expected markers {CORRECTNESS_START!r} and {TIMING_START!r} "
            "not found in results_table.md -- did its structure change?"
        )
    start = text.index(CORRECTNESS_START)
    end = text.index(TIMING_START)
    return text[start:end]


def main() -> int:
    before = RESULTS_TABLE.read_text()

    subprocess.run(
        [sys.executable, "-m", "experiments.run_experiment"],
        cwd=ROOT, check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "experiments.measure"],
        cwd=ROOT, check=True,
    )

    after = RESULTS_TABLE.read_text()

    before_correctness = _extract_correctness_section(before)
    after_correctness = _extract_correctness_section(after)

    if before_correctness != after_correctness:
        print(
            "STALE: results/results_table.md's Correctness section does not "
            "match a fresh run. Regenerate it with:\n"
            "    python3 -m experiments.run_experiment && python3 -m experiments.measure\n"
            "and commit the update.\n",
            file=sys.stderr,
        )
        print("--- committed ---", file=sys.stderr)
        print(before_correctness, file=sys.stderr)
        print("--- freshly generated ---", file=sys.stderr)
        print(after_correctness, file=sys.stderr)
        return 1

    print("OK: results/results_table.md's Correctness section is fresh.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
