"""
How often does the provider decline to answer a legitimate security question?

This is a property of the deployed system, not an error in it. A security tool
built on a commercial model inherits that model's safety behaviour as an
availability characteristic: some fraction of well-formed vulnerability
questions return no answer at all, and the user sees a failure. It is worth
measuring for the same reason latency is.

It was very nearly measured by accident and then deleted. `query.py` substitutes
a placeholder string on `stop_reason: "refusal"`, and the first answer-quality
run graded those placeholders as though they were answers - the judge read "The
model declined to answer this query" and quite reasonably called it an
abstention. Excluding them from groundedness was the right correction. Deleting
them would have been the wrong one: on 2 of 18 vulnerability questions the user
got nothing back, which is a real thing to know about this system.

Three independent observations of the same behaviour are aggregated here, each
with its own denominator, because they measure it at different points in the
pipeline and should not be pooled into a single rate:

  - eval-set construction: generating an analyst question from a CVE record
  - answer generation: answering a question against retrieved context
  - the API ledger: every call the project has ever made, by stop_reason

    python experiments/refusals.py

Writes experiments/results/refusals.json, committed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import api_ledger  # noqa: E402
import provenance  # noqa: E402

RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
EVAL_PATH = PROJECT_ROOT / "experiments" / "samples" / "paraphrased_eval.json"
OUT_PATH = RESULTS_DIR / "refusals.json"


def from_eval_construction() -> Dict[str, Any]:
    """CVEs whose analyst question the generator declined to write."""
    if not EVAL_PATH.exists():
        return {}
    payload = json.loads(EVAL_PATH.read_text(encoding="utf-8"))
    excluded = payload.get("excluded", {})
    refused = {k: v for k, v in excluded.items() if v == "refusal"}
    attempted = len(payload.get("items", [])) + len(excluded)
    return {
        "stage": "generating an analyst question from a CVE record",
        "attempted": attempted,
        "refused": len(refused),
        "rate": round(len(refused) / attempted, 4) if attempted else 0.0,
        "cve_ids": sorted(refused),
    }


def from_answer_runs() -> List[Dict[str, Any]]:
    """Questions the API declined to answer, per run."""
    out = []
    seen = set()
    for path in sorted(RESULTS_DIR.glob("answer_quality*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        # answer_quality.json is a copy of whichever run is current, so the same
        # refusals would otherwise be counted under two names and read as two
        # independent observations.
        fingerprint = tuple(sorted(
            r["id"] for group in payload.get("records", {}).values()
            for r in group))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        # Two ways a refusal is recorded, because the harness learned to skip
        # them partway through: named in generation_failures once the run loop
        # stopped persisting them, and still present as records before that.
        named = list(payload.get("generation_failures", []))
        embedded: List[str] = []
        # Only the groups that involve a generation call. The calibration groups
        # re-judge answers that already exist, so counting them would inflate
        # the denominator with attempts the provider was never asked to make.
        generated = {g: v for g, v in payload.get("records", {}).items()
                     if g in ("answerable", "unanswerable")}
        for group in generated.values():
            embedded.extend(
                r["id"] for r in group
                if (r.get("error") == "refusal"
                    or (r.get("answer") or "").strip()
                    == "The model declined to answer this query.")
            )
        refused = sorted(set(named) | set(embedded))
        answered = sum(len(g) for g in generated.values()) - len(embedded)
        attempted = answered + len(refused)
        if not attempted:
            continue
        out.append({
            "run": path.name,
            "retrieval": payload.get("retrieval"),
            "stage": "answering a question against retrieved context",
            "attempted": attempted,
            "refused": len(refused),
            "rate": round(len(refused) / attempted, 4),
            "cve_ids": refused,
        })
    return out


def from_ledger() -> Dict[str, Any]:
    """Every call the project has made, counted by stop_reason.

    The only complete denominator available, and the only one that keeps
    counting as new experiments are added.
    """
    summary = api_ledger.summarize()
    totals = summary["totals"]
    return {
        "stage": "every API call in the project",
        "attempted": totals["calls_with_stop_reason"],
        "refused": totals["refusals"],
        "rate": (round(totals["refusals"] / totals["calls_with_stop_reason"], 4)
                 if totals["calls_with_stop_reason"] else 0.0),
        "total_calls_ever": totals["calls"],
        "by_purpose": summary["refusals_by_purpose"],
        "caveat": (
            "the denominator is calls with a recorded stop_reason, not all "
            "calls: the field was added partway through the project and "
            "earlier entries lack it. The per-run figures above cover those."
        ),
    }


def main() -> None:
    payload = {
        **provenance.stamp(),
        "what_this_measures": (
            "the rate at which a safety classifier declines a legitimate "
            "vulnerability question, returning HTTP 200 with stop_reason "
            "'refusal' and no content"
        ),
        "why_it_is_not_one_rate": (
            "the three stages ask the model to do different things and are not "
            "pooled; a refusal while writing a question about a privilege "
            "escalation is not the same event as a refusal while answering one"
        ),
        "eval_construction": from_eval_construction(),
        "answer_runs": from_answer_runs(),
        "ledger": from_ledger(),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print("Provider refusals, by pipeline stage")
    print("-" * 72)
    block = payload["eval_construction"]
    if block:
        print(f"{'eval-set construction':<34}{block['refused']:>4} / "
              f"{block['attempted']:<5} = {block['rate']:.3f}")
    for run in payload["answer_runs"]:
        label = run["run"].replace("answer_quality", "").replace(".json", "")
        print(f"{'answering' + label:<34}{run['refused']:>4} / "
              f"{run['attempted']:<5} = {run['rate']:.3f}")
    led = payload["ledger"]
    print(f"{'all ledgered calls':<34}{led['refused']:>4} / "
          f"{led['attempted']:<5} = {led['rate']:.3f}")
    print()
    print("Refused CVEs are named in the artifact. These are not errors and not")
    print("hallucinations; they are questions the user gets no answer to.")
    print(f"wrote {OUT_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
