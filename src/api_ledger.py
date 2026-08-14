"""
An append-only record of every Claude API call this project makes.

Written because the first answer-quality run could not account for its own
spend. Token usage was stored per *record*, on the object being graded, which
meant two things went uncounted:

  - re-grading a record overwrote the previous pass's usage, so four judging
    passes over the same 50 answers left the usage of one
  - build_eval_set.py stored no usage at all, and its ~200 generations were
    invisible entirely - their visible output was a one-line JSON object while
    the thinking tokens that dominate the bill leave no trace in the response
    length

The result was a "measured" cost roughly a third of what actually disappeared,
which is worse than not measuring: it looks authoritative.

So usage is recorded here instead - one line per call, appended, never
overwritten, tagged with what the call was for. Reconciling against the Console
is then arithmetic rather than archaeology.

Prices are not hardcoded. Token counts are exact and do not go stale; rates
change, and a stale constant in a file is exactly the kind of unverifiable
number this project removes. Pass rates in explicitly to cost a run:

    python src/api_ledger.py --in-price 5 --out-price 25
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = PROJECT_ROOT / "data" / "api_ledger.jsonl"


def record(
    response: Any,
    model: str,
    purpose: str,
    ledger_path: Path = LEDGER_PATH,
) -> Dict[str, Any]:
    """
    Append one call's usage. Returns the entry.

    Failures to write are swallowed: losing an accounting line must never lose
    an expensive API result that has already been paid for.
    """
    usage = getattr(response, "usage", None)
    entry = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": model,
        "purpose": purpose,
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        # A safety classifier can decline a request: HTTP 200, stop_reason
        # "refusal", no content. Recorded here because it is a property of the
        # deployed system, not an error - a security tool built on a commercial
        # model inherits its refusal behaviour as an availability
        # characteristic, and this is the only place it can be counted exactly
        # across every call the project makes.
        "stop_reason": getattr(response, "stop_reason", None),
        # Cache fields are absent on most responses; keep them when present so
        # a caching experiment can be costed later without re-running anything.
        "cache_creation_input_tokens": getattr(
            usage, "cache_creation_input_tokens", None),
        "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", None),
    }
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:
        pass
    return entry


def read(ledger_path: Path = LEDGER_PATH) -> Iterable[Dict[str, Any]]:
    if not Path(ledger_path).exists():
        return []
    entries = []
    for line in Path(ledger_path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def summarize(
    ledger_path: Path = LEDGER_PATH,
    in_price: Optional[float] = None,
    out_price: Optional[float] = None,
) -> Dict[str, Any]:
    """Totals by model and purpose. Prices are per million tokens, if supplied."""
    by_model: Dict[str, Dict[str, int]] = {}
    by_purpose: Dict[str, Dict[str, int]] = {}
    totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "refusals": 0}
    refusals_by_purpose: Dict[str, int] = {}

    for entry in read(ledger_path):
        tokens_in = entry.get("input_tokens") or 0
        tokens_out = entry.get("output_tokens") or 0
        if entry.get("stop_reason") == "refusal":
            totals["refusals"] += 1
            key = entry.get("purpose", "?")
            refusals_by_purpose[key] = refusals_by_purpose.get(key, 0) + 1
        totals["calls"] += 1
        totals["input_tokens"] += tokens_in
        totals["output_tokens"] += tokens_out
        for bucket, key in ((by_model, entry.get("model", "?")),
                            (by_purpose, entry.get("purpose", "?"))):
            slot = bucket.setdefault(key, {"calls": 0, "input_tokens": 0,
                                           "output_tokens": 0})
            slot["calls"] += 1
            slot["input_tokens"] += tokens_in
            slot["output_tokens"] += tokens_out

    result: Dict[str, Any] = {"totals": totals, "by_model": by_model,
                              "by_purpose": by_purpose,
                              "refusals_by_purpose": refusals_by_purpose}
    if in_price is not None and out_price is not None:
        result["cost"] = {
            "input_price_per_mtok": in_price,
            "output_price_per_mtok": out_price,
            "estimated_usd": round(
                totals["input_tokens"] * in_price / 1e6
                + totals["output_tokens"] * out_price / 1e6, 4),
            "note": "prices supplied at the command line, not stored; token "
                    "counts are exact, rates are not verified here",
        }
    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ledger", default=str(LEDGER_PATH))
    parser.add_argument("--in-price", type=float,
                        help="USD per million input tokens (see the pricing page)")
    parser.add_argument("--out-price", type=float,
                        help="USD per million output tokens")
    args = parser.parse_args()

    summary = summarize(Path(args.ledger), args.in_price, args.out_price)
    t = summary["totals"]
    print(f"{t['calls']:,} calls | {t['input_tokens']:,} in | {t['output_tokens']:,} out")
    if t["refusals"]:
        rate = t["refusals"] / t["calls"]
        print(f"{t['refusals']} refused by a safety classifier "
              f"({rate:.1%} of calls): "
              + ", ".join(f"{k} {v}" for k, v in
                          sorted(summary["refusals_by_purpose"].items())))
    print()
    print(f"{'purpose':<28}{'calls':>7}{'input':>12}{'output':>12}")
    print("-" * 59)
    for name, slot in sorted(summary["by_purpose"].items()):
        print(f"{name:<28}{slot['calls']:>7,}{slot['input_tokens']:>12,}"
              f"{slot['output_tokens']:>12,}")
    print()
    print(f"{'model':<28}{'calls':>7}{'input':>12}{'output':>12}")
    print("-" * 59)
    for name, slot in sorted(summary["by_model"].items()):
        print(f"{name:<28}{slot['calls']:>7,}{slot['input_tokens']:>12,}"
              f"{slot['output_tokens']:>12,}")
    if "cost" in summary:
        print()
        print(f"estimated: ${summary['cost']['estimated_usd']:.2f} at "
              f"${args.in_price}/M in, ${args.out_price}/M out")
        print("compare against console.anthropic.com usage; that is authoritative")


if __name__ == "__main__":
    main()
