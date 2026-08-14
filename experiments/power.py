"""
Sample-size arithmetic for every claim this project makes about answer quality.

Two questions, both of which were being answered by intuition before this file
existed:

  1. How wide are the intervals on the rates already published? A rate of 0.611
     from 18 questions is not 61.1%, and saying so in words rather than in a
     bracket is where overstatement creeps back in.

  2. Is the planned bm25-vs-hybrid_rerank answer-quality comparison large enough
     to answer the question it is being run to answer? McNemar's test spends its
     power on *discordant pairs*, not on the raw sample, so a run can look large
     and detect nothing.

The second question was initially answered here from `ranks_by_cve`, which
records whether the *target* CVE landed in the top five. On that basis the two
configs looked nearly interchangeable - they disagree on the target indicator
for 21 of 192 queries - and the comparison looked both cheap and well powered,
because a marginal difference cannot exceed the rate at which the two arms
differ.

experiments/context_divergence.py measured the thing itself rather than the
proxy, and the proxy was badly wrong. The configs hand the generator a different
set of five documents on 190 of 192 questions, with a mean overlap of 2.2
documents. They agree about where the target is and disagree about almost
everything else. There is no ceiling argument to make and no large stratum of
identical prompts contributing only noise.

So the grade-level discordance rate - the only input McNemar's power actually
depends on - is not known in advance and cannot be derived from retrieval
artifacts. It is bounded above by the prompt divergence, which is 0.99, and
below by nothing useful. What is reported below is therefore power across a
range of plausible discordance rates rather than a single number, and the run
itself measures which column applies.

Run:
    python experiments/power.py
"""

from __future__ import annotations

import functools
import json
import math
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import provenance  # noqa: E402

RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
OUT_PATH = RESULTS_DIR / "power.json"

ALPHA = 0.05
TARGET_POWER = 0.80

# Every held-out question that exists. paraphrased_eval.json carries one item per
# CVE from the 200-CVE sample pinned in Phase 2; 192 generated successfully and
# 35 have been spent developing the prompt. Buying a larger sample would mean
# redrawing a sample this project committed not to redraw, so this is a hard
# ceiling rather than a budget line. 38 questions appear across the two
# development runs, not 35: the two the API refused in the baseline are held out
# too, because they were seen and their exclusion is not a reason to reuse them.
HELD_OUT_CEILING = 154

# The generator is given this many documents. Retrieval differences deeper than
# this are invisible to the answer, which is the whole point of measuring
# discordance here rather than at rank 1.
GENERATION_DEPTH = 5


# --------------------------------------------------------------------------
# Interval arithmetic
# --------------------------------------------------------------------------

def wald(successes: int, n: int, z: float = 1.96) -> Dict[str, float]:
    """The textbook normal approximation. Included because it is what most
    people compute, and because it misbehaves badly at these sample sizes."""
    p = successes / n
    se = math.sqrt(p * (1 - p) / n)
    return {
        "point": round(p, 4),
        "standard_error": round(se, 4),
        "half_width_95": round(z * se, 4),
        "low": round(max(0.0, p - z * se), 4),
        "high": round(min(1.0, p + z * se), 4),
    }


def wilson(successes: int, n: int, z: float = 1.96) -> Dict[str, float]:
    """Better behaved near 0 and 1 and at small n, which is where this project
    lives. Preferred for anything quoted in the README."""
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return {
        "point": round(p, 4),
        "low": round(max(0.0, centre - half), 4),
        "high": round(min(1.0, centre + half), 4),
        "width": round(2 * half, 4),
    }


# --------------------------------------------------------------------------
# Exact McNemar power
# --------------------------------------------------------------------------

def _binom_pmf(k: int, n: int, p: float) -> float:
    """Computed in log space. math.comb(n, k) is exact but overflows float
    conversion past a few hundred trials, which is inside the range of sample
    sizes this file is asked about."""
    if k < 0 or k > n:
        return 0.0
    if p <= 0.0:
        return 1.0 if k == 0 else 0.0
    if p >= 1.0:
        return 1.0 if k == n else 0.0
    log_p = (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
             + k * math.log(p) + (n - k) * math.log1p(-p))
    return math.exp(log_p)


def two_sided_exact_p(wins_a: int, discordant: int) -> float:
    """The p-value src/significance.py computes, restated here so the power
    calculation rejects on exactly the rule the real test uses."""
    if discordant == 0:
        return 1.0
    lower = sum(_binom_pmf(i, discordant, 0.5) for i in range(0, wins_a + 1))
    upper = sum(_binom_pmf(i, discordant, 0.5) for i in range(wins_a, discordant + 1))
    return min(1.0, 2 * min(lower, upper))


@functools.lru_cache(maxsize=None)
def critical_threshold(discordant: int, alpha: float = ALPHA) -> int:
    """Largest c for which a split of c-or-fewer wins rejects at `alpha`.

    Under the null the discordant split is Binomial(m, 0.5), which is symmetric,
    so the two-sided rejection region is exactly the two tails {b <= c} and
    {b >= m - c}. Returns -1 when no split rejects: below six discordant pairs
    even a clean sweep leaves p > 0.05, so the test cannot fire at all.

    The comparison is strict, matching `significant_at_05` in src/significance.py.
    A power calculation that rejected on a rule the real test does not use would
    report power the run cannot deliver.
    """
    cumulative = 0.0
    threshold = -1
    for b in range(discordant + 1):
        cumulative += _binom_pmf(b, discordant, 0.5)
        if min(1.0, 2 * cumulative) < alpha:
            threshold = b
        else:
            break
    return threshold


def critical_region(discordant: int, alpha: float = ALPHA) -> List[int]:
    """The rejecting splits, enumerated. Kept for testing the threshold form
    against the p-value the real test computes."""
    c = critical_threshold(discordant, alpha)
    if c < 0:
        return []
    return [b for b in range(discordant + 1)
            if b <= c or b >= discordant - c]


def rejects(wins_a: int, discordant: int, alpha: float = ALPHA) -> bool:
    """Whether this split rejects, decided from the p-value directly. The
    threshold form above must agree with this everywhere; tests check it."""
    return two_sided_exact_p(wins_a, discordant) < alpha


def power_given_discordant(discordant: int, psi: float,
                           alpha: float = ALPHA) -> float:
    """Probability of rejecting, given the discordant count and the true share
    of discordant pairs favouring A."""
    c = critical_threshold(discordant, alpha)
    if c < 0:
        return 0.0
    lower = sum(_binom_pmf(b, discordant, psi) for b in range(0, c + 1))
    upper = sum(_binom_pmf(b, discordant, psi)
                for b in range(discordant - c, discordant + 1))
    return min(1.0, lower + upper)


def power(n: int, discordance: float, psi: float,
          alpha: float = ALPHA) -> float:
    """Unconditional power: the discordant count is itself random.

    The sum over discordant counts is restricted to a ten-sigma window around
    the expected count. Outside it the binomial weight is far below the
    precision of anything reported here, and including it makes large-n
    searches quadratic for no gain.
    """
    if discordance <= 0:
        return 0.0
    mean = n * discordance
    sd = math.sqrt(n * discordance * (1 - discordance))
    low = max(0, int(mean - 10 * sd) - 1)
    high = min(n, int(mean + 10 * sd) + 1)
    total = 0.0
    for m in range(low, high + 1):
        weight = _binom_pmf(m, n, discordance)
        if weight < 1e-12:
            continue
        total += weight * power_given_discordant(m, psi, alpha)
    return total


def psi_for_delta(delta: float, discordance: float) -> Optional[float]:
    """A marginal difference of `delta` points requires this share of discordant
    pairs to favour A. Returns None when the difference is arithmetically
    impossible: the marginal difference can never exceed the discordance rate,
    because agreeing pairs contribute nothing to it."""
    if discordance <= 0 or abs(delta) > discordance:
        return None
    return (1 + delta / discordance) / 2


def required_n(delta: float, discordance: float, alpha: float = ALPHA,
               target: float = TARGET_POWER, cap: int = 5000) -> Optional[int]:
    """Smallest n reaching the target power. None if unreachable within cap."""
    psi = psi_for_delta(delta, discordance)
    if psi is None:
        return None
    low, high = 1, 64
    while high <= cap and power(high, discordance, psi, alpha) < target:
        low, high = high, high * 2
    if high > cap:
        return None
    while low < high:
        mid = (low + high) // 2
        if power(mid, discordance, psi, alpha) >= target:
            high = mid
        else:
            low = mid + 1
    return low


# --------------------------------------------------------------------------
# Measured inputs, read from committed artifacts rather than assumed
# --------------------------------------------------------------------------

def retrieval_discordance(mode_a: str, mode_b: str,
                          depths: Sequence[int] = (1, 3, 5, 10)) -> Dict[str, Dict]:
    """How often the two configs disagree on whether the target document is
    retrieved, at each depth. Read from the paraphrased query results."""
    def ranks(mode: str) -> Dict[str, Optional[int]]:
        path = RESULTS_DIR / f"paraphrased_queries_{mode}.json"
        if not path.exists():
            raise SystemExit(f"missing {path.name}; run paraphrased_queries.py first")
        return json.loads(path.read_text(encoding="utf-8"))["ranks_by_cve"]

    a, b = ranks(mode_a), ranks(mode_b)
    shared = sorted(set(a) & set(b))
    out: Dict[str, Dict] = {}
    for depth in depths:
        wins_a = wins_b = 0
        for key in shared:
            hit_a = a[key] is not None and a[key] <= depth
            hit_b = b[key] is not None and b[key] <= depth
            if hit_a != hit_b:
                if hit_a:
                    wins_a += 1
                else:
                    wins_b += 1
        discordant = wins_a + wins_b
        out[f"depth_{depth}"] = {
            "queries": len(shared),
            f"{mode_a}_wins": wins_a,
            f"{mode_b}_wins": wins_b,
            "discordant": discordant,
            "discordance_rate": round(discordant / len(shared), 4) if shared else 0.0,
            "observed_marginal_difference": round(
                (wins_a - wins_b) / len(shared), 4) if shared else 0.0,
        }
    return out


def context_divergence() -> Dict[str, Any]:
    """How often the two configs build a different prompt. Measured, not
    inferred; see experiments/context_divergence.py."""
    path = RESULTS_DIR / "context_divergence.json"
    if not path.exists():
        raise SystemExit("missing context_divergence.json; run "
                         "python experiments/context_divergence.py first")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in payload.items() if k != "records"}


def published_intervals() -> Dict[str, Dict]:
    """Intervals for the rates already in the README, so the words used to gloss
    them can be checked against arithmetic."""
    path = RESULTS_DIR / "answer_quality.json"
    if not path.exists():
        return {}
    summary = json.loads(path.read_text(encoding="utf-8")).get("summary", {})
    out: Dict[str, Dict] = {}
    for group, keys in (("answerable", ("grounded", "unsupported", "abstained")),
                        ("unanswerable", ("abstained",))):
        block = summary.get(group)
        if not block:
            continue
        n = block["answers"]
        for grade in keys:
            count = block.get("grades", {}).get(grade, 0)
            out[f"{group}.{grade}"] = {
                "count": count,
                "n": n,
                "wald": wald(count, n),
                "wilson": wilson(count, n),
            }
    return out


# --------------------------------------------------------------------------

def main() -> None:
    disc = retrieval_discordance("hybrid_rerank", "bm25")
    at_depth = disc[f"depth_{GENERATION_DEPTH}"]
    divergence = context_divergence()

    # Grade discordance is unknown until the run measures it, so power is
    # reported across a range. The columns bracket the plausible values: at the
    # low end the two configs mostly produce the same grade despite different
    # documents, at the high end the documents matter and grades move with them.
    discordances = [0.10, 0.20, 0.30, 0.50]
    deltas = [0.05, 0.075, 0.10, 0.15]
    held_out = HELD_OUT_CEILING
    grid: Dict[str, Dict[str, Any]] = {}
    for d_grade in discordances:
        column: Dict[str, Any] = {}
        for delta in deltas:
            psi = psi_for_delta(delta, d_grade)
            key = f"delta_{delta:.3f}"
            if psi is None:
                column[key] = {"impossible_at_this_discordance": True}
                continue
            column[key] = {
                f"power_at_n_{held_out}": round(power(held_out, d_grade, psi), 4),
                "n_for_80_percent": required_n(delta, d_grade),
            }
        grid[f"grade_discordance_{d_grade:.2f}"] = column

    # What the remaining held-out questions would buy. The evaluation set holds
    # one question per CVE from the pinned 200-CVE sample, so 174 unused items
    # is not a budget decision - it is the entire ceiling, and no amount of
    # money raises it without drawing a sample the project has committed not to
    # redraw.
    projected = {
        f"n_{n}": {
            "unsupported": wilson(round(0.278 * n), n),
            "grounded": wilson(round(0.611 * n), n),
        }
        for n in (18, HELD_OUT_CEILING)
    }
    projected["note"] = (
        "held-out ceiling is 174: paraphrased_eval.json carries one question "
        "per CVE from a 200-CVE sample pinned in Phase 2, 192 of which "
        "generated successfully, 18 spent as a development set. Rates are held "
        "at the observed values to isolate the effect of sample size."
    )

    payload = {
        **provenance.stamp(),
        "alpha": ALPHA,
        "target_power": TARGET_POWER,
        "generation_depth": GENERATION_DEPTH,
        "published_intervals": published_intervals(),
        "projected_intervals": projected,
        "retrieval_discordance_hybrid_rerank_vs_bm25": disc,
        "context_divergence": divergence,
        "planned_comparison": {
            "held_out_ceiling": held_out,
            "held_out_note": (
                "paraphrased_eval.json carries one question per CVE from a "
                "200-CVE sample pinned in Phase 2 and committed not to be "
                "redrawn. 192 generated; the remainder is the entire held-out "
                "set that exists, so sample size here is not a budget decision."
            ),
            "grade_discordance": "unknown until measured; power reported across a range",
            "upper_bound_on_discordance": divergence.get(
                "different_document_set_rate"),
            "why_not_a_point_estimate": (
                "The target-indicator discordance of "
                f"{at_depth['discordance_rate']} was used as a proxy and is "
                "wrong for this purpose: the configs agree about the target and "
                "disagree about the rest of the prompt on "
                f"{divergence.get('different_document_set_rate')} of questions, "
                "with a mean overlap of "
                f"{divergence.get('mean_overlap_of_%d' % GENERATION_DEPTH)} of "
                f"{GENERATION_DEPTH} documents. Grade discordance lies "
                "somewhere below the latter and cannot be derived from either."
            ),
            "power_grid": grid,
        },
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # ---- report -------------------------------------------------------
    print("Intervals on the rates already published")
    print("-" * 72)
    for name, block in payload["published_intervals"].items():
        w, wi = block["wald"], block["wilson"]
        print(f"{name:<28} {block['count']}/{block['n']} = {w['point']:.3f}")
        print(f"{'':<28} wald   [{w['low']:.3f}, {w['high']:.3f}]  "
              f"(SE {w['standard_error']:.3f})")
        print(f"{'':<28} wilson [{wi['low']:.3f}, {wi['high']:.3f}]  "
              f"width {wi['width']:.3f}")
    print()

    print("Retrieval discordance, hybrid_rerank vs bm25 (192 paraphrased queries)")
    print("-" * 72)
    print(f"{'depth':>7}{'discordant':>13}{'rate':>9}{'hr wins':>10}{'bm25 wins':>12}")
    for name, block in disc.items():
        depth = name.split("_")[1]
        print(f"{depth:>7}{block['discordant']:>13}{block['discordance_rate']:>9.3f}"
              f"{block['hybrid_rerank_wins']:>10}{block['bm25_wins']:>12}")
    print()
    print(f"At depth {GENERATION_DEPTH} the two configs disagree about the target on "
          f"{at_depth['discordant']} of {at_depth['queries']} queries "
          f"({at_depth['discordance_rate']:.1%}), split "
          f"{at_depth['hybrid_rerank_wins']}/{at_depth['bm25_wins']}. That is a "
          f"much narrower claim than it looks; see below.")
    print()

    print("What the remaining held-out questions buy (rates held fixed)")
    print("-" * 72)
    for size in (18, HELD_OUT_CEILING):
        u = projected[f"n_{size}"]["unsupported"]
        g = projected[f"n_{size}"]["grounded"]
        print(f"  n={size:<4} unsupported [{u['low']:.3f}, {u['high']:.3f}] "
              f"+/-{u['width'] / 2 * 100:4.1f} pts   "
              f"grounded [{g['low']:.3f}, {g['high']:.3f}] "
              f"+/-{g['width'] / 2 * 100:4.1f} pts")
    print(f"  {HELD_OUT_CEILING} is the ceiling, not a budget choice: one question per")
    print("  CVE from a sample pinned in Phase 2, committed not to be redrawn.")
    print()

    print("How different are the two prompts?")
    print("-" * 72)
    print(f"  identical document set   "
          f"{divergence['identical_document_set_rate']:.3f}")
    print(f"  different prompt         "
          f"{divergence['different_document_set_rate']:.3f}   <- upper bound on "
          f"grade discordance")
    print(f"  mean overlap of {GENERATION_DEPTH}        "
          f"{divergence['mean_overlap_of_%d' % GENERATION_DEPTH]} documents")
    print(f"  target-indicator only    {at_depth['discordance_rate']:.3f}   "
          f"<- the proxy this file used to assume, and should not have")
    print()

    print(f"McNemar power at alpha={ALPHA}, n={held_out} (every held-out question)")
    print("-" * 72)
    print("Grade discordance is unknown before the run. Columns bracket it.")
    print()
    header = f"{'true difference':>16}" + "".join(
        f"{f'd={d:.2f}':>12}" for d in discordances)
    print(header)
    for delta in deltas:
        cells = ""
        for d_grade in discordances:
            cell = grid[f"grade_discordance_{d_grade:.2f}"][f"delta_{delta:.3f}"]
            if cell.get("impossible_at_this_discordance"):
                cells += f"{'n/a':>12}"
            else:
                cells += f"{cell[f'power_at_n_{held_out}']:>12.2f}"
        print(f"{delta:>15.1%}{cells}")
    print()
    print(f"{'n for 0.80 power':>16}" + "".join(
        f"{f'd={d:.2f}':>12}" for d in discordances))
    for delta in deltas:
        cells = ""
        for d_grade in discordances:
            cell = grid[f"grade_discordance_{d_grade:.2f}"][f"delta_{delta:.3f}"]
            need = None if cell.get("impossible_at_this_discordance") else \
                cell["n_for_80_percent"]
            cells += f"{(str(need) if need else 'n/a'):>12}"
        print(f"{delta:>15.1%}{cells}")
    print()
    print(f"wrote {OUT_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
