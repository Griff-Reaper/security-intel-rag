"""
Paired significance testing for retrieval comparisons.

Recall@1 differences on a 200-query sample are a handful of queries wide. Two
averages three points apart can mean one configuration is genuinely better, or
that three queries moved for reasons that would not survive a different sample,
and subtracting the averages cannot tell those apart.

Every comparison here is therefore *paired*: the two configurations answer the
same queries, so the only informative cases are the ones where they disagree.
Queries both get right, or both get wrong, carry no signal about which is
better and are excluded. What remains is a count of disagreements in each
direction, and an exact binomial test against the null that a disagreement is
equally likely to fall either way - McNemar's test.

A large p-value here means "this sample cannot tell these apart", not "these are
the same". With around 200 queries the design cannot reliably detect a true
difference smaller than roughly ten points, so an absence of significance is a
statement about the measurement's resolution as much as about the systems.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

# The comparisons worth running: each isolates one component's contribution.
DEFAULT_PAIRINGS: Tuple[Tuple[str, str], ...] = (
    ("bm25", "dense"),
    ("hybrid_rerank", "dense"),
    ("hybrid_rerank", "bm25"),
    ("hybrid", "bm25"),
)

DEFAULT_DEPTHS: Tuple[int, ...] = (1, 10, 100)


def hit(rank: Optional[int], k: int) -> bool:
    """Did the target land within the top k? A miss is None, not a large rank."""
    return rank is not None and rank <= k


def exact_binomial_two_sided(smaller: int, total: int) -> float:
    """P(a split at least this uneven) under a fair coin, both tails."""
    if total == 0:
        return 1.0
    tail = sum(math.comb(total, i) for i in range(smaller + 1))
    return min(1.0, 2 * tail / 2 ** total)


def mcnemar(
    a_ranks: Mapping[str, Optional[int]],
    b_ranks: Mapping[str, Optional[int]],
    ids: Sequence[str],
    k: int,
) -> Dict[str, Any]:
    """Exact McNemar test on hit@k between two configurations over shared queries."""
    a_only = sum(1 for i in ids if hit(a_ranks.get(i), k) and not hit(b_ranks.get(i), k))
    b_only = sum(1 for i in ids if hit(b_ranks.get(i), k) and not hit(a_ranks.get(i), k))
    total = a_only + b_only
    return {
        "a_wins": a_only,
        "b_wins": b_only,
        "discordant": total,
        "p_value": round(exact_binomial_two_sided(min(a_only, b_only), total), 4),
        "significant_at_05": exact_binomial_two_sided(min(a_only, b_only), total) < 0.05,
    }


def shared_ids(rank_sets: Iterable[Mapping[str, Optional[int]]]) -> list:
    """Queries every configuration answered, so the comparison stays paired."""
    sets = [set(r) for r in rank_sets]
    return sorted(set.intersection(*sets)) if sets else []


def compare_all(
    ranks_by_config: Mapping[str, Mapping[str, Optional[int]]],
    pairings: Sequence[Tuple[str, str]] = DEFAULT_PAIRINGS,
    depths: Sequence[int] = DEFAULT_DEPTHS,
) -> Dict[str, Any]:
    """Run every applicable pairing at every depth."""
    ids = shared_ids(ranks_by_config.values())
    out: Dict[str, Any] = {
        "test": "exact McNemar on hit@k, two-sided",
        "queries": len(ids),
        "note": "only discordant pairs are informative; a large p means this "
                "sample cannot separate the two, not that they are equal",
        "comparisons": {},
    }
    for a, b in pairings:
        if a not in ranks_by_config or b not in ranks_by_config:
            continue
        out["comparisons"][f"{a} vs {b}"] = {
            f"recall_at_{k}": mcnemar(ranks_by_config[a], ranks_by_config[b], ids, k)
            for k in depths
        }
    return out


def complementarity(
    ranks_by_config: Mapping[str, Mapping[str, Optional[int]]],
    arm_a: str = "dense",
    arm_b: str = "bm25",
    fused: str = "hybrid_rerank",
) -> Optional[Dict[str, int]]:
    """
    What each arm answers alone that the other does not, and how much survives.

    An average cannot show this: two arms scoring the same can be right about
    the same queries or about disjoint ones, and only the second case makes
    fusing them worth anything.
    """
    if arm_a not in ranks_by_config or arm_b not in ranks_by_config:
        return None
    ids = shared_ids(ranks_by_config.values())
    a, b = ranks_by_config[arm_a], ranks_by_config[arm_b]
    a_only = [i for i in ids if a.get(i) == 1 and b.get(i) != 1]
    b_only = [i for i in ids if b.get(i) == 1 and a.get(i) != 1]
    result = {
        f"rank_1_{arm_a}_only": len(a_only),
        f"rank_1_{arm_b}_only": len(b_only),
    }
    if fused in ranks_by_config:
        kept = sum(1 for i in a_only if ranks_by_config[fused].get(i) == 1)
        result[f"{arm_a}_only_wins_kept_by_{fused}"] = kept
    return result


def print_report(report: Dict[str, Any], depth: int = 1) -> None:
    """Human-readable summary at one depth."""
    print(f"exact McNemar, {report['queries']} paired queries")
    for name, by_depth in report["comparisons"].items():
        row = by_depth[f"recall_at_{depth}"]
        marker = "  significant" if row["significant_at_05"] else ""
        print(f"  {name:<32} R@{depth} {row['a_wins']:>3} vs {row['b_wins']:>3}  "
              f"p={row['p_value']:.4f}{marker}")
