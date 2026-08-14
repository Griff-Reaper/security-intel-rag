"""
Does dense retrieval earn its place when queries are not copied from documents?

Every prior measurement in this project used queries drawn from the corpus: a
CVE's identifier, its product strings, or the first sentence of its own
description. On that last one BM25 beat dense retrieval (0.870 vs 0.765), which
proves nothing about semantics - the query *was* the document, so the task
rewarded string matching.

This runs the same ablation over paraphrased questions instead
(experiments/build_eval_set.py, committed to
experiments/samples/paraphrased_eval.json).

    python experiments/paraphrased_queries.py --retrieval dense
    python experiments/paraphrased_queries.py --retrieval hybrid_rerank
    python experiments/paraphrased_queries.py --compare

The metric functions are imported from identifier_queries.py rather than
rewritten, so Recall@1 means exactly what it meant in Phase 2 and the two sets
of numbers can be read side by side.

Results are stratified by *leakage* - the share of a question's content words
that also appear in its target document. Paraphrasing lowers leakage but cannot
remove it: an analyst searching for a Log4j bug will type "log4j". The
low-leakage stratum is the closest thing here to a pure semantic test, and it is
the stratum that answers the question in the title.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "experiments"))

import lexical_index as LX  # noqa: E402
import provenance  # noqa: E402
import retrieval  # noqa: E402
from embeddings import EmbeddingService  # noqa: E402

# Same metric code as the identifier ablation. Importing rather than copying is
# the only way the two tables stay comparable as either changes.
from identifier_queries import DEPTH, rank_of, summarize  # noqa: E402

EVAL_PATH = PROJECT_ROOT / "experiments" / "samples" / "paraphrased_eval.json"
RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
LEXICAL_DB = PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"

OVERALL = "paraphrased question"
LEAKAGE_BANDS = (("low leakage", 0.0, 1 / 3), ("mid leakage", 1 / 3, 2 / 3),
                 ("high leakage", 2 / 3, 1.01))


def load_eval_set() -> Dict[str, Any]:
    if not EVAL_PATH.exists():
        raise SystemExit(
            f"no eval set at {EVAL_PATH.relative_to(PROJECT_ROOT)}. "
            "Build it with: python experiments/build_eval_set.py"
        )
    return json.loads(EVAL_PATH.read_text(encoding="utf-8"))


def band_of(value: float) -> str:
    for name, low, high in LEAKAGE_BANDS:
        if low <= value < high:
            return name
    return LEAKAGE_BANDS[-1][0]


def measure(collection, retriever, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Rank every paraphrased question and summarize, overall and by leakage."""
    items = payload["items"]
    present = set(collection.get(ids=[i["cve_id"] for i in items], include=[])["ids"])
    missing = [i["cve_id"] for i in items if i["cve_id"] not in present]
    if missing:
        raise SystemExit(
            f"{len(missing)} eval CVEs are absent from '{collection.name}' "
            f"(e.g. {missing[:3]}); the eval set and the index disagree."
        )

    buckets: Dict[str, List[Optional[int]]] = {OVERALL: []}
    for name, _, _ in LEAKAGE_BANDS:
        buckets[name] = []
    specific_ranks: List[Optional[int]] = []
    vague_ranks: List[Optional[int]] = []
    examples: List[Dict[str, Any]] = []
    # Per-item ranks, so two configurations can be compared as a paired test
    # rather than by eyeballing two averages. A 1.6-point gap on 192 questions
    # is three queries, and whether that is a real difference depends entirely
    # on whether the same queries moved.
    per_item: Dict[str, Optional[int]] = {}

    for item in items:
        rank = rank_of(retriever, item["question"], item["cve_id"], DEPTH)
        buckets[OVERALL].append(rank)
        buckets[band_of(item["leakage_vs_target"])].append(rank)
        per_item[item["cve_id"]] = rank
        (specific_ranks if item.get("specific", True) else vague_ranks).append(rank)
        if len(examples) < 5:
            examples.append({
                "cve_id": item["cve_id"],
                "question": item["question"],
                "leakage": item["leakage_vs_target"],
                "rank": rank,
            })

    return {
        **provenance.stamp(),
        "collection": collection.name,
        "documents_in_collection": collection.count(),
        "eval_set": str(EVAL_PATH.relative_to(PROJECT_ROOT)),
        "eval_items": len(items),
        "eval_excluded": len(payload.get("excluded", {})),
        "search_depth": DEPTH,
        "retrieval": retriever.name,
        "retrieval_description": retriever.description,
        "query_types": {name: summarize(ranks) for name, ranks in buckets.items()},
        "by_specificity": {
            "specific": summarize(specific_ranks),
            "vague": summarize(vague_ranks),
        },
        "leakage": payload.get("leakage", {}),
        "ranks_by_cve": per_item,
        "latency": retriever.stats(),
        "examples": examples,
    }


def print_table(results: Dict[str, Any]) -> None:
    print(f"\nretrieval: {results['retrieval_description']}")
    print(f"{'query set':<34}{'R@1':>8}{'R@10':>8}{f'top{DEPTH}':>8}{'MRR':>8}")
    print("-" * 66)
    for name, s in results["query_types"].items():
        if s["queries"]:
            print(f"{name:<34}{s['recall_at_1']:>8.3f}{s['recall_at_10']:>8.3f}"
                  f"{s[f'found_in_top_{DEPTH}']:>8.3f}{s['mrr']:>8.3f}")
    print()
    for name, s in results["by_specificity"].items():
        if s["queries"]:
            print(f"{'  description ' + name:<34}{s['recall_at_1']:>8.3f}"
                  f"{s['recall_at_10']:>8.3f}{s[f'found_in_top_{DEPTH}']:>8.3f}"
                  f"{s['mrr']:>8.3f}  (n={s['queries']})")

    end_to_end = (results.get("latency") or {}).get("end_to_end")
    if end_to_end:
        print(f"\nlatency p50 {end_to_end['p50_ms']:.1f} ms | "
              f"p95 {end_to_end['p95_ms']:.1f} ms")


def compare() -> None:
    files = sorted(RESULTS_DIR.glob("paraphrased_queries_*.json"))
    if not files:
        raise SystemExit("no paraphrased result files yet")
    runs = [json.loads(f.read_text(encoding="utf-8")) for f in files]

    for query_set in [OVERALL] + [n for n, _, _ in LEAKAGE_BANDS]:
        rows = [r for r in runs if r["query_types"].get(query_set, {}).get("queries")]
        if not rows:
            continue
        print(f"\n{query_set}")
        print(f"{'retrieval':<26}{'R@1':>9}{'R@10':>9}{'MRR':>9}{'R@1 vs dense':>16}")
        print("-" * 69)
        baseline = next((r["query_types"][query_set]["recall_at_1"]
                         for r in rows if r["retrieval"] == "dense"), None)
        for r in rows:
            s = r["query_types"][query_set]
            delta = "" if baseline is None or r["retrieval"] == "dense" \
                else f"{s['recall_at_1'] - baseline:+.3f}"
            print(f"{r['retrieval']:<26}{s['recall_at_1']:>9.3f}"
                  f"{s['recall_at_10']:>9.3f}{s['mrr']:>9.3f}{delta:>16}")


PAIRED_PATH = RESULTS_DIR / "paraphrased_paired_tests.json"

# Comparisons worth testing: each isolates one component's contribution.
PAIRINGS = (
    ("bm25", "dense"),
    ("hybrid_rerank", "dense"),
    ("hybrid_rerank", "bm25"),
    ("hybrid", "bm25"),
)


def mcnemar(a_ranks, b_ranks, ids, k: int) -> Dict[str, Any]:
    """
    Exact McNemar test on hit@k between two configurations.

    Averages hide whether a 1.6-point gap is three queries moving or three
    hundred. Only the *discordant* pairs carry information - questions both
    configurations get right, or both get wrong, say nothing about which is
    better - so the test counts those and asks whether the split is further from
    even than chance would produce.
    """
    def hit(rank):
        return rank is not None and rank <= k

    a_only = sum(1 for i in ids if hit(a_ranks[i]) and not hit(b_ranks[i]))
    b_only = sum(1 for i in ids if hit(b_ranks[i]) and not hit(a_ranks[i]))
    n = a_only + b_only
    if n == 0:
        return {"a_wins": 0, "b_wins": 0, "discordant": 0, "p_value": 1.0}
    smaller = min(a_only, b_only)
    tail = sum(math.comb(n, i) for i in range(smaller + 1))
    return {
        "a_wins": a_only,
        "b_wins": b_only,
        "discordant": n,
        "p_value": round(min(1.0, 2 * tail / 2 ** n), 4),
    }


def paired_tests() -> None:
    """Compare configurations pairwise and commit the result."""
    ranks: Dict[str, Dict[str, Optional[int]]] = {}
    for path in RESULTS_DIR.glob("paraphrased_queries_*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if "ranks_by_cve" in payload:
            ranks[payload["retrieval"]] = payload["ranks_by_cve"]
    if len(ranks) < 2:
        raise SystemExit("need at least two result files carrying ranks_by_cve")

    ids = sorted(set.intersection(*(set(v) for v in ranks.values())))
    out: Dict[str, Any] = {
        **provenance.stamp(),
        "test": "exact McNemar on hit@k, two-sided",
        "questions": len(ids),
        "note": "only discordant pairs are informative; p is the probability of "
                "a split at least this uneven under the null that the two "
                "configurations are equally likely to win a disagreement",
        "comparisons": {},
    }

    for a, b in PAIRINGS:
        if a not in ranks or b not in ranks:
            continue
        out["comparisons"][f"{a} vs {b}"] = {
            f"recall_at_{k}": mcnemar(ranks[a], ranks[b], ids, k) for k in (1, 10, 100)
        }

    # What each arm uniquely contributes, which an average cannot show.
    if "dense" in ranks and "bm25" in ranks:
        dense_only = [i for i in ids if ranks["dense"][i] == 1 and ranks["bm25"][i] != 1]
        bm25_only = [i for i in ids if ranks["bm25"][i] == 1 and ranks["dense"][i] != 1]
        kept = [i for i in dense_only
                if ranks.get("hybrid_rerank", {}).get(i) == 1]
        out["complementarity"] = {
            "rank_1_dense_only": len(dense_only),
            "rank_1_bm25_only": len(bm25_only),
            "dense_only_wins_kept_by_hybrid_rerank": len(kept),
        }

    PAIRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAIRED_PATH.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    print(f"exact McNemar, {len(ids)} paired questions")
    for name, byk in out["comparisons"].items():
        r1 = byk["recall_at_1"]
        print(f"  {name:<32} R@1 {r1['a_wins']:>3} vs {r1['b_wins']:>3}  "
              f"p={r1['p_value']:.4f}")
    if "complementarity" in out:
        c = out["complementarity"]
        print(f"\n  dense returns {c['rank_1_dense_only']} questions at rank 1 "
              f"that bm25 misses; bm25 returns {c['rank_1_bm25_only']} that "
              f"dense misses")
        print(f"  hybrid_rerank keeps {c['dense_only_wins_kept_by_hybrid_rerank']} "
              f"of the dense-only wins")
    print(f"\nwrote {PAIRED_PATH.relative_to(PROJECT_ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--lexical-db", default=str(LEXICAL_DB))
    parser.add_argument("--retrieval", default="dense", choices=list(retrieval.MODES))
    parser.add_argument("--direct-id", action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--paired", action="store_true",
                        help="paired significance tests across existing results")
    args = parser.parse_args()

    if args.compare:
        compare()
        return
    if args.paired:
        paired_tests()
        return

    provenance.require_layout_match()
    payload = load_eval_set()

    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)

    needs_dense = args.retrieval in ("dense", "hybrid", "hybrid_rerank")
    needs_lexical = args.retrieval in ("bm25", "hybrid", "hybrid_rerank") or args.direct_id
    lexical_conn = LX.connect(Path(args.lexical_db), read_only=True) if needs_lexical else None

    retriever = retrieval.build_retriever(
        args.retrieval,
        collection=collection,
        embedder=EmbeddingService() if needs_dense else None,
        lexical_conn=lexical_conn,
        direct_id=args.direct_id,
    )

    print(f"eval set: {len(payload['items'])} paraphrased questions "
          f"({len(payload.get('excluded', {}))} CVEs excluded)")
    results = measure(collection, retriever, payload)
    print_table(results)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"paraphrased_queries_{retriever.name}.json"
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
