"""
Why does RRF fusion rank worse than the BM25 arm it contains?

The ablation shows hybrid below bm25 on Recall@1 for every query type, which is
not what fusing a strong arm with a weak one is supposed to do. This script
tests the suspected mechanism: score ties.

With two arms and k = 60, a document at rank r in exactly one arm scores
1/(60+r). If the arms return disjoint candidates - which is close to true for
identifier queries, where dense retrieval finds the target 0.5% of the time -
then for every rank r there are two documents with byte-identical scores, one
from each arm. RRF has no preference between them, so the ordering falls to
whatever tie-break the implementation happens to use, and the correct answer
wins or loses by something unrelated to relevance.

    python experiments/rrf_ties.py

Writes experiments/results/rrf_ties.json.

IMPORTANT - this runs on a DEV sample, not the pinned evaluation sample.
Tie-breaking is a retrieval parameter. Measuring candidate policies against
experiments/samples/identifier_sample.json would be tuning on the evaluation
set, and every published comparison against the dense baseline would then be
reporting a choice that had already seen the answers. The dev sample is drawn
with a different seed and explicitly excludes every pinned ID.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import lexical_index as LX  # noqa: E402
import nvd_normalize as N  # noqa: E402
import retrieval as R  # noqa: E402
from embeddings import EmbeddingService  # noqa: E402

RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "rrf_ties.json"
DEV_SAMPLE_PATH = PROJECT_ROOT / "experiments" / "samples" / "dev_sample.json"
PINNED_SAMPLE_PATH = PROJECT_ROOT / "experiments" / "samples" / "identifier_sample.json"

DEV_SEED = 20260813          # deliberately not the evaluation seed
DEV_SIZE = 200


def load_or_draw_dev_sample(collection) -> List[str]:
    """Draw a dev sample disjoint from the pinned evaluation sample, and pin it too.

    The dev sample is pinned for the same reason the evaluation sample is: a
    parameter chosen against a moving sample cannot be re-checked later.
    """
    if DEV_SAMPLE_PATH.exists():
        return json.loads(DEV_SAMPLE_PATH.read_text(encoding="utf-8"))["cve_ids"]

    held_out = set(json.loads(PINNED_SAMPLE_PATH.read_text(encoding="utf-8"))["cve_ids"])
    candidates = [cid for cid in collection.get(include=[])["ids"] if cid not in held_out]
    sampled = random.Random(DEV_SEED).sample(candidates, min(DEV_SIZE, len(candidates)))

    DEV_SAMPLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEV_SAMPLE_PATH.write_text(
        json.dumps({
            "purpose": "dev set for tuning retrieval parameters; never used for "
                       "reported accuracy numbers",
            "seed": DEV_SEED,
            "sample_size": len(sampled),
            "disjoint_from": str(PINNED_SAMPLE_PATH.relative_to(PROJECT_ROOT)),
            "cve_ids": sampled,
        }, indent=2) + "\n",
        encoding="utf-8",
    )
    return sampled


# ── Tie-break policies ───────────────────────────────────────────────────────
# Each takes the per-arm rankings and returns a sort key applied *after* the RRF
# score, so none of them can change the score itself - only the order within a
# group the formula considers equal.
def policy_document_id(_arms: List[List[str]]) -> Callable[[str], Any]:
    """Lexicographic by CVE ID. Arbitrary with respect to relevance."""
    return lambda doc_id: doc_id


def policy_prefer_lexical(arms: List[List[str]]) -> Callable[[str], Any]:
    """Prefer the document the lexical arm ranked higher. An arm weighting."""
    lexical = {doc: rank for rank, doc in enumerate(arms[1])}
    return lambda doc_id: (lexical.get(doc_id, len(arms[1]) + 1), doc_id)


def policy_prefer_dense(arms: List[List[str]]) -> Callable[[str], Any]:
    """The mirror image, included so the asymmetry is visible rather than assumed."""
    dense = {doc: rank for rank, doc in enumerate(arms[0])}
    return lambda doc_id: (dense.get(doc_id, len(arms[0]) + 1), doc_id)


POLICIES: Dict[str, Callable[[List[List[str]]], Callable[[str], Any]]] = {
    "document_id": policy_document_id,
    "prefer_lexical_arm (shipped)": policy_prefer_lexical,
    "prefer_dense_arm": policy_prefer_dense,
}


def fuse_with_policy(arms: List[List[str]], policy_name: str, k: int) -> List[str]:
    scored = R.reciprocal_rank_fusion(arms, k=k)
    secondary = POLICIES[policy_name](arms)
    return [doc for doc, _ in sorted(scored, key=lambda item: (-item[1], secondary(item[0])))]


def tie_report(arms: List[List[str]], target: str, k: int) -> Optional[Dict[str, Any]]:
    """How many documents share the target's exact fused score, and how many outrank it."""
    scored = R.reciprocal_rank_fusion(arms, k=k)
    scores = dict(scored)
    if target not in scores:
        return None
    target_score = scores[target]
    tied = [doc for doc, s in scored if s == target_score]
    strictly_better = sum(1 for _, s in scored if s > target_score)
    return {
        "tied_group_size": len(tied),
        "strictly_better": strictly_better,
        # The target can only reach rank 1 at all if nothing scores higher.
        "reachable_rank_1": strictly_better == 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--lexical-db",
                        default=str(PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"))
    args = parser.parse_args()

    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)
    conn = LX.connect(Path(args.lexical_db), read_only=True)

    dev_ids = load_or_draw_dev_sample(collection)
    pinned = set(json.loads(PINNED_SAMPLE_PATH.read_text(encoding="utf-8"))["cve_ids"])
    overlap = pinned & set(dev_ids)
    if overlap:
        raise SystemExit(f"dev sample overlaps the evaluation sample: {sorted(overlap)[:5]}")
    print(f"dev sample: {len(dev_ids)} CVEs (seed {DEV_SEED}), "
          f"0 shared with the pinned evaluation sample\n")

    hybrid = R.HybridRetriever(collection, EmbeddingService(), conn)
    records = collection.get(ids=dev_ids, include=["metadatas"])

    queries: List[Tuple[str, str, str]] = []
    for cve_id, meta in zip(records["ids"], records["metadatas"]):
        queries.append(("bare CVE ID", cve_id, cve_id))
        products = (meta.get("products") or "").split(N.LIST_DELIMITER)
        if products and products[0]:
            year = (meta.get("year") or "").strip()
            queries.append(("product + version",
                            f"{products[0]} {year}".strip(), cve_id))

    by_type: Dict[str, Dict[str, Any]] = {}
    for query_type in ("bare CVE ID", "product + version"):
        subset = [(q, t) for qt, q, t in queries if qt == query_type]
        ties, ceiling_hits, policy_hits = [], 0, {name: 0 for name in POLICIES}

        for query, target in subset:
            arms = hybrid._arms(query)
            report = tie_report(arms, target, R.RRF_K)
            if report is None:
                continue
            ties.append(report["tied_group_size"])
            if report["reachable_rank_1"]:
                ceiling_hits += 1
            for name in POLICIES:
                if fuse_with_policy(arms, name, R.RRF_K)[0] == target:
                    policy_hits[name] += 1

        n = max(len(subset), 1)
        by_type[query_type] = {
            "queries": len(subset),
            "target_found": len(ties),
            "mean_tied_group_size": round(sum(ties) / max(len(ties), 1), 2),
            "share_in_a_tie": round(sum(1 for t in ties if t > 1) / max(len(ties), 1), 4),
            # The best Recall@1 any tie-break could reach: nothing outscores the target.
            "recall_at_1_ceiling": round(ceiling_hits / n, 4),
            "recall_at_1_by_policy": {
                name: round(hits / n, 4) for name, hits in policy_hits.items()
            },
        }

        print(query_type)
        print(f"  targets found in the fused list : {len(ties)}/{len(subset)}")
        print(f"  share sharing their exact score : {by_type[query_type]['share_in_a_tie']:.3f}")
        print(f"  mean tied-group size            : {by_type[query_type]['mean_tied_group_size']}")
        print(f"  R@1 ceiling (best possible)     : {by_type[query_type]['recall_at_1_ceiling']:.3f}")
        for name, hits in policy_hits.items():
            print(f"    R@1 with {name:<22}: {hits / n:.3f}")
        print()

    conn.close()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps({
        "sample": "dev",
        "sample_path": str(DEV_SAMPLE_PATH.relative_to(PROJECT_ROOT)),
        "sample_seed": DEV_SEED,
        "disjoint_from_evaluation_sample": True,
        "rrf_k": R.RRF_K,
        "arm_depth": R.ARM_DEPTH,
        "query_types": by_type,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {RESULTS_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
