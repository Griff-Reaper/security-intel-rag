"""
How well does dense-only retrieval handle identifier-style queries?

Security queries are full of exact identifiers: a bare CVE ID, a product plus a
version string. Dense embeddings are poor at these - a 384-dimensional vector of
"CVE-2021-44228" is nearly indistinguishable from one of any other CVE ID,
because the strings differ only in digits that carry no semantic weight.

This script measures the size of that gap on the live index by asking, for a
sample of CVEs, where the correct record ranks when the query is:

  1. the CVE's own identifier, verbatim
  2. its affected product name plus a version string
  3. its description's opening sentence (a semantic control)

    python experiments/identifier_queries.py

Results are written to experiments/results/identifier_queries.json.

The control case exists to separate two failure modes: if the semantic query
succeeds while the identifier query fails, retrieval is working and the problem
is specific to identifiers - which is what lexical/hybrid search is for.
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import nvd_normalize as N
from embeddings import EmbeddingService

RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "identifier_queries.json"
SEED = 20260812
DEPTH = 100


def rank_of(collection, embedder, query: str, target: str, depth: int) -> Optional[int]:
    """1-based rank of `target` within the top `depth` hits, or None."""
    hits = collection.query(
        query_embeddings=[embedder.get_embedding(query)], n_results=depth
    )["ids"][0]
    return hits.index(target) + 1 if target in hits else None


def summarize(name: str, ranks: List[Optional[int]]) -> Dict[str, Any]:
    found = [r for r in ranks if r is not None]
    n = len(ranks)
    return {
        "queries": n,
        "recall_at_1": round(sum(1 for r in found if r == 1) / n, 4),
        "recall_at_10": round(sum(1 for r in found if r <= 10) / n, 4),
        f"found_in_top_{DEPTH}": round(len(found) / n, 4),
        "mrr": round(sum(1 / r for r in found) / n, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--sample", type=int, default=200)
    args = parser.parse_args()

    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)
    total = collection.count()
    print(f"collection '{args.collection}': {total:,} documents")

    # Sample IDs from the collection itself so the experiment needs no feed files.
    all_ids = collection.get(include=[])["ids"]
    rng = random.Random(SEED)
    sampled = rng.sample(all_ids, min(args.sample, len(all_ids)))
    records = collection.get(ids=sampled, include=["documents", "metadatas"])

    embedder = EmbeddingService()
    buckets: Dict[str, List[Optional[int]]] = {
        "bare CVE ID": [],
        "product + version": [],
        "description sentence (control)": [],
    }
    examples = []

    for cve_id, document, meta in zip(
        records["ids"], records["documents"], records["metadatas"]
    ):
        buckets["bare CVE ID"].append(rank_of(collection, embedder, cve_id, cve_id, DEPTH))

        products = (meta.get("products") or "").split(N.LIST_DELIMITER)
        product = products[0] if products and products[0] else None
        if product:
            year = (meta.get("year") or "").strip()
            query = f"{product} {year}" if year else product
            buckets["product + version"].append(
                rank_of(collection, embedder, query, cve_id, DEPTH)
            )

        # The document begins "CVE-xxxx-yyyy: <description>"; take its first sentence.
        body = document.split(": ", 1)[-1]
        cut = body.find(". ")
        sentence = body[: cut + 1] if 0 < cut < 240 else body[:240]
        buckets["description sentence (control)"].append(
            rank_of(collection, embedder, sentence, cve_id, DEPTH)
        )

        if len(examples) < 5:
            examples.append({
                "cve_id": cve_id,
                "rank_for_own_id": buckets["bare CVE ID"][-1],
                "rank_for_description": buckets["description sentence (control)"][-1],
            })

    print(f"\n{'query type':<34}{'R@1':>8}{'R@10':>8}{f'top{DEPTH}':>8}{'MRR':>8}")
    print("-" * 66)
    results: Dict[str, Any] = {
        "collection": args.collection,
        "documents_in_collection": total,
        "sample_size": len(sampled),
        "seed": SEED,
        "search_depth": DEPTH,
        "retrieval": "dense-only (cosine over all-MiniLM-L6-v2)",
        "query_types": {},
        "examples": examples,
    }
    for name, ranks in buckets.items():
        stats = summarize(name, ranks)
        results["query_types"][name] = stats
        print(f"{name:<34}{stats['recall_at_1']:>8.3f}{stats['recall_at_10']:>8.3f}"
              f"{stats[f'found_in_top_{DEPTH}']:>8.3f}{stats['mrr']:>8.3f}")

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {RESULTS_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
