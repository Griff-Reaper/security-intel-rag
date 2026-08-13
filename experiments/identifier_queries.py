#!/usr/bin/env python3
"""
How well does retrieval handle identifier-style queries?

Part of: Security Intelligence RAG
Version: 0.2.0

Security queries are full of exact identifiers: a bare CVE ID, a product plus a
version string. Dense embeddings are poor at these - a 384-dimensional vector of
"CVE-2021-44228" is nearly indistinguishable from one of any other CVE ID,
because the strings differ only in digits that carry no semantic weight.

This script measures the size of that gap on the live index by asking, for a
fixed sample of CVEs, where the correct record ranks when the query is:

  1. the CVE's own identifier, verbatim
  2. its affected product name plus a version string
  3. its description's opening sentence (a semantic control)

The control case exists to separate two failure modes: if the semantic query
succeeds while the identifier query fails, retrieval is working and the problem
is specific to identifiers - which is what lexical/hybrid search is for.

Usage:

    # One time, BEFORE changing retrieval: freeze the sample.
    python experiments/identifier_queries.py --pin-sample

    # Measure a retrieval configuration.
    python experiments/identifier_queries.py --retrieval dense
    python experiments/identifier_queries.py --retrieval bm25
    python experiments/identifier_queries.py --retrieval hybrid
    python experiments/identifier_queries.py --retrieval hybrid_rerank

    # Print the ablation table across whatever has been measured.
    python experiments/identifier_queries.py --compare

Results are written per configuration to
experiments/results/identifier_queries_<retrieval>.json, so runs never
overwrite each other and the ablation can be rebuilt at any time.

The sample is pinned to experiments/samples/identifier_sample.json and committed.
Every configuration is therefore measured against byte-identical queries; if the
sample were re-drawn per run, a change in the numbers could not be attributed to
the retrieval change.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import lexical_index as LX  # noqa: E402
import nvd_normalize as N  # noqa: E402
import retrieval  # noqa: E402
from embeddings import EmbeddingService  # noqa: E402
from retrieval import Retriever, build_retriever  # noqa: E402

# ── Constants ────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

RESULTS_DIR = PROJECT_ROOT / "experiments" / "results"
SAMPLE_PATH = PROJECT_ROOT / "experiments" / "samples" / "identifier_sample.json"
LEXICAL_DB = PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"

SEED = 20260812          # unchanged from v0.1.0 so the pin reproduces the original draw
DEPTH = 100              # how deep to look for the target before calling it a miss
DEFAULT_SAMPLE = 200
SENTENCE_MAX = 240

BARE_ID = "bare CVE ID"
PRODUCT = "product + version"
CONTROL = "description sentence (control)"

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("identifier_queries")


# ── Retrieval backends ───────────────────────────────────────────────────────
# The backends live in src/retrieval.py so the API and the CLI use the same
# ranking code that is measured here; an experiment that scores a private copy
# of retrieval measures something the product does not ship. Every backend
# satisfies the same Retriever protocol - name, description, search(query,
# depth) -> ranked IDs - so the metrics below are computed identically no matter
# how the ranking was produced.


# ── Sampling ─────────────────────────────────────────────────────────────────
def draw_sample(collection, size: int) -> List[str]:
    """Draw a reproducible sample of document IDs from the collection.

    Uses a fixed seed, but note that seeding alone is not sufficient for
    comparability: the draw also depends on the number and order of IDs the
    collection returns, both of which change as the corpus grows. That is why
    the result gets pinned to disk.
    """
    all_ids = collection.get(include=[])["ids"]
    rng = random.Random(SEED)
    return rng.sample(all_ids, min(size, len(all_ids)))


def load_pinned_sample() -> Optional[List[str]]:
    """Return the committed sample IDs, or None if no pin file exists."""
    if not SAMPLE_PATH.exists():
        return None
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    return payload["cve_ids"]


def write_pinned_sample(collection, size: int) -> List[str]:
    """Draw a sample and commit it to disk as the fixed evaluation set."""
    sampled = draw_sample(collection, size)
    SAMPLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SAMPLE_PATH.write_text(
        json.dumps(
            {
                "seed": SEED,
                "sample_size": len(sampled),
                "documents_in_collection_at_draw": collection.count(),
                "cve_ids": sampled,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    logger.info("pinned %d IDs to %s", len(sampled), SAMPLE_PATH.relative_to(PROJECT_ROOT))
    return sampled


# ── Metrics ──────────────────────────────────────────────────────────────────
def rank_of(retriever: Retriever, query: str, target: str, depth: int) -> Optional[int]:
    """1-based rank of `target` within the top `depth` hits, or None if absent."""
    hits = retriever.search(query, depth)
    return hits.index(target) + 1 if target in hits else None


def summarize(ranks: List[Optional[int]]) -> Dict[str, Any]:
    """Recall@1, Recall@10, found-in-top-DEPTH and MRR over a list of ranks.

    Misses count against every metric: they stay in the denominator and
    contribute nothing to the numerator.
    """
    found = [r for r in ranks if r is not None]
    n = len(ranks)
    if n == 0:
        return {"queries": 0, "recall_at_1": 0.0, "recall_at_10": 0.0,
                f"found_in_top_{DEPTH}": 0.0, "mrr": 0.0}
    return {
        "queries": n,
        "recall_at_1": round(sum(1 for r in found if r == 1) / n, 4),
        "recall_at_10": round(sum(1 for r in found if r <= 10) / n, 4),
        f"found_in_top_{DEPTH}": round(len(found) / n, 4),
        "mrr": round(sum(1 / r for r in found) / n, 4),
    }


def first_sentence(document: str) -> str:
    """Extract the description's opening sentence from a stored document."""
    body = document.split(": ", 1)[-1]
    cut = body.find(". ")
    return body[: cut + 1] if 0 < cut < SENTENCE_MAX else body[:SENTENCE_MAX]


# ── Measurement ──────────────────────────────────────────────────────────────
def measure(collection, retriever: Retriever, sample_ids: List[str]) -> Dict[str, Any]:
    """Run all three query types over the pinned sample and summarize."""
    records = collection.get(ids=sample_ids, include=["documents", "metadatas"])

    returned = set(records["ids"])
    missing = [cid for cid in sample_ids if cid not in returned]
    if missing:
        # Failing here is deliberate. Silently measuring a smaller set would
        # make the ablation invalid in a way the output would not reveal.
        raise SystemExit(
            f"{len(missing)} pinned IDs are absent from collection "
            f"'{collection.name}' (e.g. {missing[:3]}). The pin and the index "
            "disagree; re-pin only if you intend to abandon comparability."
        )

    buckets: Dict[str, List[Optional[int]]] = {BARE_ID: [], PRODUCT: [], CONTROL: []}
    examples: List[Dict[str, Any]] = []

    for cve_id, document, meta in zip(
        records["ids"], records["documents"], records["metadatas"]
    ):
        buckets[BARE_ID].append(rank_of(retriever, cve_id, cve_id, DEPTH))

        products = (meta.get("products") or "").split(N.LIST_DELIMITER)
        product = products[0] if products and products[0] else None
        if product:
            year = (meta.get("year") or "").strip()
            query = f"{product} {year}" if year else product
            buckets[PRODUCT].append(rank_of(retriever, query, cve_id, DEPTH))

        buckets[CONTROL].append(
            rank_of(retriever, first_sentence(document), cve_id, DEPTH)
        )

        if len(examples) < 5:
            examples.append({
                "cve_id": cve_id,
                "rank_for_own_id": buckets[BARE_ID][-1],
                "rank_for_description": buckets[CONTROL][-1],
            })

    return {
        "collection": collection.name,
        "documents_in_collection": collection.count(),
        "sample_size": len(sample_ids),
        "sample_source": str(SAMPLE_PATH.relative_to(PROJECT_ROOT)),
        "seed": SEED,
        "search_depth": DEPTH,
        "retrieval": retriever.name,
        "retrieval_description": retriever.description,
        "query_types": {name: summarize(ranks) for name, ranks in buckets.items()},
        # Recorded by the backend itself over every query above, so the timing
        # covers the same work the accuracy numbers describe.
        "latency": retriever.stats(),
        "examples": examples,
    }


def print_table(results: Dict[str, Any]) -> None:
    """Print one configuration's results as a fixed-width table."""
    print(f"\nretrieval: {results['retrieval_description']}")
    print(f"{'query type':<34}{'R@1':>8}{'R@10':>8}{f'top{DEPTH}':>8}{'MRR':>8}")
    print("-" * 66)
    for name, s in results["query_types"].items():
        print(f"{name:<34}{s['recall_at_1']:>8.3f}{s['recall_at_10']:>8.3f}"
              f"{s[f'found_in_top_{DEPTH}']:>8.3f}{s['mrr']:>8.3f}")

    latency = results.get("latency") or {}
    if latency:
        print(f"\n{'latency (ms)':<34}{'p50':>8}{'p95':>8}{'mean':>8}")
        print("-" * 66)
        for stage, s in latency.items():
            if isinstance(s, dict) and "p50_ms" in s:
                print(f"{stage:<34}{s['p50_ms']:>8.1f}{s['p95_ms']:>8.1f}"
                      f"{s['mean_ms']:>8.1f}")


def compare() -> None:
    """Print the ablation table across every configuration measured so far."""
    files = sorted(RESULTS_DIR.glob("identifier_queries_*.json"))
    if not files:
        raise SystemExit(f"no result files in {RESULTS_DIR.relative_to(PROJECT_ROOT)}")

    runs = [json.loads(f.read_text(encoding="utf-8")) for f in files]

    samples = {r.get("sample_size") for r in runs}
    if len(samples) > 1:
        logger.warning(
            "result files disagree on sample size %s - they are not comparable", samples
        )

    for query_type in (BARE_ID, PRODUCT, CONTROL):
        print(f"\n{query_type}")
        # ASCII only: the Windows console defaults to cp1252 and a stray
        # non-ASCII character in a header aborts the whole report.
        print(f"{'retrieval':<20}{'R@1':>9}{'R@10':>9}{'MRR':>9}{'R@1 vs dense':>16}")
        print("-" * 63)
        baseline = next(
            (r["query_types"][query_type]["recall_at_1"]
             for r in runs if r["retrieval"] == "dense"),
            None,
        )
        for r in runs:
            s = r["query_types"][query_type]
            delta = "" if baseline is None or r["retrieval"] == "dense" \
                else f"{s['recall_at_1'] - baseline:+.3f}"
            print(f"{r['retrieval']:<20}{s['recall_at_1']:>9.3f}"
                  f"{s['recall_at_10']:>9.3f}{s['mrr']:>9.3f}{delta:>16}")

    # Accuracy without cost is half the comparison.
    print("\nend-to-end latency per query")
    print(f"{'retrieval':<20}{'p50 ms':>9}{'p95 ms':>9}{'mean ms':>9}")
    print("-" * 47)
    for r in runs:
        end_to_end = (r.get("latency") or {}).get("end_to_end")
        if not end_to_end:
            print(f"{r['retrieval']:<20}{'n/a':>9}{'n/a':>9}{'n/a':>9}")
            continue
        print(f"{r['retrieval']:<20}{end_to_end['p50_ms']:>9.1f}"
              f"{end_to_end['p95_ms']:>9.1f}{end_to_end['mean_ms']:>9.1f}")


# ── Entry point ──────────────────────────────────────────────────────────────
def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--retrieval", default="dense",
                        choices=list(retrieval.MODES))
    parser.add_argument("--lexical-db", default=str(LEXICAL_DB),
                        help="SQLite FTS5 index, for the bm25 and hybrid modes")
    parser.add_argument("--sample", type=int, default=DEFAULT_SAMPLE,
                        help="sample size, used only when pinning")
    parser.add_argument("--pin-sample", action="store_true",
                        help="draw and commit the fixed sample, then exit")
    parser.add_argument("--compare", action="store_true",
                        help="print the ablation across existing result files")
    args = parser.parse_args()

    if args.compare:
        compare()
        return

    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)
    logger.info("collection '%s': %s documents", args.collection, f"{collection.count():,}")

    if args.pin_sample:
        write_pinned_sample(collection, args.sample)
        return

    sample_ids = load_pinned_sample()
    if sample_ids is None:
        logger.warning(
            "no pin file at %s - drawing from the live collection. Run "
            "--pin-sample to freeze it before comparing configurations.",
            SAMPLE_PATH.relative_to(PROJECT_ROOT),
        )
        sample_ids = draw_sample(collection, args.sample)

    # Build only what the mode needs: bm25 should not pay to load a 90 MB
    # embedding model, and dense should not require a lexical index to exist.
    needs_dense = args.retrieval in ("dense", "hybrid", "hybrid_rerank")
    needs_lexical = args.retrieval in ("bm25", "hybrid", "hybrid_rerank")

    lexical_conn = None
    if needs_lexical:
        lexical_conn = LX.connect(Path(args.lexical_db), read_only=True)
        lexical_count = LX.document_count(lexical_conn)
        if lexical_count != collection.count():
            # Fusion across two indexes that hold different documents produces
            # a number that looks like a retrieval result and is not one.
            raise SystemExit(
                f"lexical index has {lexical_count:,} documents, collection "
                f"'{args.collection}' has {collection.count():,}. Rebuild with "
                "python src/build_fts.py before measuring hybrid retrieval."
            )
        logger.info("lexical index: %s documents", f"{lexical_count:,}")

    retriever = build_retriever(
        args.retrieval,
        collection=collection,
        embedder=EmbeddingService() if needs_dense else None,
        lexical_conn=lexical_conn,
    )
    results = measure(collection, retriever, sample_ids)
    print_table(results)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"identifier_queries_{retriever.name}.json"
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
