"""
Where does BM25's latency tail come from?

The ablation reports BM25 at a p50 of 14.8 ms and a p95 of 588 ms. A 40x spread
is the kind of number that looks fine in a summary and hurts in production, so
it is worth knowing which queries are in the tail before quoting either figure.

The plausible culprit is a common term - "windows", "android" - whose postings
list covers a large share of the corpus. This script tests that against the
alternative: that cost tracks the *number* of terms in the query, because
escape_fts_query joins terms with OR and every additional term is another
postings list to walk and merge.

Three measurements:

  by query shape     the three query types the project measures, timed apart
                     instead of pooled into one percentile
  by term count      the same description truncated to 1, 2, 4 ... 32 terms,
                     which isolates length from term commonality
  by term frequency  single-term queries over terms of known document frequency,
                     which isolates commonality from length

    python experiments/lexical_latency.py

Writes experiments/results/lexical_latency.json.

Runs on the dev sample, not the pinned evaluation sample. Nothing here selects a
parameter, but keeping every ad-hoc measurement off the evaluation set means the
question of what has seen it never has to be re-litigated.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import lexical_index as LX  # noqa: E402
import nvd_normalize as N  # noqa: E402
import retrieval as R  # noqa: E402

RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "lexical_latency.json"
DEV_SAMPLE_PATH = PROJECT_ROOT / "experiments" / "samples" / "dev_sample.json"

DEPTH = 200          # the depth hybrid retrieval actually pulls per arm
TERM_COUNTS = (1, 2, 4, 8, 16, 32)
WARMUP = 20


def summarize(name: str, timings: List[float], extra: Dict[str, Any] = None) -> Dict[str, Any]:
    out = {
        "queries": len(timings),
        "p50_ms": round(R.percentile(timings, 50), 2),
        "p95_ms": round(R.percentile(timings, 95), 2),
        "max_ms": round(max(timings), 2) if timings else 0.0,
    }
    out.update(extra or {})
    print(f"  {name:<34} p50={out['p50_ms']:>8.1f}  p95={out['p95_ms']:>8.1f}  "
          f"max={out['max_ms']:>8.1f}   n={out['queries']}")
    return out


def timed(conn, query: str, depth: int = DEPTH) -> float:
    start = time.perf_counter()
    LX.search(conn, query, depth)
    return (time.perf_counter() - start) * 1000.0


def first_sentence(document: str, limit: int = 240) -> str:
    body = document.split(": ", 1)[-1]
    cut = body.find(". ")
    return body[: cut + 1] if 0 < cut < limit else body[:limit]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--lexical-db",
                        default=str(PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"))
    args = parser.parse_args()

    conn = LX.connect(Path(args.lexical_db), read_only=True)
    total_docs = LX.document_count(conn)
    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)

    dev_ids = json.loads(DEV_SAMPLE_PATH.read_text(encoding="utf-8"))["cve_ids"]
    records = collection.get(ids=dev_ids, include=["documents", "metadatas"])
    print(f"corpus: {total_docs:,} documents | dev sample: {len(records['ids'])} CVEs\n")

    # Warm the page cache: the first query against a 400 MB index on disk pays
    # for I/O that no later query does, and a cold read in the sample would be
    # reported as a tail that does not exist in a running system.
    for cve_id in records["ids"][:WARMUP]:
        LX.search(conn, cve_id, DEPTH)

    results: Dict[str, Any] = {
        "documents": total_docs,
        "search_depth": DEPTH,
        "sample": "dev",
        "max_query_terms": LX.MAX_QUERY_TERMS,
    }

    # 1. By query shape.
    print("latency by query shape")
    shapes: Dict[str, List[float]] = {"bare CVE ID": [], "product + version": [],
                                      "description sentence": []}
    for cve_id, document, meta in zip(
        records["ids"], records["documents"], records["metadatas"]
    ):
        shapes["bare CVE ID"].append(timed(conn, cve_id))
        products = (meta.get("products") or "").split(N.LIST_DELIMITER)
        if products and products[0]:
            year = (meta.get("year") or "").strip()
            shapes["product + version"].append(
                timed(conn, f"{products[0]} {year}".strip())
            )
        shapes["description sentence"].append(timed(conn, first_sentence(document)))
    results["by_query_shape"] = {
        name: summarize(name, timings) for name, timings in shapes.items()
    }

    # 2. By term count, holding the source text fixed.
    print("\nlatency by term count (same descriptions, truncated)")
    by_terms: Dict[str, Any] = {}
    for count in TERM_COUNTS:
        timings = []
        for document in records["documents"]:
            terms = first_sentence(document).split()
            if len(terms) < count:
                continue
            timings.append(timed(conn, " ".join(terms[:count])))
        if timings:
            by_terms[str(count)] = summarize(f"{count} term(s)", timings)
    results["by_term_count"] = by_terms

    # 3. By document frequency, holding the term count at one.
    print("\nlatency by single-term document frequency")
    probes = ["heartbleed", "log4shell", "openssl", "wordpress", "android",
              "windows", "buffer", "attacker", "vulnerability"]
    by_frequency: Dict[str, Any] = {}
    for term in probes:
        matches = conn.execute(
            f"SELECT count(*) FROM {LX.FTS_TABLE} WHERE {LX.FTS_TABLE} MATCH ?",
            [LX.escape_fts_query(term)],
        ).fetchone()[0]
        timings = [timed(conn, term) for _ in range(15)]
        by_frequency[term] = summarize(
            f"{term} ({matches:,} docs)", timings,
            {"documents_matched": matches,
             "corpus_share": round(matches / total_docs, 4)},
        )
    results["by_single_term_frequency"] = by_frequency

    # 4. What direct-ID routing costs.
    #
    # Measured here, interleaved in a single process, rather than by comparing
    # two identifier_queries.py runs. Those runs happen minutes apart on a
    # developer machine and the whole latency distribution moves between them -
    # in one pair every component, including ones routing cannot touch, was
    # about twice as slow. A difference of that size would swamp what is being
    # measured, so the comparison has to be internally valid.
    print("\ndirect-ID routing overhead (same process, interleaved)")
    from embeddings import EmbeddingService  # noqa: E402

    embedder = EmbeddingService()
    plain = R.build_retriever("dense", collection=collection, embedder=embedder,
                              lexical_conn=conn)
    routed = R.build_retriever("dense", collection=collection, embedder=embedder,
                               lexical_conn=conn, direct_id=True)
    probe_ids = records["ids"][:100]
    for cve_id in probe_ids[:10]:      # warm both paths
        plain.search(cve_id, DEPTH)
        routed.search(cve_id, DEPTH)
    plain.latency.samples_ms.clear()
    routed.latency.samples_ms.clear()
    for cve_id in probe_ids:
        plain.search(cve_id, DEPTH)
        routed.search(cve_id, DEPTH)

    # The routing step alone, with no retrieval underneath it.
    lookup = []
    for cve_id in probe_ids:
        start = time.perf_counter()
        routed.extract_ids(cve_id)
        lookup.append((time.perf_counter() - start) * 1000.0)

    routing = {
        "dense": summarize("dense", plain.latency.samples_ms),
        "dense+direct_id": summarize("dense+direct_id", routed.latency.samples_ms),
        "routing_step_only": summarize("routing step only (regex + keyed lookup)", lookup),
    }
    results["routing_overhead"] = routing

    conn.close()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {RESULTS_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
