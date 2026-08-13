"""
Does BM25 really solve CVE-ID lookup, or only for the CVEs nobody searches for?

The ablation reports Recall@1 of 0.995 for BM25 on bare CVE IDs, which reads as
"identifier lookup is solved". It is not, and the reason is visible in how BM25
ranks:

    query: CVE-2021-44228 (Log4Shell)
    1. CVE-2022-23848    259 chars   merely cites Log4Shell
    2. CVE-2021-44530    364 chars   merely cites Log4Shell
    3. CVE-2022-33915   1007 chars   merely cites Log4Shell
    4. CVE-2021-4125     454 chars   merely cites Log4Shell
    5. CVE-2021-44228   1123 chars   the actual record
    6. CVE-2021-45046   1057 chars

Six documents contain the token. BM25 normalizes for document length, the
authoritative record is the longest of them because a heavily-analysed CVE
accumulates vendors and products, and so it ranks fifth of six.

That failure needs another document to cite the CVE, and almost no CVE is cited
by another. A uniform random sample is therefore made almost entirely of records
where the identifier is unique, BM25 wins trivially, and the average hides the
cases an analyst actually types.

This script splits the corpus by that property and scores each population
separately:

    python experiments/crossref_identifiers.py

Writes experiments/results/crossref_identifiers.json.

The populations are drawn fresh here and are not the pinned evaluation sample:
the point is precisely to measure a sub-population the pinned sample barely
contains. Nothing here tunes a parameter.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import lexical_index as LX  # noqa: E402
import retrieval as R  # noqa: E402
from embeddings import EmbeddingService  # noqa: E402

RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "crossref_identifiers.json"
SEED = 20260813
SAMPLE_PER_GROUP = 150
DEPTH = 100
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Widely-known CVEs, listed by name rather than sampled, because "the ones an
# analyst types" is the population that matters and it is not a random draw.
FAMOUS = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2014-0160",   # Heartbleed
    "CVE-2017-0144",   # EternalBlue / WannaCry
    "CVE-2021-45046",  # Log4j follow-up
    "CVE-2014-6271",   # Shellshock
    "CVE-2019-0708",   # BlueKeep
    "CVE-2020-1472",   # Zerologon
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2022-30190",  # Follina
    "CVE-2023-4966",   # Citrix Bleed
    "CVE-2021-26855",  # ProxyLogon
    "CVE-2018-13379",  # Fortinet path traversal
]


def build_citation_counts(conn) -> Dict[str, int]:
    """
    Count, for every CVE in the corpus, how many documents mention its ID.

    A full scan rather than a sample: the cross-referenced population is a
    fraction of a percent, so sampling to find it would mostly find nothing.
    """
    corpus_ids = {
        row["cve_id"] for row in conn.execute(f"SELECT cve_id FROM {LX.META_TABLE}")
    }
    counts: Dict[str, int] = {cve_id: 0 for cve_id in corpus_ids}
    scanned = 0
    for row in conn.execute(f"SELECT cve_id, document FROM {LX.FTS_TABLE}"):
        scanned += 1
        for mentioned in set(CVE_PATTERN.findall(row["document"])):
            upper = mentioned.upper()
            if upper in counts:
                counts[upper] += 1
        if scanned % 100_000 == 0:
            print(f"    scanned {scanned:,} documents ...", flush=True)
    return counts


def recall_at_1(retriever, cve_ids: List[str]) -> Dict[str, Any]:
    """Fraction of IDs whose own record comes back first for a bare-ID query."""
    hits, ranks = 0, []
    start = time.perf_counter()
    for cve_id in cve_ids:
        results = retriever.search(cve_id, DEPTH)
        rank = results.index(cve_id) + 1 if cve_id in results else None
        ranks.append(rank)
        if rank == 1:
            hits += 1
    found = [r for r in ranks if r is not None]
    n = max(len(cve_ids), 1)
    return {
        "queries": len(cve_ids),
        "recall_at_1": round(hits / n, 4),
        "recall_at_10": round(sum(1 for r in found if r <= 10) / n, 4),
        "mrr": round(sum(1 / r for r in found) / n, 4),
        "mean_ms": round(1000 * (time.perf_counter() - start) / n, 1),
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

    conn = LX.connect(Path(args.lexical_db), read_only=True)
    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)

    print("scanning the corpus for cross-references ...")
    counts = build_citation_counts(conn)
    cited = sorted(cve_id for cve_id, n in counts.items() if n > 1)
    unique = sorted(cve_id for cve_id, n in counts.items() if n <= 1)
    total = len(counts)
    print(f"  {total:,} CVEs | cross-referenced by another record: {len(cited):,} "
          f"({len(cited)/total:.3%})\n")

    rng = random.Random(SEED)
    famous_present = [c for c in FAMOUS if c in counts]
    populations = {
        "cross-referenced": rng.sample(cited, min(SAMPLE_PER_GROUP, len(cited))),
        "not cross-referenced": rng.sample(unique, min(SAMPLE_PER_GROUP, len(unique))),
        "widely-known (named, not sampled)": famous_present,
    }

    embedder = EmbeddingService()
    results: Dict[str, Any] = {
        "corpus_size": total,
        "cross_referenced_count": len(cited),
        "cross_referenced_share": round(len(cited) / total, 5),
        "sample_per_group": SAMPLE_PER_GROUP,
        "seed": SEED,
        "search_depth": DEPTH,
        "note": "populations drawn here, not the pinned evaluation sample; this "
                "measures a sub-population the pinned sample barely contains",
        "populations": {name: {"size": len(ids)} for name, ids in populations.items()},
        "by_retrieval": {},
    }

    for mode in R.MODES:
        retriever = R.build_retriever(
            mode, collection=collection, embedder=embedder, lexical_conn=conn
        )
        results["by_retrieval"][mode] = {
            name: recall_at_1(retriever, ids) for name, ids in populations.items()
        }
        print(f"{mode}")
        for name, scored in results["by_retrieval"][mode].items():
            print(f"  {name:<38} R@1={scored['recall_at_1']:.3f} "
                  f"R@10={scored['recall_at_10']:.3f} MRR={scored['mrr']:.3f} "
                  f"(n={scored['queries']})")
        print()

    # Where each famous CVE actually lands, per configuration.
    detail: Dict[str, Any] = {}
    for mode in R.MODES:
        retriever = R.build_retriever(
            mode, collection=collection, embedder=embedder, lexical_conn=conn
        )
        detail[mode] = {}
        for cve_id in famous_present:
            hits = retriever.search(cve_id, DEPTH)
            detail[mode][cve_id] = {
                "rank": hits.index(cve_id) + 1 if cve_id in hits else None,
                "documents_mentioning_it": counts[cve_id],
            }
    results["widely_known_detail"] = detail

    print("rank of each widely-known CVE when searched by its own ID")
    print(f"{'CVE':<18}{'cites':>7}" + "".join(f"{m:>16}" for m in R.MODES))
    print("-" * (25 + 16 * len(R.MODES)))
    for cve_id in famous_present:
        row = f"{cve_id:<18}{counts[cve_id]:>7}"
        for mode in R.MODES:
            rank = detail[mode][cve_id]["rank"]
            row += f"{('miss' if rank is None else str(rank)):>16}"
        print(row)

    conn.close()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {RESULTS_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
