"""
Which FTS5 tokenizer should the lexical index use?

The default unicode61 tokenizer splits on punctuation, so CVE-2021-44228 becomes
three tokens (cve, 2021, 44228) and a version string like 2.14.1 becomes three
integers. Adding "-" and "." to `tokenchars` keeps each of those whole.

The tradeoff is not obvious in either direction:

  split   the rare component (44228) is still highly selective, but every
          document contains "cve" and tens of thousands share a year, so an
          OR query drags in an enormous candidate set
  atomic  cve-2021-44228 becomes a single very rare token - precise and fast -
          but a partial query ("44228" alone, or "log4j" against an indexed
          "log4j-core") no longer matches at all

So measure it. Build the same subset of the corpus under each tokenizer and
score the two identifier-shaped query types the project actually cares about.

    python experiments/fts_tokenizer.py

Writes experiments/results/fts_tokenizer.json.

This uses a corpus subset and its own sample, so its absolute numbers are not
comparable with the pinned 200-CVE identifier experiment; it exists only to
choose between tokenizers.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import lexical_index as LX  # noqa: E402
import nvd_feeds  # noqa: E402
import nvd_normalize as N  # noqa: E402

RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "fts_tokenizer.json"
SEED = 20260812
DEPTH = 100
SAMPLE = 300
YEARS = ["2021", "2024"]

CANDIDATES = {
    "unicode61 (default, splits on punctuation)": "unicode61",
    "unicode61 + tokenchars '-.' (atomic identifiers)": "unicode61 tokenchars '-.' remove_diacritics 2",
}


def build_subset(db_path: Path, tokenizer: str, years: List[str], raw_dir: Path) -> int:
    conn = LX.connect(db_path)
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA synchronous = OFF")
    LX.create_schema(conn, tokenizer=tokenizer)
    batch: List[Dict[str, Any]] = []
    for year in years:
        for record in nvd_feeds.iter_records(raw_dir / f"CVE-{year}.json.xz"):
            normalized = N.normalize(record)
            if normalized is None:
                continue
            batch.append(normalized)
            if len(batch) >= 5000:
                LX.insert_batch(conn, batch)
                batch = []
    if batch:
        LX.insert_batch(conn, batch)
    conn.commit()
    conn.execute(f"INSERT INTO {LX.FTS_TABLE}({LX.FTS_TABLE}) VALUES('optimize')")
    conn.commit()
    count = LX.document_count(conn)
    conn.close()
    return count


def rank_of(conn, query: str, target: str) -> Optional[int]:
    hits = [cve_id for cve_id, _ in LX.search(conn, query, DEPTH)]
    return hits.index(target) + 1 if target in hits else None


def score(conn, sample: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for label, build_query in (
        ("bare CVE ID", lambda r: r["id"]),
        ("product + version", lambda r: f"{r['product']} {r['year']}".strip()),
    ):
        ranks, elapsed = [], 0.0
        for rec in sample:
            query = build_query(rec)
            if not query.strip():
                continue
            start = time.perf_counter()
            ranks.append(rank_of(conn, query, rec["id"]))
            elapsed += time.perf_counter() - start
        found = [r for r in ranks if r is not None]
        n = max(len(ranks), 1)
        out[label] = {
            "queries": len(ranks),
            "recall_at_1": round(sum(1 for r in found if r == 1) / n, 4),
            "recall_at_10": round(sum(1 for r in found if r <= 10) / n, 4),
            "mrr": round(sum(1 / r for r in found) / n, 4),
            "mean_query_ms": round(1000 * elapsed / n, 2),
        }
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", default=str(PROJECT_ROOT / "data" / "raw"))
    parser.add_argument("--years", nargs="*", default=YEARS)
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    # Draw the sample once, from normalized records, so both tokenizers face
    # byte-identical queries.
    pool: List[Dict[str, Any]] = []
    for year in args.years:
        for record in nvd_feeds.iter_records(raw_dir / f"CVE-{year}.json.xz"):
            normalized = N.normalize(record)
            if normalized is None:
                continue
            products = (normalized["metadata"].get("products") or "").split(N.LIST_DELIMITER)
            pool.append({
                "id": normalized["id"],
                "product": products[0] if products and products[0] else "",
                "year": normalized["metadata"].get("year", ""),
            })
    sample = random.Random(SEED).sample(pool, min(SAMPLE, len(pool)))
    print(f"corpus subset: years {args.years}, {len(pool):,} documents")
    print(f"sample: {len(sample)} CVEs (seed {SEED})\n")

    results: Dict[str, Any] = {
        "years": args.years,
        "sample_size": len(sample),
        "seed": SEED,
        "search_depth": DEPTH,
        "note": "corpus subset with its own sample; not comparable to the pinned "
                "200-CVE identifier experiment",
        "tokenizers": {},
    }

    scratch = PROJECT_ROOT / "chroma_db" / "_tokenizer_probe.sqlite3"
    for label, tokenizer in CANDIDATES.items():
        scratch.unlink(missing_ok=True)
        built = time.perf_counter()
        count = build_subset(scratch, tokenizer, args.years, raw_dir)
        build_s = time.perf_counter() - built
        conn = LX.connect(scratch, read_only=True)
        measured = score(conn, sample)
        conn.close()
        size_mb = scratch.stat().st_size / 1e6
        results["tokenizers"][label] = {
            "tokenizer": tokenizer,
            "documents": count,
            "build_seconds": round(build_s, 1),
            "index_mb": round(size_mb, 1),
            "query_types": measured,
        }
        print(f"{label}")
        print(f"  built {count:,} docs in {build_s:.0f}s, {size_mb:,.0f} MB")
        for qtype, s in measured.items():
            print(f"    {qtype:<22} R@1={s['recall_at_1']:.3f} R@10={s['recall_at_10']:.3f} "
                  f"MRR={s['mrr']:.3f}  {s['mean_query_ms']:.1f} ms/query")
        print()
    scratch.unlink(missing_ok=True)

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {RESULTS_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
