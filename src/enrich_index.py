"""
Join CISA KEV and FIRST EPSS onto the indexed corpus.

    python src/enrich_index.py            # fetch (or reuse cached) and apply
    python src/enrich_index.py --force    # re-download both feeds first
    python src/enrich_index.py --check    # report coverage without writing

**Metadata only. Nothing is re-embedded, and no document text changes.**

That is a deliberate choice with two reasons behind it.

The first is volatility. EPSS re-scores essentially the whole corpus every day
and KEV grows every week. Embedding an exploitation signal into the document
text would mean re-embedding 358,170 documents on every refresh - about an hour
of CPU - to capture a number that changes again tomorrow. Metadata updates are
an in-place write that takes minutes.

The second is that it keeps the document layout fingerprint unchanged, so every
result file committed under Phase 2 still describes the index that ships. An
enrichment pass that altered document text would silently invalidate the entire
ablation; see src/provenance.py.

The honest cost of this choice: a natural-language question like "what is being
actively exploited right now" will not semantically match KEV membership,
because KEV membership is not in the embedded text. Exploitation is a filter
here, not a retrieval signal. Making it a retrieval signal is a different piece
of work - query understanding that maps such a question onto a filter - and
pretending otherwise would be worse than saying so.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import exploitation  # noqa: E402
import lexical_index as LX  # noqa: E402

DEFAULT_PERSIST_DIR = PROJECT_ROOT / "chroma_db"
DEFAULT_LEXICAL_DB = PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"
DEFAULT_COLLECTION = "nvd_cve"
MANIFEST_PATH = PROJECT_ROOT / "data" / "manifest.json"

UPDATE_BATCH = 2000


def _epoch(date_text: str) -> Optional[int]:
    """KEV dates are plain YYYY-MM-DD; store epoch seconds for range filters."""
    if not date_text:
        return None
    try:
        parsed = datetime.strptime(date_text.strip(), "%Y-%m-%d")
        return int(parsed.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def build_updates(
    corpus_ids: List[str], signals: Dict[str, Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """
    Metadata to write, for corpus CVEs that have a signal.

    Only CVEs present in the corpus are updated: the feeds cover CVEs this index
    does not hold (rejected, or newer than the last pull), and writing those
    would create metadata rows with no document behind them.

    `kev` is written as an explicit False for any CVE that has an EPSS score but
    is not in KEV, so "checked and not listed" is distinguishable from "never
    enriched". Records with no signal at all are left untouched.
    """
    in_corpus = set(corpus_ids)
    updates: Dict[str, Dict[str, Any]] = {}
    for cve_id, fields in signals.items():
        if cve_id not in in_corpus:
            continue
        row: Dict[str, Any] = {
            "kev": bool(fields.get("kev", False)),
            "kev_ransomware": bool(fields.get("kev_ransomware", False)),
        }
        if "epss_score" in fields:
            row["epss_score"] = float(fields["epss_score"])
            row["epss_percentile"] = float(fields["epss_percentile"])
        added = _epoch(fields.get("kev_date_added", ""))
        if added is not None:
            row["kev_date_added_ts"] = added
        if fields.get("kev_date_added"):
            row["kev_date_added"] = fields["kev_date_added"]
        if fields.get("kev_due_date"):
            row["kev_due_date"] = fields["kev_due_date"]
        updates[cve_id] = row
    return updates


def apply_to_chroma(collection, updates: Dict[str, Dict[str, Any]]) -> int:
    """Merge the enrichment fields into the collection's metadata.

    Chroma's update() merges rather than replaces, so the fields written by
    ingestion survive and only the exploitation keys are touched.
    """
    ids = list(updates)
    written = 0
    # Carriage-return progress only when a terminal is attached: redirected to a
    # file or a pipe it produces one enormous unreadable line.
    interactive = sys.stdout.isatty()
    for start in range(0, len(ids), UPDATE_BATCH):
        chunk = ids[start:start + UPDATE_BATCH]
        collection.update(ids=chunk, metadatas=[updates[c] for c in chunk])
        written += len(chunk)
        if interactive:
            print(f"  chroma: {written:,}/{len(ids):,}", end="\r", flush=True)
        elif written % (UPDATE_BATCH * 50) == 0:
            print(f"  chroma: {written:,}/{len(ids):,}", flush=True)
    print(f"  chroma: {written:,} records updated          ")
    return written


def apply_to_lexical(conn, updates: Dict[str, Dict[str, Any]]) -> int:
    """Write the same fields into the FTS metadata table."""
    added = LX.ensure_enrichment_columns(conn)
    if added:
        print(f"  lexical: added columns {', '.join(added)}")
    rows = [
        (
            int(fields["kev"]),
            int(fields["kev_ransomware"]),
            fields.get("kev_date_added_ts"),
            fields.get("epss_score"),
            fields.get("epss_percentile"),
            cve_id,
        )
        for cve_id, fields in updates.items()
    ]
    conn.executemany(
        f"UPDATE {LX.META_TABLE} SET kev = ?, kev_ransomware = ?, "
        f"kev_date_added_ts = ?, epss_score = ?, epss_percentile = ? "
        f"WHERE cve_id = ?",
        rows,
    )
    conn.commit()
    LX.create_metadata_indexes(conn)
    print(f"  lexical: {len(rows):,} records updated")
    return len(rows)


def coverage(conn) -> Dict[str, Any]:
    """Count what the index actually holds after enrichment."""
    def scalar(sql: str) -> int:
        return conn.execute(sql).fetchone()[0]

    total = scalar(f"SELECT count(*) FROM {LX.META_TABLE}")
    return {
        "documents": total,
        "with_epss": scalar(
            f"SELECT count(*) FROM {LX.META_TABLE} WHERE epss_score IS NOT NULL"),
        "kev_listed": scalar(f"SELECT count(*) FROM {LX.META_TABLE} WHERE kev = 1"),
        "kev_ransomware": scalar(
            f"SELECT count(*) FROM {LX.META_TABLE} WHERE kev_ransomware = 1"),
        "epss_over_0_5": scalar(
            f"SELECT count(*) FROM {LX.META_TABLE} WHERE epss_score >= 0.5"),
        "epss_over_0_9": scalar(
            f"SELECT count(*) FROM {LX.META_TABLE} WHERE epss_score >= 0.9"),
        "not_enriched": scalar(
            f"SELECT count(*) FROM {LX.META_TABLE} WHERE kev IS NULL"),
    }


def update_manifest(manifest_path: Path, block: Dict[str, Any]) -> None:
    manifest: Dict[str, Any] = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {}
    manifest["exploitation"] = block
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"  recorded in {manifest_path.relative_to(PROJECT_ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--persist-dir", default=str(DEFAULT_PERSIST_DIR))
    parser.add_argument("--collection", default=DEFAULT_COLLECTION)
    parser.add_argument("--lexical-db", default=str(DEFAULT_LEXICAL_DB))
    parser.add_argument("--cache-dir", default=str(exploitation.DEFAULT_CACHE_DIR))
    parser.add_argument("--force", action="store_true",
                        help="re-download both feeds instead of reusing the cache")
    parser.add_argument("--check", action="store_true",
                        help="report current coverage and exit without writing")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    args = parser.parse_args()

    conn = LX.connect(Path(args.lexical_db))
    if args.check:
        LX.ensure_enrichment_columns(conn)
        for key, value in coverage(conn).items():
            print(f"  {key:<18} {value:,}")
        conn.close()
        return

    print("Fetching exploitation feeds ...")
    signals, provenance = exploitation.load(Path(args.cache_dir), force=args.force)
    print(f"  KEV  {provenance['kev']['entries']:,} entries "
          f"(catalog {provenance['kev']['catalog_version']})")
    print(f"  EPSS {provenance['epss']['entries']:,} scores "
          f"(model {provenance['epss']['model_version']})")

    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)
    corpus_ids = collection.get(include=[])["ids"]
    print(f"  corpus {len(corpus_ids):,} documents")

    updates = build_updates(corpus_ids, signals)
    unmatched = len(signals) - len(updates)
    print(f"\nApplying to {len(updates):,} matched CVEs "
          f"({unmatched:,} feed entries are not in this corpus) ...")

    start = time.perf_counter()
    apply_to_chroma(collection, updates)
    apply_to_lexical(conn, updates)
    elapsed = time.perf_counter() - start

    stats = coverage(conn)
    conn.close()

    print()
    for key, value in stats.items():
        print(f"  {key:<18} {value:,}")

    provenance.update({
        "matched_in_corpus": len(updates),
        "feed_entries_not_in_corpus": unmatched,
        "apply_seconds": round(elapsed, 1),
        "coverage": stats,
        "storage": "metadata only; document text and embeddings unchanged",
    })
    print()
    update_manifest(Path(args.manifest), provenance)


if __name__ == "__main__":
    main()
