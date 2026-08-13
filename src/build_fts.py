"""
Build the SQLite FTS5 lexical index over the NVD corpus.

The index is built from the *same* normalized records that ingest_nvd.py embeds
into ChromaDB - the same feed files through the same nvd_normalize functions -
so the lexical and dense arms of hybrid retrieval rank identical text. Building
the lexical side from a different source (say, re-deriving text from stored
metadata) is how the two indexes quietly drift apart and the fusion starts
comparing different documents.

    python src/build_fts.py                     # build, then verify against Chroma
    python src/build_fts.py --verify-only       # check an existing index
    python src/build_fts.py --tokenizer "..."   # build with a different tokenizer

After building, the script cross-checks against the ChromaDB collection:
document counts must match, and a random sample of documents must be
byte-identical on both sides. A count match alone would not catch a normalizer
change that altered the text without changing how many records survive.

The index is a generated artifact and is not committed; its provenance is
recorded in data/manifest.json.
"""

from __future__ import annotations

import argparse
import json
import random
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

import lexical_index as LX
import nvd_feeds
import nvd_normalize

DEFAULT_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DEFAULT_DB_PATH = PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"
DEFAULT_COLLECTION = "nvd_cve"
MANIFEST_PATH = PROJECT_ROOT / "data" / "manifest.json"

INSERT_BATCH = 5000
VERIFY_SAMPLE = 300
VERIFY_SEED = 20260812


def build(
    raw_dir: Path,
    db_path: Path,
    tokenizer: str,
    years: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build the FTS index from the year feeds. Returns provenance for the manifest."""
    feed_files = sorted(raw_dir.glob("CVE-*.json.xz"))
    if years:
        wanted = set(years)
        feed_files = [p for p in feed_files if p.name[len("CVE-"):-len(".json.xz")] in wanted]
    if not feed_files:
        raise SystemExit(
            f"No feed files in {raw_dir}. Run: python src/nvd_feeds.py --dest {raw_dir}"
        )

    conn = LX.connect(db_path)
    # Durability is irrelevant for a rebuildable derived index, and turning it
    # off is worth several minutes across 358k inserts.
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA synchronous = OFF")
    LX.create_schema(conn, tokenizer=tokenizer)

    start = time.perf_counter()
    total_raw = 0
    total_indexed = 0
    batch: List[Dict[str, Any]] = []

    for path in feed_files:
        year = path.name[len("CVE-"):-len(".json.xz")]
        year_indexed = 0
        for record in nvd_feeds.iter_records(path):
            total_raw += 1
            normalized = nvd_normalize.normalize(record)
            if normalized is None:
                continue
            batch.append(normalized)
            year_indexed += 1
            if len(batch) >= INSERT_BATCH:
                LX.insert_batch(conn, batch)
                batch = []
        total_indexed += year_indexed
        print(f"  CVE-{year}: {year_indexed:,} indexed", flush=True)

    if batch:
        LX.insert_batch(conn, batch)
    conn.commit()

    print("  building metadata indexes ...", flush=True)
    LX.create_metadata_indexes(conn)

    # FTS5 keeps its postings in many small b-tree segments after a bulk load;
    # merging them once makes every later query faster.
    print("  optimizing FTS index ...", flush=True)
    conn.execute(f"INSERT INTO {LX.FTS_TABLE}({LX.FTS_TABLE}) VALUES('optimize')")
    conn.commit()

    elapsed = time.perf_counter() - start
    count = LX.document_count(conn)
    conn.close()

    size_bytes = db_path.stat().st_size
    print()
    print(f"  raw records   : {total_raw:,}")
    print(f"  indexed       : {count:,}")
    print(f"  wall clock    : {elapsed/60:.1f} min ({count/elapsed:,.0f} docs/s)")
    print(f"  index size    : {size_bytes/1e6:,.0f} MB")

    return {
        # POSIX separators so the committed manifest reads the same on any OS.
        "path": db_path.relative_to(PROJECT_ROOT).as_posix(),
        "tokenizer": tokenizer,
        "documents": count,
        "records_raw": total_raw,
        "size_bytes": size_bytes,
        "build_seconds": round(elapsed, 1),
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def verify(db_path: Path, persist_dir: Path, collection_name: str) -> Dict[str, Any]:
    """
    Cross-check the lexical index against ChromaDB.

    Two checks, because they fail for different reasons: a count mismatch means
    one index dropped records, while a text mismatch means the two were built
    from different normalizer behaviour and fusion would be ranking different
    documents against each other.
    """
    conn = LX.connect(db_path, read_only=True)
    fts_count = LX.document_count(conn)

    client = chromadb.PersistentClient(
        path=str(persist_dir), settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(collection_name)
    chroma_count = collection.count()

    print(f"  FTS documents    : {fts_count:,}")
    print(f"  Chroma documents : {chroma_count:,}")
    if fts_count != chroma_count:
        raise SystemExit(
            f"MISMATCH: FTS has {fts_count:,} documents, Chroma has {chroma_count:,}. "
            "One index dropped records; do not use hybrid retrieval until this is "
            "resolved."
        )
    print("  counts agree")

    # Text equality on a random sample.
    all_ids = collection.get(include=[])["ids"]
    rng = random.Random(VERIFY_SEED)
    sample = rng.sample(all_ids, min(VERIFY_SAMPLE, len(all_ids)))
    chroma_docs = collection.get(ids=sample, include=["documents"])
    by_id = dict(zip(chroma_docs["ids"], chroma_docs["documents"]))

    placeholders = ", ".join("?" for _ in sample)
    rows = conn.execute(
        f"SELECT cve_id, document FROM {LX.FTS_TABLE} WHERE cve_id IN ({placeholders})",
        sample,
    ).fetchall()
    fts_docs = {row["cve_id"]: row["document"] for row in rows}
    conn.close()

    missing = [cid for cid in sample if cid not in fts_docs]
    differing = [
        cid for cid in sample
        if cid in fts_docs and fts_docs[cid] != by_id.get(cid)
    ]
    if missing or differing:
        raise SystemExit(
            f"MISMATCH on sampled documents: {len(missing)} missing from FTS, "
            f"{len(differing)} with differing text (e.g. "
            f"{(missing + differing)[:3]}). The two indexes were built from "
            "different normalized text."
        )
    print(f"  {len(sample)} sampled documents byte-identical on both sides")

    return {
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "chroma_documents": chroma_count,
        "documents_compared": len(sample),
    }


def update_manifest(manifest_path: Path, lexical: Dict[str, Any]) -> None:
    """Record the lexical build alongside the corpus provenance."""
    manifest: Dict[str, Any] = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {}
    manifest["lexical_index"] = lexical
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"  recorded in {manifest_path.relative_to(PROJECT_ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", default=str(DEFAULT_RAW_DIR))
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default=DEFAULT_COLLECTION)
    parser.add_argument("--tokenizer", default=LX.TOKENIZER)
    parser.add_argument("--years", nargs="*")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--skip-verify", action="store_true")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    args = parser.parse_args()

    db_path = Path(args.db)

    if args.verify_only:
        print("Verifying lexical index against ChromaDB ...")
        verify(db_path, Path(args.persist_dir), args.collection)
        return

    print(f"Building FTS5 index at {db_path.relative_to(PROJECT_ROOT)}")
    print(f"  tokenizer: {args.tokenizer}")
    provenance = build(db_path=db_path, raw_dir=Path(args.raw_dir),
                       tokenizer=args.tokenizer, years=args.years)

    if not args.skip_verify:
        print()
        print("Verifying against ChromaDB ...")
        provenance["verification"] = verify(
            db_path, Path(args.persist_dir), args.collection
        )

    update_manifest(Path(args.manifest), provenance)


if __name__ == "__main__":
    main()
