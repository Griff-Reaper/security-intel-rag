"""
Resumable NVD corpus ingestion.

This script - not the resulting index - is the committed artifact. A ChromaDB
collection holding hundreds of thousands of documents is far too large to commit
and impossible to review, so the repository carries the code that builds it plus
a provenance manifest recording exactly what was ingested and when.

Design notes:

Resumability. Embedding the full corpus takes on the order of an hour on CPU. A
run that dies at 80% must not start over. After every committed batch the script
records how many records of the current year have been written to
data/raw/.ingest_checkpoint.json. On restart it skips that many records. This is
deterministic because the year feed on disk is fixed and sha256-verified, so
record order is stable across runs. Upserts are idempotent, so re-running a
partially-complete batch is harmless.

Batching. Embeddings are generated in batches (default 256 texts per forward
pass) and written to ChromaDB in larger chunks. Per-record encoding would be
roughly an order of magnitude slower.

Provenance. The manifest records source, release tag, pull date, raw record
count, and the count actually indexed after filtering. That manifest is what
substantiates any corpus-size claim made elsewhere.
"""

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import nvd_api
import nvd_feeds
import nvd_normalize
from embeddings import EmbeddingService

DEFAULT_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DEFAULT_PERSIST_DIR = PROJECT_ROOT / "chroma_db"
DEFAULT_COLLECTION = "nvd_cve"
MANIFEST_PATH = PROJECT_ROOT / "data" / "manifest.json"
CHECKPOINT_PATH = DEFAULT_RAW_DIR / ".ingest_checkpoint.json"

DEFAULT_EMBED_BATCH = 256
DEFAULT_UPSERT_BATCH = 1000


def load_checkpoint(path: Path) -> Dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt checkpoint should not block a re-run; ingest from zero.
            return {}
    return {}


def save_checkpoint(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename so an interrupted save cannot corrupt the checkpoint.
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temp.replace(path)


def _chunks(items: List[Any], size: int) -> Iterable[List[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def open_collection(persist_dir: Path, collection_name: str):
    """
    Open (or create) the target collection.

    The collection is configured for cosine distance. all-MiniLM-L6-v2 is
    trained for cosine similarity, and combined with L2-normalized vectors this
    keeps distances in a predictable [0, 2] range - which is what makes a
    relevance floor meaningful later.
    """
    client = chromadb.PersistentClient(
        path=str(persist_dir), settings=Settings(anonymized_telemetry=False)
    )
    return client.get_or_create_collection(
        name=collection_name,
        metadata={
            "description": "NVD CVE corpus",
            "hnsw:space": "cosine",
        },
    )


def ingest_year(
    feed_path: Path,
    collection,
    embedder: EmbeddingService,
    already_done: int,
    embed_batch: int,
    upsert_batch: int,
    on_progress,
) -> Dict[str, int]:
    """
    Ingest one year's feed, skipping the first `already_done` indexable records.

    Returns counts for the manifest. `already_done` counts *indexable* records
    (post-filter), so the skip stays correct even though filtering is applied
    while streaming.
    """
    raw_count = 0
    filtered = Counter()
    indexable_seen = 0
    written = 0

    pending: List[Dict[str, Any]] = []

    def flush() -> None:
        nonlocal written, pending
        if not pending:
            return
        for chunk in _chunks(pending, upsert_batch):
            texts = [item["document"] for item in chunk]
            vectors = embedder.get_embeddings(
                texts, show_progress=False, batch_size=embed_batch
            )
            collection.upsert(
                ids=[item["id"] for item in chunk],
                documents=texts,
                embeddings=vectors,
                metadatas=[item["metadata"] for item in chunk],
            )
            written += len(chunk)
            on_progress(written)
        pending = []

    for record in nvd_feeds.iter_records(feed_path):
        raw_count += 1
        keep, reason = nvd_normalize.should_index(record)
        if not keep:
            filtered[reason] += 1
            continue

        indexable_seen += 1
        # Skip records already committed by a previous run.
        if indexable_seen <= already_done:
            continue

        normalized = nvd_normalize.normalize(record)
        if normalized is None:
            continue
        pending.append(normalized)

        if len(pending) >= upsert_batch:
            flush()

    flush()

    return {
        "raw": raw_count,
        "indexable": indexable_seen,
        "written_this_run": written,
        "filtered": dict(filtered),
    }


def run(
    raw_dir: Path,
    persist_dir: Path,
    collection_name: str,
    years: Optional[List[str]],
    embed_batch: int,
    upsert_batch: int,
    reset: bool,
    manifest_path: Path,
) -> Dict[str, Any]:
    feed_files = sorted(raw_dir.glob("CVE-*.json.xz"))
    if years:
        wanted = set(years)
        feed_files = [p for p in feed_files if p.stem.split("-")[1].split(".")[0] in wanted]
    if not feed_files:
        raise SystemExit(
            f"No feed files in {raw_dir}. Run: python src/nvd_feeds.py --dest {raw_dir}"
        )

    checkpoint = {} if reset else load_checkpoint(CHECKPOINT_PATH)
    # A checkpoint only applies to the collection and model that produced it.
    if checkpoint.get("collection") not in (None, collection_name):
        print("Checkpoint belongs to a different collection; starting fresh.")
        checkpoint = {}
    completed: Dict[str, int] = dict(checkpoint.get("completed", {}))

    print(f"Loading embedding model ...")
    embedder = EmbeddingService()
    collection = open_collection(persist_dir, collection_name)

    if reset:
        print(f"Reset requested: clearing collection '{collection_name}'")
        client = chromadb.PersistentClient(
            path=str(persist_dir), settings=Settings(anonymized_telemetry=False)
        )
        client.delete_collection(collection_name)
        collection = open_collection(persist_dir, collection_name)
        completed = {}

    totals = {"raw": 0, "indexable": 0, "written": 0}
    filtered_totals: Counter = Counter()
    start = time.perf_counter()

    for feed_path in feed_files:
        year = feed_path.name[len("CVE-") : -len(".json.xz")]
        done = completed.get(year, 0)
        year_start = time.perf_counter()

        def on_progress(written_so_far: int, _year=year, _done=done) -> None:
            completed[_year] = _done + written_so_far
            save_checkpoint(
                CHECKPOINT_PATH,
                {
                    "collection": collection_name,
                    "embedding_model": embedder.model_name,
                    "completed": completed,
                },
            )
            elapsed = time.perf_counter() - start
            total_written = totals["written"] + written_so_far
            rate = total_written / elapsed if elapsed > 0 else 0.0
            print(
                f"    CVE-{_year}: {_done + written_so_far:,} indexed "
                f"({rate:,.0f} docs/s overall)",
                end="\r",
                flush=True,
            )

        stats = ingest_year(
            feed_path,
            collection,
            embedder,
            already_done=done,
            embed_batch=embed_batch,
            upsert_batch=upsert_batch,
            on_progress=on_progress,
        )

        totals["raw"] += stats["raw"]
        totals["indexable"] += stats["indexable"]
        totals["written"] += stats["written_this_run"]
        filtered_totals.update(stats["filtered"])
        completed[year] = stats["indexable"]
        save_checkpoint(
            CHECKPOINT_PATH,
            {
                "collection": collection_name,
                "embedding_model": embedder.model_name,
                "completed": completed,
            },
        )

        year_elapsed = time.perf_counter() - year_start
        print(
            f"  CVE-{year}: {stats['raw']:,} raw -> {stats['indexable']:,} indexable "
            f"({stats['written_this_run']:,} written this run, {year_elapsed:,.1f}s)"
            + " " * 20
        )

    elapsed = time.perf_counter() - start
    indexed_total = collection.count()

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus": {
            "source": nvd_feeds.FEED_REPO,
            "source_url": f"https://github.com/{nvd_feeds.FEED_REPO}",
            "upstream": "National Vulnerability Database (NVD), NIST",
            "license": "NVD and CVE Terms of Use",
            "years": [p.name[len("CVE-") : -len(".json.xz")] for p in feed_files],
            "records_raw": totals["raw"],
            "records_indexable": totals["indexable"],
            "records_filtered_out": sum(filtered_totals.values()),
            "filters": dict(filtered_totals),
            "filter_definitions": {
                "rejected": "vulnStatus == 'Rejected' (CVE withdrawn by its assigner)",
                "no_english_description": "no descriptions[] entry with lang == 'en'",
            },
        },
        # Captured at build time so a later measurement can check that it is
        # describing the index it thinks it is. nvd_normalize.layout_fingerprint()
        # hashes the rendered output of fixed fixtures, so it moves when and only
        # when the documents actually change.
        "document_layout": nvd_normalize.layout_descriptor(),
        "index": {
            "collection": collection_name,
            "documents_in_collection": indexed_total,
            "embedding_model": embedder.model_name,
            "embedding_dimension": embedder.get_embedding_dimension(),
            "distance": "cosine",
            "documents_written_this_run": totals["written"],
            "wall_clock_seconds": round(elapsed, 1),
            "docs_per_second": round(totals["written"] / elapsed, 1) if elapsed > 0 else None,
        },
    }

    # Merge feed provenance (release tag, pull date) recorded at download time.
    feed_meta_path = raw_dir / "download_manifest.json"
    if feed_meta_path.exists():
        try:
            feed_meta = json.loads(feed_meta_path.read_text(encoding="utf-8"))
            manifest["corpus"]["release_tag"] = feed_meta.get("release_tag", "")
            manifest["corpus"]["release_published_at"] = feed_meta.get(
                "release_published_at", ""
            )
            manifest["corpus"]["pulled_at"] = feed_meta.get("pulled_at", "")
        except (json.JSONDecodeError, OSError):
            pass

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print()
    print("=" * 64)
    print("Ingestion complete")
    print("=" * 64)
    print(f"  raw records          : {totals['raw']:,}")
    print(f"  indexable            : {totals['indexable']:,}")
    print(f"  filtered out         : {sum(filtered_totals.values()):,} {dict(filtered_totals)}")
    print(f"  written this run     : {totals['written']:,}")
    print(f"  documents in index   : {indexed_total:,}")
    print(f"  wall clock           : {elapsed/60:.1f} min")
    if elapsed > 0 and totals["written"]:
        print(f"  throughput           : {totals['written']/elapsed:,.0f} docs/second")
    print(f"  manifest             : {manifest_path}")
    return manifest


def refresh(
    persist_dir: Path,
    collection_name: str,
    days: int,
    embed_batch: int,
    upsert_batch: int,
) -> Dict[str, Any]:
    """
    Apply incremental NVD changes to an existing collection.

    Pulls everything modified in the last `days` days and upserts it. Records
    that have since become Rejected are *deleted* rather than skipped: a CVE can
    be withdrawn after publication, and leaving a stale copy in the index would
    keep presenting a withdrawn vulnerability as real.
    """
    embedder = EmbeddingService()
    collection = open_collection(persist_dir, collection_name)
    before = collection.count()

    pending: List[Dict[str, Any]] = []
    to_delete: List[str] = []
    upserted = 0
    seen = 0

    def flush() -> None:
        nonlocal upserted, pending
        if not pending:
            return
        texts = [item["document"] for item in pending]
        vectors = embedder.get_embeddings(
            texts, show_progress=False, batch_size=embed_batch
        )
        collection.upsert(
            ids=[item["id"] for item in pending],
            documents=texts,
            embeddings=vectors,
            metadatas=[item["metadata"] for item in pending],
        )
        upserted += len(pending)
        pending = []

    print(f"Fetching NVD changes from the last {days} day(s) ...")
    for record in nvd_api.fetch_recent(days=days):
        seen += 1
        normalized = nvd_normalize.normalize(record)
        if normalized is None:
            # Withdrawn or unusable now; drop any previously indexed copy.
            to_delete.append(record["id"])
            continue
        pending.append(normalized)
        if len(pending) >= upsert_batch:
            flush()
    flush()

    deleted = 0
    if to_delete:
        # Only delete IDs actually present, so the count reported is truthful.
        existing = set(collection.get(ids=to_delete, include=[])["ids"])
        if existing:
            collection.delete(ids=list(existing))
            deleted = len(existing)

    after = collection.count()
    print()
    print(f"  records returned by NVD : {seen:,}")
    print(f"  upserted                : {upserted:,}")
    print(f"  removed (now rejected)  : {deleted:,}")
    print(f"  collection size         : {before:,} -> {after:,}")
    return {
        "records_seen": seen,
        "upserted": upserted,
        "deleted": deleted,
        "collection_size": after,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest the NVD corpus into ChromaDB")
    parser.add_argument("--raw-dir", default=str(DEFAULT_RAW_DIR))
    parser.add_argument("--persist-dir", default=str(DEFAULT_PERSIST_DIR))
    parser.add_argument("--collection", default=DEFAULT_COLLECTION)
    parser.add_argument("--years", nargs="*", help="limit to specific years")
    parser.add_argument("--embed-batch", type=int, default=DEFAULT_EMBED_BATCH)
    parser.add_argument("--upsert-batch", type=int, default=DEFAULT_UPSERT_BATCH)
    parser.add_argument(
        "--reset",
        action="store_true",
        help="drop the collection and checkpoint, then ingest from scratch",
    )
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="incremental update via the NVD API instead of a bulk feed ingest",
    )
    parser.add_argument(
        "--days", type=int, default=7, help="look-back window for --refresh"
    )
    args = parser.parse_args()

    if args.refresh:
        refresh(
            persist_dir=Path(args.persist_dir),
            collection_name=args.collection,
            days=args.days,
            embed_batch=args.embed_batch,
            upsert_batch=args.upsert_batch,
        )
        return

    run(
        raw_dir=Path(args.raw_dir),
        persist_dir=Path(args.persist_dir),
        collection_name=args.collection,
        years=args.years,
        embed_batch=args.embed_batch,
        upsert_batch=args.upsert_batch,
        reset=args.reset,
        manifest_path=Path(args.manifest),
    )


if __name__ == "__main__":
    main()
