"""
Which index does a result file describe?

A measurement is only comparable with another if both were taken against the
same corpus rendered the same way. The pinned sample protects against the
queries drifting; nothing yet protected against the *documents* drifting. If the
document layout changes and the index is rebuilt, every previously committed
result file silently starts describing a system that no longer exists, and
nothing in the artifacts says so.

Two mechanisms, because they fail differently:

  stamp()                every result file records when it was generated and the
                         layout fingerprint of the code that generated it, so a
                         future reader can tell two runs apart

  require_layout_match() an experiment refuses to run when the live code's
                         layout no longer matches what the manifest says the
                         index was built with, so a stale index is caught before
                         it produces numbers rather than after they are published

verify_index_layout() is the stronger of the two and the one that settles the
question for an *existing* index: it re-normalizes raw feed records with the
current code and compares the result against what is actually stored in
ChromaDB. That is evidence rather than bookkeeping - it does not depend on the
manifest having been written correctly at build time.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import nvd_feeds  # noqa: E402
import nvd_normalize as N  # noqa: E402

MANIFEST_PATH = PROJECT_ROOT / "data" / "manifest.json"
DEFAULT_RAW_DIR = PROJECT_ROOT / "data" / "raw"

# Years sampled by verify_index_layout: spread across the corpus so the check
# covers early records (sparse metadata) and recent ones (heavy CPE trees).
VERIFY_YEARS = ("2014", "2021", "2025")
VERIFY_SAMPLE_PER_YEAR = 500
VERIFY_SEED = 20260813


class LayoutMismatch(RuntimeError):
    """Raised when the code's document layout disagrees with the index's."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stamp(extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    The provenance block every generated artifact should carry.

    Kept deliberately small: a timestamp, the layout the numbers were produced
    against, and nothing that would go stale on its own.
    """
    block: Dict[str, Any] = {
        "generated_at": now_iso(),
        "document_layout": N.layout_descriptor(),
    }
    if extra:
        block.update(extra)
    return block


def read_manifest(manifest_path: Path = MANIFEST_PATH) -> Dict[str, Any]:
    if not Path(manifest_path).exists():
        return {}
    try:
        return json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def recorded_layout(manifest_path: Path = MANIFEST_PATH) -> Optional[Dict[str, Any]]:
    """The layout the manifest says the index was built with, if recorded."""
    return read_manifest(manifest_path).get("document_layout")


def enrichment_snapshot(manifest_path: Path = MANIFEST_PATH) -> Dict[str, Any]:
    """
    Which KEV catalog and EPSS scoring run the index was enriched from.

    Answers that report exploitation status are making a dated claim - "not
    listed in KEV" is only true as of a catalog version - so the version travels
    with the fact into the prompt rather than being assumed current. Absent keys
    are normal on an index built before enrichment ran; callers render without
    the qualifier rather than inventing one.
    """
    block = read_manifest(manifest_path).get("exploitation") or {}
    snapshot = {}
    catalog = (block.get("kev") or {}).get("catalog_version")
    if catalog:
        snapshot["kev_catalog"] = catalog
    scored = (block.get("epss") or {}).get("score_date")
    if scored:
        snapshot["epss_date"] = scored[:10]
    return snapshot


def require_layout_match(manifest_path: Path = MANIFEST_PATH) -> Dict[str, Any]:
    """
    Fail unless the live layout matches the one the index was built with.

    Raises:
        LayoutMismatch: The fingerprints differ, so any number produced now
            would describe a document layout the index does not contain.
    """
    live = N.layout_descriptor()
    recorded = recorded_layout(manifest_path)
    if recorded is None:
        # Not an error: an index built before layout recording existed. Say so
        # rather than inventing a match, and let the caller decide.
        return {"status": "unrecorded", "live": live}
    if recorded.get("fingerprint") != live["fingerprint"]:
        raise LayoutMismatch(
            f"document layout has changed since the index was built.\n"
            f"  index was built with : v{recorded.get('version')} "
            f"{recorded.get('fingerprint')}\n"
            f"  this code produces   : v{live['version']} {live['fingerprint']}\n"
            f"Re-ingest (python src/ingest_nvd.py --reset) and rebuild the "
            f"lexical index before measuring, or the numbers will describe a "
            f"corpus rendering that is not in the index."
        )
    return {"status": "match", "live": live}


def verify_index_layout(
    collection,
    raw_dir: Path = DEFAULT_RAW_DIR,
    years: Any = VERIFY_YEARS,
    per_year: int = VERIFY_SAMPLE_PER_YEAR,
) -> Dict[str, Any]:
    """
    Prove that the current code reproduces the text stored in the index.

    Re-normalizes a sample of raw feed records and compares the rendered
    document against what ChromaDB actually holds. Unlike a recorded
    fingerprint, this cannot be wrong about the past: if the layout used to
    build the index differed from this code, the texts differ here.

    Returns a summary; raises LayoutMismatch if any sampled document differs.
    """
    rng = random.Random(VERIFY_SEED)
    compared, mismatches = 0, []

    for year in years:
        feed = Path(raw_dir) / f"CVE-{year}.json.xz"
        if not feed.exists():
            continue
        normalized = []
        for record in nvd_feeds.iter_records(feed):
            done = N.normalize(record)
            if done is not None:
                normalized.append(done)
        if not normalized:
            continue
        sample = rng.sample(normalized, min(per_year, len(normalized)))

        stored = collection.get(
            ids=[doc["id"] for doc in sample], include=["documents"]
        )
        by_id = dict(zip(stored["ids"], stored["documents"]))
        for doc in sample:
            if doc["id"] not in by_id:
                continue  # absent from the index is a different failure
            compared += 1
            if by_id[doc["id"]] != doc["document"]:
                mismatches.append(doc["id"])

    if mismatches:
        raise LayoutMismatch(
            f"{len(mismatches)} of {compared} sampled documents differ between "
            f"the current code and the index (e.g. {mismatches[:3]}). The index "
            f"was built with a different document layout; re-ingest before "
            f"measuring."
        )

    return {
        "verified_at": now_iso(),
        "years_sampled": list(years),
        "documents_compared": compared,
        "mismatches": 0,
        "fingerprint": N.layout_fingerprint(),
    }


def write_manifest_layout(
    manifest_path: Path = MANIFEST_PATH,
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record the current document layout in the manifest."""
    manifest = read_manifest(manifest_path)
    block = N.layout_descriptor()
    if verification:
        block["verified_against_index"] = verification
    manifest["document_layout"] = block
    Path(manifest_path).parent.mkdir(parents=True, exist_ok=True)
    Path(manifest_path).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return block


def main() -> None:
    """Verify the live layout against the index, and record the result."""
    import argparse

    import chromadb
    from chromadb.config import Settings

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--raw-dir", default=str(DEFAULT_RAW_DIR))
    parser.add_argument("--record", action="store_true",
                        help="write the verified layout into data/manifest.json")
    args = parser.parse_args()

    live = N.layout_descriptor()
    print(f"document layout v{live['version']}, fingerprint {live['fingerprint']}")

    client = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client.get_collection(args.collection)

    print(f"re-normalizing feeds {', '.join(VERIFY_YEARS)} and comparing to the index ...")
    result = verify_index_layout(collection, Path(args.raw_dir))
    print(f"  {result['documents_compared']:,} documents compared, "
          f"{result['mismatches']} mismatches")

    if args.record:
        write_manifest_layout(verification=result)
        print(f"  recorded in {MANIFEST_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
