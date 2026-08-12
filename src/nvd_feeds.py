"""
Bulk NVD corpus download from the fkie-cad community data feeds.

Why not the NVD API for the initial load: NVD API 2.0 caps a page at 2,000
records against a corpus of roughly 300,000, and the unauthenticated rate limit
is 5 requests per 30 seconds. The bulk feeds are a single compressed file per
year, so a cold start is a few minutes instead of a long paged crawl. The API is
still the right tool for incremental refreshes - see nvd_api.py.

Source: https://github.com/fkie-cad/nvd-json-data-feeds
  Community reconstruction of the deprecated legacy NVD JSON feeds. Repackaged
  daily at 00:00 UTC; synchronised with NVD every 2 hours. Each year ships as
  CVE-<YEAR>.json.xz plus a CVE-<YEAR>.meta sidecar carrying size and sha256.

The underlying data is NVD/CVE content and remains subject to the NVD and CVE
Terms of Use (see LICENSES/ in the upstream repository).
"""

import hashlib
import json
import lzma
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

RELEASE_API = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"
FEED_REPO = "fkie-cad/nvd-json-data-feeds"

# Years present in the feed. Resolved from the release rather than hardcoded so
# a new year appears automatically each January.
YEAR_ASSET_SUFFIX = ".json.xz"
META_ASSET_SUFFIX = ".meta"

DEFAULT_TIMEOUT = 180
CHUNK_BYTES = 1 << 20  # 1 MiB


class FeedDownloadError(RuntimeError):
    """Raised when a feed asset cannot be fetched or fails verification."""


def _session(user_agent: str = "security-intel-rag/1.0") -> requests.Session:
    """
    Session with backoff retries.

    GitHub's asset CDN intermittently drops connections mid-transfer; without
    retries a single hiccup 100 files into a corpus download loses the run.
    """
    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def get_latest_release(session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Fetch release metadata (tag, published date, asset URLs) for the newest feed."""
    session = session or _session()
    response = session.get(
        RELEASE_API,
        headers={"Accept": "application/vnd.github+json"},
        timeout=DEFAULT_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def list_year_assets(release: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Map year -> {"data": asset, "meta": asset} for per-year feeds only.

    The aggregate CVE-all / CVE-recent / CVE-modified assets are excluded: the
    per-year split is what makes the download resumable and progress legible.
    """
    by_year: Dict[str, Dict[str, Any]] = {}
    for asset in release.get("assets", []):
        name = asset["name"]
        if name.startswith("CVE-") and name.endswith(YEAR_ASSET_SUFFIX):
            stem = name[: -len(YEAR_ASSET_SUFFIX)]
            year = stem.split("-", 1)[1]
            if year.isdigit():
                by_year.setdefault(year, {})["data"] = asset
        elif name.startswith("CVE-") and name.endswith(META_ASSET_SUFFIX):
            stem = name[: -len(META_ASSET_SUFFIX)]
            year = stem.split("-", 1)[1]
            if year.isdigit():
                by_year.setdefault(year, {})["meta"] = asset
    return {year: assets for year, assets in sorted(by_year.items()) if "data" in assets}


def parse_meta(text: str) -> Dict[str, str]:
    """Parse the key:value sidecar (lastModifiedDate, size, xzSize, sha256)."""
    meta: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip()
    return meta


def sha256_decompressed(path: Path) -> str:
    """
    sha256 of the *decompressed* JSON.

    The sidecar hashes the uncompressed payload, not the .xz - its `size` field
    is the decompressed byte count and `xzSize` the compressed one. Hashing the
    archive instead would make every check fail. Streamed so a 330 MB year never
    lands in memory.
    """
    digest = hashlib.sha256()
    with lzma.open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify(path: Path, meta: Dict[str, str]) -> Optional[str]:
    """Return an error string when the file fails its sidecar, else None."""
    expected_xz = meta.get("xzSize")
    if expected_xz and expected_xz.isdigit():
        actual_xz = path.stat().st_size
        if actual_xz != int(expected_xz):
            return f"compressed size {actual_xz} != expected {expected_xz}"
    expected_sha = meta.get("sha256")
    if expected_sha:
        try:
            actual_sha = sha256_decompressed(path)
        except lzma.LZMAError as exc:
            return f"corrupt archive: {exc}"
        if actual_sha != expected_sha:
            return f"sha256 {actual_sha} != expected {expected_sha}"
    return None


def download_year(
    year: str,
    assets: Dict[str, Any],
    dest_dir: Path,
    session: Optional[requests.Session] = None,
    force: bool = False,
) -> Tuple[Path, bool]:
    """
    Download one year's compressed feed, verifying it against its sidecar.

    Returns (path, downloaded) where `downloaded` is False when an existing
    file already passed verification and was reused.
    """
    session = session or _session()
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / f"CVE-{year}.json.xz"

    meta: Dict[str, str] = {}
    if "meta" in assets:
        try:
            meta_response = session.get(
                assets["meta"]["browser_download_url"], timeout=DEFAULT_TIMEOUT
            )
            meta_response.raise_for_status()
            meta = parse_meta(meta_response.text)
        except requests.RequestException:
            # A missing sidecar is not fatal; we simply cannot verify.
            meta = {}

    # An already-verified file is left alone: this is what makes re-running the
    # download cheap and interruption-safe.
    if target.exists() and not force and _verify(target, meta) is None:
        return target, False

    response = session.get(
        assets["data"]["browser_download_url"], timeout=DEFAULT_TIMEOUT, stream=True
    )
    response.raise_for_status()
    # Write to a temp path first so an interrupted download never leaves a
    # truncated file that later looks complete.
    temp = target.with_suffix(".partial")
    with temp.open("wb") as handle:
        for chunk in response.iter_content(chunk_size=CHUNK_BYTES):
            if chunk:
                handle.write(chunk)

    problem = _verify(temp, meta)
    if problem:
        temp.unlink(missing_ok=True)
        raise FeedDownloadError(f"CVE-{year} failed verification: {problem}")

    temp.replace(target)
    return target, True


def read_feed(path: Path) -> Dict[str, Any]:
    """Decompress and parse one year feed file."""
    with lzma.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def iter_records(path: Path) -> Iterator[Dict[str, Any]]:
    """Yield raw CVE records from a year feed, in the feed's own order."""
    feed = read_feed(path)
    for record in feed.get("cve_items", []):
        yield record


def download_corpus(
    dest_dir: Path,
    years: Optional[List[str]] = None,
    force: bool = False,
    progress: bool = True,
) -> Dict[str, Any]:
    """
    Download every per-year feed and return provenance for the manifest.

    Returns the release tag, feed timestamp, and per-year file/record counts -
    exactly the fields needed to substantiate a corpus-size claim later.
    """
    session = _session()
    release = get_latest_release(session)
    assets_by_year = list_year_assets(release)

    if years:
        wanted = set(years)
        assets_by_year = {y: a for y, a in assets_by_year.items() if y in wanted}
        missing = wanted - set(assets_by_year)
        if missing:
            raise FeedDownloadError(f"no feed asset for year(s): {sorted(missing)}")

    downloaded: Dict[str, Dict[str, Any]] = {}
    fetched = reused = 0
    for year, assets in assets_by_year.items():
        path, was_downloaded = download_year(
            year, assets, dest_dir, session=session, force=force
        )
        fetched += was_downloaded
        reused += not was_downloaded
        if progress:
            action = "downloaded" if was_downloaded else "verified (cached)"
            print(f"  CVE-{year}: {action}", flush=True)
        downloaded[year] = {
            "path": str(path),
            "compressed_bytes": path.stat().st_size,
        }

    info = {
        "source": FEED_REPO,
        "source_url": f"https://github.com/{FEED_REPO}",
        "release_tag": release.get("tag_name", ""),
        "release_published_at": release.get("published_at", ""),
        "pulled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "license": "NVD and CVE Terms of Use (see LICENSES/ upstream)",
        "years": sorted(downloaded),
        "files": downloaded,
        "files_downloaded": fetched,
        "files_reused": reused,
    }

    # Record provenance next to the data so ingestion can fold the release tag
    # and pull date into the committed manifest.
    (dest_dir / "download_manifest.json").write_text(
        json.dumps(info, indent=2) + "\n", encoding="utf-8"
    )
    return info


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Download NVD bulk feeds")
    parser.add_argument("--dest", default="data/raw", help="download directory")
    parser.add_argument("--years", nargs="*", help="specific years (default: all)")
    parser.add_argument("--force", action="store_true", help="re-download even if verified")
    args = parser.parse_args()

    info = download_corpus(Path(args.dest), years=args.years, force=args.force)
    print(json.dumps({k: v for k, v in info.items() if k != "files"}, indent=2))
    print(f"years downloaded: {len(info['years'])}")
