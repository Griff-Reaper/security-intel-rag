"""
Incremental NVD updates via the NVD CVE API 2.0.

The bulk feeds (nvd_feeds.py) seed the corpus; this module keeps it current.
Refreshes use the lastModStartDate / lastModEndDate window so only records that
actually changed are pulled, which is a few hundred records a day rather than
376,000.

Rate limits (NVD published values):
  - without an API key: 5 requests per rolling 30 seconds
  - with an API key:   50 requests per rolling 30 seconds
Request a free key at https://nvd.nist.gov/developers/request-an-api-key and put
it in the environment as NVD_API_KEY. It is never read from the repository.

API constraints this module respects:
  - lastModStartDate and lastModEndDate must be supplied together
  - the window between them may not exceed 120 days, so longer catch-ups are
    split into consecutive windows
  - resultsPerPage caps at 2000; paging uses startIndex
"""

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MAX_RESULTS_PER_PAGE = 2000
MAX_WINDOW_DAYS = 120

# Conservative pacing. NVD counts a rolling 30-second window; sleeping this long
# between requests keeps us inside the limit without tracking a token bucket.
DELAY_WITH_KEY = 30.0 / 50 + 0.1
DELAY_WITHOUT_KEY = 30.0 / 5 + 0.5

DEFAULT_TIMEOUT = 120


class NvdApiError(RuntimeError):
    """Raised when the NVD API cannot be queried successfully."""


def _session() -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = "security-intel-rag/1.0"
    retry = Retry(
        total=5,
        backoff_factor=2.0,
        # 403 is what NVD returns when the rate limit is tripped.
        status_forcelist=(403, 429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


def _format_timestamp(value: datetime) -> str:
    """
    Render an NVD-acceptable ISO-8601 timestamp, e.g. 2026-08-11T00:00:00.000+00:00

    The offset must be colon-separated. strftime("%z") emits "+0000" without the
    colon, which NVD rejects with a 404 rather than a validation error - an
    opaque failure worth avoiding.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def iter_windows(
    start: datetime, end: datetime, max_days: int = MAX_WINDOW_DAYS
) -> Iterator[tuple]:
    """Split [start, end] into windows no longer than the API's 120-day cap."""
    cursor = start
    span = timedelta(days=max_days)
    while cursor < end:
        stop = min(cursor + span, end)
        yield cursor, stop
        cursor = stop


def get_api_key() -> Optional[str]:
    """Read the NVD API key from the environment (never from the repo)."""
    key = os.getenv("NVD_API_KEY", "").strip()
    return key or None


def fetch_modified(
    start: datetime,
    end: datetime,
    api_key: Optional[str] = None,
    progress: bool = True,
) -> Iterator[Dict[str, Any]]:
    """
    Yield raw CVE records modified within [start, end].

    Records are yielded in the API's own order. The caller is responsible for
    normalization and upserting; because upserts are idempotent, an interrupted
    refresh can simply be re-run.
    """
    api_key = api_key if api_key is not None else get_api_key()
    session = _session()
    headers = {"apiKey": api_key} if api_key else {}
    delay = DELAY_WITH_KEY if api_key else DELAY_WITHOUT_KEY

    for window_start, window_end in iter_windows(start, end):
        start_index = 0
        while True:
            params = {
                "lastModStartDate": _format_timestamp(window_start),
                "lastModEndDate": _format_timestamp(window_end),
                "resultsPerPage": MAX_RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            try:
                response = session.get(
                    API_URL, params=params, headers=headers, timeout=DEFAULT_TIMEOUT
                )
                response.raise_for_status()
                payload = response.json()
            except requests.RequestException as exc:
                raise NvdApiError(f"NVD API request failed: {exc}") from exc
            except ValueError as exc:
                raise NvdApiError(f"NVD API returned invalid JSON: {exc}") from exc

            total = payload.get("totalResults", 0)
            items = payload.get("vulnerabilities", []) or []
            if progress:
                print(
                    f"  {window_start:%Y-%m-%d} -> {window_end:%Y-%m-%d}: "
                    f"{start_index + len(items)}/{total}",
                    flush=True,
                )

            for item in items:
                # The API nests each record under "cve"; the inner object has the
                # same shape as a bulk-feed record, so one normalizer serves both.
                record = item.get("cve")
                if record:
                    yield record

            start_index += len(items)
            if not items or start_index >= total:
                break
            time.sleep(delay)


def fetch_recent(days: int = 7, api_key: Optional[str] = None) -> Iterator[Dict[str, Any]]:
    """Convenience wrapper: everything modified in the last `days` days."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return fetch_modified(start, end, api_key=api_key)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fetch recently modified CVEs from NVD")
    parser.add_argument("--days", type=int, default=1, help="look-back window in days")
    parser.add_argument("--limit", type=int, default=5, help="records to display")
    args = parser.parse_args()

    key = get_api_key()
    print(f"API key: {'present' if key else 'absent (5 requests / 30s)'}")
    shown = 0
    for cve in fetch_recent(days=args.days):
        if shown < args.limit:
            print(f"  {cve['id']}  {cve.get('vulnStatus','')}  modified {cve.get('lastModified','')}")
        shown += 1
    print(f"total modified in last {args.days} day(s): {shown}")
