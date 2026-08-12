"""
Tests for the two NVD data sources: bulk feeds and the incremental API.

Everything here is offline. The cases cover the two mistakes that cost real
debugging time during development, both of which fail in a misleading way:

  - the .meta sha256 covers the *decompressed* JSON, not the .xz archive, so
    hashing the archive makes verification fail on every healthy file
  - NVD rejects a "+0000" UTC offset with a 404 rather than a validation error,
    so the wrong timestamp format looks like a dead endpoint
"""

import hashlib
import json
import lzma
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import nvd_api
import nvd_feeds


class TestMetaSidecar:
    def test_parses_key_value_lines(self):
        text = (
            "lastModifiedDate:2026-08-11T21:17:23+00:00\n"
            "size:332863840\n"
            "xzSize:12184840\n"
            "sha256:8edcb5dddb54976d1bec4b6b14f10a7aa551ab194416db0e3b95633b19213991\n"
        )
        meta = nvd_feeds.parse_meta(text)
        assert meta["size"] == "332863840"
        assert meta["xzSize"] == "12184840"
        assert meta["sha256"].startswith("8edcb5ddd")

    def test_timestamp_value_keeps_its_colons(self):
        """The value itself contains colons; only the first one is a separator."""
        meta = nvd_feeds.parse_meta("lastModifiedDate:2026-08-11T21:17:23+00:00")
        assert meta["lastModifiedDate"] == "2026-08-11T21:17:23+00:00"


class TestFeedVerification:
    @pytest.fixture
    def feed_file(self, tmp_path):
        payload = json.dumps({"cve_items": [{"id": "CVE-2024-0001"}]}).encode()
        path = tmp_path / "CVE-2024.json.xz"
        path.write_bytes(lzma.compress(payload))
        return path, payload

    def test_hashes_decompressed_content_not_the_archive(self, feed_file):
        path, payload = feed_file
        assert nvd_feeds.sha256_decompressed(path) == hashlib.sha256(payload).hexdigest()
        # The archive's own digest must differ, or the test proves nothing.
        assert nvd_feeds.sha256_decompressed(path) != hashlib.sha256(path.read_bytes()).hexdigest()

    def test_verify_accepts_matching_sidecar(self, feed_file):
        path, payload = feed_file
        meta = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "xzSize": str(path.stat().st_size),
        }
        assert nvd_feeds._verify(path, meta) is None

    def test_verify_rejects_wrong_digest(self, feed_file):
        path, _ = feed_file
        assert "sha256" in nvd_feeds._verify(path, {"sha256": "0" * 64})

    def test_verify_rejects_wrong_compressed_size(self, feed_file):
        path, _ = feed_file
        assert "compressed size" in nvd_feeds._verify(path, {"xzSize": "999999"})

    def test_verify_passes_when_sidecar_is_missing(self, feed_file):
        """A missing sidecar means unverifiable, not invalid."""
        path, _ = feed_file
        assert nvd_feeds._verify(path, {}) is None


class TestAssetSelection:
    def test_pairs_year_assets_and_excludes_aggregates(self):
        release = {
            "assets": [
                {"name": "CVE-2024.json.xz", "browser_download_url": "u1"},
                {"name": "CVE-2024.meta", "browser_download_url": "u2"},
                {"name": "CVE-2025.json.xz", "browser_download_url": "u3"},
                {"name": "CVE-2025.meta", "browser_download_url": "u4"},
                # Aggregates must not be treated as years; they duplicate the corpus.
                {"name": "CVE-all.json.xz", "browser_download_url": "u5"},
                {"name": "CVE-recent.json.xz", "browser_download_url": "u6"},
                {"name": "CVE-modified.json.xz", "browser_download_url": "u7"},
            ]
        }
        assets = nvd_feeds.list_year_assets(release)
        assert sorted(assets) == ["2024", "2025"]
        assert assets["2024"]["data"]["browser_download_url"] == "u1"
        assert assets["2024"]["meta"]["browser_download_url"] == "u2"


class TestApiTimestamps:
    def test_offset_is_colon_separated(self):
        """strftime("%z") yields "+0000", which NVD answers with a 404."""
        stamp = nvd_api._format_timestamp(datetime(2026, 8, 11, tzinfo=timezone.utc))
        assert stamp == "2026-08-11T00:00:00.000+00:00"
        assert "+0000" not in stamp

    def test_naive_datetime_is_treated_as_utc(self):
        assert nvd_api._format_timestamp(datetime(2026, 8, 11)).endswith("+00:00")

    def test_non_utc_input_is_converted(self):
        eastern = timezone(timedelta(hours=-5))
        stamp = nvd_api._format_timestamp(datetime(2026, 8, 11, 0, 0, tzinfo=eastern))
        assert stamp == "2026-08-11T05:00:00.000+00:00"


class TestApiWindowing:
    def test_short_range_is_a_single_window(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        windows = list(nvd_api.iter_windows(start, start + timedelta(days=10)))
        assert len(windows) == 1

    def test_long_range_is_split_under_the_api_cap(self):
        """NVD rejects any lastMod window wider than 120 days."""
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=400)
        windows = list(nvd_api.iter_windows(start, end))
        assert len(windows) == 4
        assert all((b - a).days <= nvd_api.MAX_WINDOW_DAYS for a, b in windows)

    def test_windows_are_contiguous_and_cover_the_range(self):
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=400)
        windows = list(nvd_api.iter_windows(start, end))
        assert windows[0][0] == start
        assert windows[-1][1] == end
        for (_, prev_end), (next_start, _) in zip(windows, windows[1:]):
            assert prev_end == next_start


class TestApiKeyHandling:
    def test_key_is_read_from_environment(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "abc123")
        assert nvd_api.get_api_key() == "abc123"

    def test_absent_or_blank_key_is_none(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "   ")
        assert nvd_api.get_api_key() is None
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        assert nvd_api.get_api_key() is None

    def test_key_presence_changes_request_pacing(self):
        """With a key NVD allows 50 requests / 30s instead of 5."""
        assert nvd_api.DELAY_WITH_KEY < nvd_api.DELAY_WITHOUT_KEY
