"""
Tests for document-layout provenance.

The fingerprint has to satisfy two opposing properties, and both are easy to get
wrong in a way that is silent: it must change when the rendered documents change
(or it fails to catch drift), and it must *not* change when only comments or
internal structure change (or it cries wolf and gets ignored).
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import nvd_normalize as N
import provenance


class TestFingerprintStability:
    def test_is_deterministic(self):
        assert N.layout_fingerprint() == N.layout_fingerprint()

    def test_is_short_and_hex(self):
        fingerprint = N.layout_fingerprint()
        assert len(fingerprint) == 16
        assert all(c in "0123456789abcdef" for c in fingerprint)

    def test_survives_a_comment_or_docstring_change(self):
        """
        The hash covers rendered output, not source text, so editing prose in
        the module must not invalidate every committed result file.
        """
        original = N.build_document_text.__doc__
        try:
            N.build_document_text.__doc__ = "completely different prose"
            assert N.layout_fingerprint() == provenance.N.layout_fingerprint()
        finally:
            N.build_document_text.__doc__ = original


class TestFingerprintSensitivity:
    """Each layout decision must move the hash, or it is not being protected."""

    @pytest.mark.parametrize("constant,new_value", [
        ("MAX_VENDORS_IN_TEXT", 3),
        ("MAX_PRODUCTS_IN_TEXT", 4),
        ("MAX_VENDORS_IN_METADATA", 5),
        ("MAX_PRODUCTS_IN_METADATA", 7),
        ("LIST_DELIMITER", ";"),
    ])
    def test_changing_a_layout_constant_changes_the_fingerprint(self, constant, new_value):
        baseline = N.layout_fingerprint()
        original = getattr(N, constant)
        try:
            setattr(N, constant, new_value)
            assert N.layout_fingerprint() != baseline, (
                f"{constant} is not covered by the fingerprint"
            )
        finally:
            setattr(N, constant, original)

    def test_fixtures_exercise_the_text_caps(self):
        """A fixture below the caps would leave them untested."""
        record = N.layout_fixtures()[0]
        _, vendors, products = N.extract_cpe_entries(record)
        assert len(vendors) > N.MAX_VENDORS_IN_TEXT
        assert len(products) > N.MAX_PRODUCTS_IN_TEXT

    def test_fixtures_exercise_cna_first_ordering(self):
        """The CNA-supplied vendor must lead, or CPE ordering is unprotected."""
        document = N.normalize(N.layout_fixtures()[0])["document"]
        assert "Affected vendors: cna_vendor," in document

    def test_fixtures_exercise_cvss_precedence(self):
        """v3.1 must win over the v2 block present in the same fixture."""
        document = N.normalize(N.layout_fixtures()[0])["document"]
        assert "CRITICAL" in document and "3.1" in document

    def test_fixtures_include_a_record_with_no_optional_sections(self):
        document = N.normalize(N.layout_fixtures()[1])["document"]
        assert "Affected vendors" not in document
        assert "Severity" not in document

    def test_fixtures_do_not_depend_on_the_corpus(self):
        """Fixture IDs must not collide with real CVEs, so feeds cannot shift them."""
        for record in N.layout_fixtures():
            assert record["id"].startswith("CVE-2000-0000")


class TestLayoutMatching:
    def test_matching_manifest_passes(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"document_layout": N.layout_descriptor()}))
        assert provenance.require_layout_match(manifest)["status"] == "match"

    def test_mismatched_manifest_raises_with_the_fix(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        stale = dict(N.layout_descriptor(), fingerprint="0000000000000000", version=1)
        manifest.write_text(json.dumps({"document_layout": stale}))
        with pytest.raises(provenance.LayoutMismatch, match="ingest_nvd.py --reset"):
            provenance.require_layout_match(manifest)

    def test_absent_layout_is_reported_not_assumed_to_match(self, tmp_path):
        """An index built before layout recording must not be silently blessed."""
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"corpus": {}}))
        assert provenance.require_layout_match(manifest)["status"] == "unrecorded"

    def test_missing_manifest_file_is_unrecorded(self, tmp_path):
        assert provenance.require_layout_match(
            tmp_path / "absent.json"
        )["status"] == "unrecorded"


class TestStamp:
    def test_stamp_carries_time_and_layout(self):
        block = provenance.stamp()
        assert block["generated_at"].endswith("+00:00")
        assert block["document_layout"]["fingerprint"] == N.layout_fingerprint()
        assert block["document_layout"]["version"] == N.DOCUMENT_LAYOUT_VERSION

    def test_stamp_merges_extra_fields(self):
        assert provenance.stamp({"note": "x"})["note"] == "x"

    def test_stamp_is_json_serializable(self):
        json.dumps(provenance.stamp())


class TestCommittedArtifacts:
    """The committed manifest and results must actually carry what they claim."""

    def test_manifest_records_the_shipped_layout(self):
        recorded = provenance.recorded_layout()
        assert recorded is not None, "data/manifest.json has no document_layout"
        assert recorded["fingerprint"] == N.layout_fingerprint()

    def test_manifest_layout_was_verified_against_the_index(self):
        verification = provenance.recorded_layout().get("verified_against_index")
        assert verification is not None
        assert verification["mismatches"] == 0
        assert verification["documents_compared"] > 0
