"""
Tests for NVD record normalization.

These focus on the cases that silently corrupt a corpus rather than crash it:
CVSS source precedence, CPE escaping, placeholder handling, and the filters that
decide what gets indexed at all.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import nvd_normalize as N


def make_record(**overrides):
    """A minimal valid record; override individual fields per test."""
    record = {
        "id": "CVE-2024-0001",
        "vulnStatus": "Analyzed",
        "published": "2024-01-31T14:15:45.000",
        "lastModified": "2024-02-01T10:00:00.000",
        "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
    }
    record.update(overrides)
    return record


class TestCpeParsing:
    def test_splits_on_unescaped_colons_only(self):
        cpe = r"cpe:2.3:a:purestorage:purity\/\/fa:*:*:*:*:*:*:*:*"
        parts = N.split_cpe(cpe)
        assert parts[0] == "cpe"
        assert parts[2] == "a"
        assert parts[3] == "purestorage"
        # The escaped slashes must not split the product into extra fields.
        assert parts[4] == r"purity\/\/fa"

    def test_escaped_colon_stays_in_component(self):
        parts = N.split_cpe(r"cpe:2.3:a:vendor:pro\:duct:1.0")
        assert parts[4] == r"pro\:duct"

    def test_unescape_makes_component_readable(self):
        assert N.unescape_cpe_component(r"purity\/\/fa") == "purity//fa"
        assert N.unescape_cpe_component("apache_http_server") == "apache http server"

    def test_extracts_vendor_and_product_from_configurations(self):
        record = make_record(
            configurations=[
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": r"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ]
        )
        criteria, vendors, products = N.extract_cpe_entries(record)
        assert vendors == ["apache"]
        assert products == ["log4j"]
        assert len(criteria) == 1

    def test_cna_product_ranks_ahead_of_cpe_products(self):
        """
        The CNA names the product that is actually broken; CPE enumerates every
        downstream product that bundles it. Since the list is truncated before
        embedding, CNA-first ordering is what keeps the headline product in the
        text.

        Modelled on CVE-2021-44228, whose CPE list starts with Siemens firmware
        part numbers while the CNA entry is "Apache Log4j2".
        """
        record = make_record(
            affected=[
                {"affectedData": [{"vendor": "Apache Software Foundation",
                                   "product": "Apache Log4j2"}]}
            ],
            configurations=[
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": f"cpe:2.3:o:siemens:6bk1602-0aa{i}2-0tp0:*:*:*:*:*:*:*:*"}
                                for i in range(40)
                            ]
                        }
                    ]
                }
            ],
        )
        _, vendors, products = N.extract_cpe_entries(record)
        assert products[0] == "Apache Log4j2"
        assert vendors[0] == "Apache Software Foundation"
        # And it survives truncation into the embedded text.
        assert "Apache Log4j2" in N.build_document_text(record)

    def test_skips_placeholder_vendor_and_product(self):
        record = make_record(
            affected=[
                {"affectedData": [{"vendor": "n/a", "product": "-"}]},
                {"affectedData": [{"vendor": "Acme", "product": "Widget"}]},
            ]
        )
        _, vendors, products = N.extract_cpe_entries(record)
        assert vendors == ["Acme"]
        assert products == ["Widget"]


class TestCvssSelection:
    def test_prefers_primary_over_secondary_same_version(self):
        """A vendor's inflated self-report must not beat NVD's own score."""
        record = make_record(
            metrics={
                "cvssMetricV31": [
                    {
                        "type": "Secondary",
                        "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL",
                                     "vectorString": "CVSS:3.1/SECONDARY"},
                    },
                    {
                        "type": "Primary",
                        "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH",
                                     "vectorString": "CVSS:3.1/PRIMARY"},
                    },
                ]
            }
        )
        cvss = N.extract_cvss(record)
        assert cvss["cvss_base_score"] == 7.5
        assert cvss["severity"] == "HIGH"
        assert cvss["cvss_vector"] == "CVSS:3.1/PRIMARY"

    def test_prefers_newer_cvss_version(self):
        record = make_record(
            metrics={
                "cvssMetricV2": [
                    {"type": "Primary", "cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}
                ],
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                    }
                ],
            }
        )
        assert N.extract_cvss(record)["cvss_version"] == "3.1"
        assert N.extract_cvss(record)["cvss_base_score"] == 9.8

    def test_cvss_v2_severity_lives_on_the_wrapper(self):
        record = make_record(
            metrics={
                "cvssMetricV2": [
                    {
                        "type": "Primary",
                        "cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L"},
                        "baseSeverity": "MEDIUM",
                    }
                ]
            }
        )
        assert N.extract_cvss(record)["severity"] == "MEDIUM"

    def test_missing_metrics_is_not_an_error(self):
        cvss = N.extract_cvss(make_record())
        assert cvss["cvss_base_score"] is None
        assert cvss["severity"] == ""


class TestCweExtraction:
    def test_drops_nvd_placeholders(self):
        record = make_record(
            weaknesses=[
                {
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}],
                }
            ]
        )
        assert N.extract_cwes(record) == []

    def test_primary_ordered_before_secondary_and_deduped(self):
        record = make_record(
            weaknesses=[
                {"type": "Secondary", "description": [{"lang": "en", "value": "CWE-89"}]},
                {"type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]},
                {"type": "Secondary", "description": [{"lang": "en", "value": "CWE-79"}]},
            ]
        )
        assert N.extract_cwes(record) == ["CWE-79", "CWE-89"]


class TestFiltering:
    def test_rejected_cve_is_excluded(self):
        keep, reason = N.should_index(make_record(vulnStatus="Rejected"))
        assert keep is False
        assert reason == "rejected"

    def test_record_without_english_description_is_excluded(self):
        record = make_record(descriptions=[{"lang": "es", "value": "Una vulnerabilidad."}])
        keep, reason = N.should_index(record)
        assert keep is False
        assert reason == "no_english_description"

    def test_normal_record_is_kept(self):
        assert N.should_index(make_record())[0] is True

    def test_normalize_returns_none_for_filtered_record(self):
        assert N.normalize(make_record(vulnStatus="Rejected")) is None


class TestDocumentText:
    def test_embeds_identifier_products_and_description(self):
        record = make_record(
            descriptions=[{"lang": "en", "value": "Remote code execution in a logging library."}],
            metrics={
                "cvssMetricV31": [
                    {"type": "Primary", "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                ]
            },
            configurations=[
                {"nodes": [{"cpeMatch": [{"criteria": r"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}
            ],
            weaknesses=[{"type": "Primary", "description": [{"lang": "en", "value": "CWE-502"}]}],
        )
        text = N.build_document_text(record)
        assert "CVE-2024-0001" in text
        assert "apache" in text
        assert "log4j" in text
        assert "CWE-502" in text
        assert "CRITICAL" in text
        assert "Remote code execution in a logging library." in text

    def test_product_list_is_capped(self):
        """One CVE listing thousands of CPEs must not crowd out the description."""
        matches = [
            {"criteria": f"cpe:2.3:a:vendor{i}:product{i}:1.0:*:*:*:*:*:*:*"}
            for i in range(200)
        ]
        record = make_record(configurations=[{"nodes": [{"cpeMatch": matches}]}])
        text = N.build_document_text(record)
        products_line = next(l for l in text.splitlines() if l.startswith("Affected products:"))
        assert len(products_line.split(", ")) <= N.MAX_PRODUCTS_IN_TEXT
        assert "A test vulnerability." in text


class TestMetadata:
    def test_values_are_chroma_compatible_scalars(self):
        """ChromaDB rejects list/dict/None metadata values."""
        record = make_record(
            metrics={
                "cvssMetricV31": [
                    {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                ]
            },
            weaknesses=[{"type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}],
        )
        meta = N.build_metadata(record)
        for key, value in meta.items():
            assert isinstance(value, (str, int, float, bool)), f"{key} is {type(value)}"

    def test_dates_are_stored_as_epoch_for_range_queries(self):
        meta = N.build_metadata(make_record())
        assert isinstance(meta["published_ts"], int)
        assert meta["published_ts"] > 0
        assert meta["published"] == "2024-01-31T14:15:45.000"

    def test_absent_score_omits_key_rather_than_storing_none(self):
        meta = N.build_metadata(make_record())
        assert "cvss_base_score" not in meta

    def test_year_is_derived_from_the_identifier(self):
        assert N.build_metadata(make_record())["year"] == "2024"
