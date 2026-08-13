"""
Tests for the SQLite FTS5 lexical index.

The emphasis is on query hygiene. FTS5 MATCH takes a query *language*, so text
arriving from outside the system is syntax unless it is deliberately turned back
into data. An unescaped quote or a bare "AND" either raises
sqlite3.OperationalError or silently changes what was asked for, and neither
failure is visible in the results.
"""

import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import lexical_index as LX


@pytest.fixture
def index(tmp_path):
    """A small in-file index with predictable contents."""
    conn = LX.connect(tmp_path / "test.sqlite3")
    LX.create_schema(conn)
    rows = [
        {
            "id": "CVE-2021-44228",
            "document": "CVE-2021-44228: Apache Log4j2 JNDI remote code execution.\n"
                        "Affected products: Apache Log4j2\nSeverity: CRITICAL",
            "metadata": {"severity": "CRITICAL", "cvss_base_score": 10.0,
                         "published_ts": 1639130000, "year": "2021",
                         "cwe_ids": "CWE-502|CWE-917", "vendors": "apache",
                         "products": "Apache Log4j2|log4j"},
        },
        {
            "id": "CVE-2014-0160",
            "document": "CVE-2014-0160: OpenSSL heartbeat information disclosure.\n"
                        "Affected products: openssl\nSeverity: HIGH",
            "metadata": {"severity": "HIGH", "cvss_base_score": 7.5,
                         "published_ts": 1396915200, "year": "2014",
                         "cwe_ids": "CWE-125", "vendors": "openssl",
                         "products": "openssl"},
        },
        {
            "id": "CVE-2020-0001",
            "document": "CVE-2020-0001: Android elevation of privilege.\n"
                        "Affected products: android\nSeverity: MEDIUM",
            "metadata": {"severity": "MEDIUM", "cvss_base_score": 5.5,
                         "published_ts": 1578960000, "year": "2020",
                         "cwe_ids": "", "vendors": "google", "products": "android"},
        },
    ]
    LX.insert_batch(conn, rows)
    LX.create_metadata_indexes(conn)
    conn.commit()
    yield conn
    conn.close()


class TestQueryEscaping:
    def test_operators_become_literal_terms(self):
        """AND / OR / NOT / NEAR must be searched for, not executed."""
        escaped = LX.escape_fts_query("log4j AND NOT NEAR")
        assert escaped == '"log4j" OR "AND" OR "NOT" OR "NEAR"'

    def test_surrounding_quotes_are_stripped_not_passed_through(self):
        assert LX.escape_fts_query('say "hi"') == '"say" OR "hi"'

    def test_every_emitted_term_is_a_balanced_quoted_literal(self):
        """
        The escaped expression must contain only quoted literals joined by OR.
        If a raw quote ever leaked through, the quote count would go odd and
        FTS5 would reinterpret the tail of the query as syntax.
        """
        for value in ('ab"cd', 'a"b"c', '"""', 'x" OR y'):
            escaped = LX.escape_fts_query(value)
            if not escaped:
                # No searchable term at all ('"""'); callers treat this as
                # "no results" and never hand it to MATCH.
                continue
            assert escaped.count('"') % 2 == 0, f"unbalanced quotes for {value!r}"
            for term in escaped.split(" OR "):
                assert term.startswith('"') and term.endswith('"'), term

    def test_empty_input_yields_empty_expression(self):
        for value in ("", "   ", "!!!", "()"):
            assert LX.escape_fts_query(value) == ""

    def test_terms_are_capped(self):
        escaped = LX.escape_fts_query(" ".join(f"w{i}" for i in range(200)))
        assert escaped.count(" OR ") + 1 == LX.MAX_QUERY_TERMS

    def test_identifier_survives_as_one_term(self):
        """Hyphens and dots are word characters for this tokenizer."""
        assert LX.escape_fts_query("CVE-2021-44228") == '"CVE-2021-44228"'
        assert LX.escape_fts_query("log4j 2.14.1") == '"log4j" OR "2.14.1"'


class TestSearchSafety:
    @pytest.mark.parametrize("hostile", [
        'unbalanced " quote',
        '"; DROP TABLE cve_fts; --',
        "wildcard* prefix^ NEAR(a b)",
        "(((",
        "AND OR NOT",
        "a" * 500,
        "ü ñ \U0001f525",
    ])
    def test_hostile_input_does_not_raise(self, index, hostile):
        LX.search(index, hostile, 5)

    def test_injection_attempt_leaves_the_table_intact(self, index):
        LX.search(index, '"; DROP TABLE cve_fts; --', 5)
        assert LX.document_count(index) == 3

    def test_empty_query_returns_no_results(self, index):
        assert LX.search(index, "   ", 5) == []


class TestRanking:
    def test_exact_identifier_ranks_first(self, index):
        hits = LX.search(index, "CVE-2021-44228", 5)
        assert hits[0][0] == "CVE-2021-44228"

    def test_product_term_finds_its_record(self, index):
        assert LX.search(index, "openssl heartbeat", 5)[0][0] == "CVE-2014-0160"

    def test_scores_are_larger_is_better(self, index):
        """SQLite bm25() is negative-better; the wrapper flips it."""
        hits = LX.search(index, "Apache Log4j2 JNDI", 5)
        scores = [score for _, score in hits]
        assert scores == sorted(scores, reverse=True)
        assert scores[0] > 0

    def test_limit_is_respected(self, index):
        assert len(LX.search(index, "products", 2)) <= 2


class TestMetadataFiltering:
    """A filtered search must never return a record outside the filter."""

    def test_severity_filter(self, index):
        hits = LX.search(index, "products", 10, filters={"severity": "CRITICAL"})
        assert [h[0] for h in hits] == ["CVE-2021-44228"]

    def test_severity_accepts_a_list(self, index):
        ids = {h[0] for h in LX.search(index, "products", 10,
                                       filters={"severity": ["CRITICAL", "HIGH"]})}
        assert ids == {"CVE-2021-44228", "CVE-2014-0160"}

    def test_cvss_range(self, index):
        ids = {h[0] for h in LX.search(index, "products", 10, filters={"min_cvss": 7.0})}
        assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
        ids = {h[0] for h in LX.search(index, "products", 10,
                                       filters={"min_cvss": 6.0, "max_cvss": 8.0})}
        assert ids == {"CVE-2014-0160"}

    def test_published_date_range(self, index):
        ids = {h[0] for h in LX.search(index, "products", 10,
                                       filters={"published_after": 1500000000})}
        assert ids == {"CVE-2021-44228", "CVE-2020-0001"}

    def test_vendor_and_product_filters(self, index):
        assert {h[0] for h in LX.search(index, "products", 10,
                                        filters={"vendor": "apache"})} == {"CVE-2021-44228"}
        assert {h[0] for h in LX.search(index, "products", 10,
                                        filters={"product": "openssl"})} == {"CVE-2014-0160"}

    def test_cwe_filter(self, index):
        assert {h[0] for h in LX.search(index, "products", 10,
                                        filters={"cwe": "CWE-502"})} == {"CVE-2021-44228"}

    def test_packed_list_filter_matches_whole_elements_only(self, index):
        """'ssl' must not match the product 'openssl'."""
        assert LX.search(index, "products", 10, filters={"product": "ssl"}) == []

    def test_empty_allow_list_matches_nothing(self, index):
        assert LX.search(index, "products", 10, filters={"severity": []}) == []

    def test_combined_filters_intersect(self, index):
        hits = LX.search(index, "products", 10,
                         filters={"severity": ["CRITICAL", "HIGH"], "year": "2014"})
        assert [h[0] for h in hits] == ["CVE-2014-0160"]

    def test_filter_ids_ignores_relevance(self, index):
        assert set(LX.filter_ids(index, {"severity": "MEDIUM"})) == {"CVE-2020-0001"}


class TestLookup:
    def test_get_by_id(self, index):
        assert LX.get_by_id(index, "CVE-2014-0160")["severity"] == "HIGH"

    def test_get_by_id_missing_returns_none(self, index):
        assert LX.get_by_id(index, "CVE-1999-9999") is None


class TestConnection:
    def test_read_only_open_on_missing_file_is_explicit(self, tmp_path):
        with pytest.raises(LX.LexicalIndexError, match="no lexical index"):
            LX.connect(tmp_path / "absent.sqlite3", read_only=True)
