"""
Tests for metadata pre-filtering.

The invariant under test is the one that matters: a filtered query must never
return a record outside the filter. It is checked against a real ChromaDB
collection and a real FTS index holding the same records, not against stubs,
because the failure modes worth catching live in the backends' filter semantics
- Chroma's inability to express list membership, SQLite's LIKE matching a
substring where a whole element was meant - and a stub would simply agree with
whatever the translation layer did.
"""

import os
import sys

import chromadb
import pytest
from chromadb.config import Settings

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import filters as F
import lexical_index as LX
import retrieval as R

# Records chosen so every filter dimension separates them differently, and so
# the packed lists contain a genuine substring trap: "ssl" inside "openssl",
# "log4j" inside "log4j-core".
RECORDS = [
    {
        "id": "CVE-2021-44228",
        "document": "CVE-2021-44228: Apache Log4j2 JNDI remote code execution in logging.",
        "metadata": {"severity": "CRITICAL", "cvss_base_score": 10.0,
                     "published_ts": 1639131309, "last_modified_ts": 1639131309,
                     "year": "2021", "cwe_ids": "CWE-502|CWE-917",
                     "vendors": "apache", "products": "log4j-core|log4j"},
    },
    {
        "id": "CVE-2014-0160",
        "document": "CVE-2014-0160: OpenSSL heartbeat information disclosure in TLS.",
        "metadata": {"severity": "HIGH", "cvss_base_score": 7.5,
                     "published_ts": 1396915200, "last_modified_ts": 1396915200,
                     "year": "2014", "cwe_ids": "CWE-125",
                     "vendors": "openssl", "products": "openssl"},
    },
    {
        "id": "CVE-2020-0001",
        "document": "CVE-2020-0001: Android elevation of privilege in the framework.",
        "metadata": {"severity": "MEDIUM", "cvss_base_score": 5.5,
                     "published_ts": 1578960000, "last_modified_ts": 1578960000,
                     "year": "2020", "cwe_ids": "CWE-269",
                     "vendors": "google", "products": "android"},
    },
    {
        "id": "CVE-2017-0144",
        "document": "CVE-2017-0144: Windows SMB remote code execution, EternalBlue.",
        "metadata": {"severity": "CRITICAL", "cvss_base_score": 8.1,
                     "published_ts": 1489000000, "last_modified_ts": 1489000000,
                     "year": "2017", "cwe_ids": "CWE-20",
                     "vendors": "microsoft", "products": "windows_7|windows_server_2008"},
    },
]

BY_ID = {r["id"]: r for r in RECORDS}


def _vector(index: int):
    """A deterministic unit vector per record; the ranking is irrelevant here."""
    vec = [0.0] * 8
    vec[index % 8] = 1.0
    return vec


class StubEmbedder:
    def get_embedding(self, text):
        return _vector(len(text))


@pytest.fixture(scope="module")
def backends(tmp_path_factory):
    """A real Chroma collection and a real FTS index over the same records."""
    tmp = tmp_path_factory.mktemp("filters")

    conn = LX.connect(tmp / "lexical.sqlite3")
    LX.create_schema(conn)
    LX.insert_batch(conn, RECORDS)
    LX.create_metadata_indexes(conn)
    conn.commit()

    client = chromadb.PersistentClient(
        path=str(tmp / "chroma"), settings=Settings(anonymized_telemetry=False)
    )
    collection = client.create_collection(
        "filter_tests", metadata={"hnsw:space": "cosine"}
    )
    collection.add(
        ids=[r["id"] for r in RECORDS],
        documents=[r["document"] for r in RECORDS],
        metadatas=[dict(r["metadata"]) for r in RECORDS],
        embeddings=[_vector(i) for i in range(len(RECORDS))],
    )
    yield collection, conn
    conn.close()


def satisfies(cve_id: str, spec: dict) -> bool:
    """Independent re-implementation of the filter, used as the oracle."""
    meta = BY_ID[cve_id]["metadata"]
    for key, value in spec.items():
        if key in ("severity", "year"):
            allowed = value if isinstance(value, (list, tuple, set)) else [value]
            if meta[key] not in allowed:
                return False
        elif key == "min_cvss" and meta["cvss_base_score"] < value:
            return False
        elif key == "max_cvss" and meta["cvss_base_score"] > value:
            return False
        elif key == "published_after" and meta["published_ts"] < value:
            return False
        elif key == "published_before" and meta["published_ts"] > value:
            return False
        elif key in ("vendor", "product", "cwe"):
            column = {"vendor": "vendors", "product": "products", "cwe": "cwe_ids"}[key]
            elements = [e.lower() for e in (meta[column] or "").split("|")]
            if str(value).lower() not in elements:
                return False
    return True


# Every filter shape the module claims to support, plus the substring traps.
SPECS = [
    {"severity": "CRITICAL"},
    {"severity": ["CRITICAL", "HIGH"]},
    {"year": "2021"},
    {"year": ["2014", "2017"]},
    {"min_cvss": 8.0},
    {"max_cvss": 7.5},
    {"min_cvss": 7.0, "max_cvss": 9.0},
    {"published_after": 1500000000},
    {"published_before": 1500000000},
    {"published_after": 1400000000, "published_before": 1600000000},
    {"vendor": "apache"},
    {"vendor": "openssl"},
    {"product": "log4j"},
    {"product": "ssl"},          # must NOT match "openssl"
    {"product": "windows_7"},
    {"cwe": "CWE-502"},
    {"cwe": "CWE-20"},           # must NOT match "CWE-269" or "CWE-2000"
    {"severity": "CRITICAL", "vendor": "apache"},
    {"severity": ["CRITICAL", "HIGH"], "min_cvss": 8.0},
    {"year": "2021", "product": "log4j", "min_cvss": 9.0},
]

QUERIES = ["remote code execution", "disclosure", "framework", "CVE-2014-0160"]


class TestInvariant:
    """A filtered query must never return a record outside the filter."""

    @pytest.mark.parametrize("mode", ["dense", "bm25", "hybrid"])
    @pytest.mark.parametrize("spec", SPECS)
    def test_no_result_falls_outside_the_filter(self, backends, mode, spec):
        collection, conn = backends
        retriever = R.build_retriever(
            mode, collection=collection, embedder=StubEmbedder(),
            lexical_conn=conn, filters=spec,
        )
        for query in QUERIES:
            for cve_id in retriever.search(query, 10):
                assert satisfies(cve_id, spec), (
                    f"{mode} returned {cve_id} for {query!r} under {spec}"
                )

    @pytest.mark.parametrize("spec", SPECS)
    def test_filtering_does_not_lose_records_it_should_keep(self, backends, spec):
        """
        The mirror of the invariant. Excluding everything also never returns a
        record outside the filter, so correctness needs both directions: with a
        depth well above the corpus size, BM25 must find every matching record
        whose text the query can reach.
        """
        _, conn = backends
        retriever = R.build_retriever("bm25", lexical_conn=conn, filters=spec)
        found = set(retriever.search("in the of a", 50)) | set(
            retriever.search("CVE remote disclosure privilege execution", 50)
        )
        expected = {r["id"] for r in RECORDS if satisfies(r["id"], spec)}
        # Only assert over records the unfiltered query could reach at all.
        reachable = set(R.build_retriever("bm25", lexical_conn=conn).search(
            "in the of a", 50
        )) | set(R.build_retriever("bm25", lexical_conn=conn).search(
            "CVE remote disclosure privilege execution", 50
        ))
        assert found == expected & reachable

    def test_an_empty_allow_list_returns_nothing_on_every_backend(self, backends):
        collection, conn = backends
        for mode in ("dense", "bm25", "hybrid"):
            retriever = R.build_retriever(
                mode, collection=collection, embedder=StubEmbedder(),
                lexical_conn=conn, filters={"severity": []},
            )
            assert retriever.search("remote code execution", 10) == []

    def test_a_filter_matching_no_record_returns_nothing(self, backends):
        collection, conn = backends
        retriever = R.build_retriever(
            "hybrid", collection=collection, embedder=StubEmbedder(),
            lexical_conn=conn, filters={"vendor": "nonexistent-vendor"},
        )
        assert retriever.search("remote code execution", 10) == []

    def test_both_arms_of_hybrid_are_filtered(self, backends):
        """
        If only one arm were filtered, fusion would still surface the other
        arm's out-of-filter records - with plausible-looking ranks.
        """
        collection, conn = backends
        retriever = R.build_retriever(
            "hybrid", collection=collection, embedder=StubEmbedder(),
            lexical_conn=conn, filters={"severity": "MEDIUM"},
        )
        arms = retriever._arms("remote code execution disclosure")
        for arm in arms:
            for cve_id in arm:
                assert BY_ID[cve_id]["metadata"]["severity"] == "MEDIUM"


class TestPreFilterNotPostFilter:
    def test_depth_returns_that_many_matching_records(self, backends):
        """
        A post-filter would return however many of the top-N survived trimming.
        Two records are CRITICAL; asking for two must return two.
        """
        collection, conn = backends
        retriever = R.build_retriever(
            "bm25", lexical_conn=conn, filters={"severity": "CRITICAL"}
        )
        assert len(retriever.search("CVE remote code execution", 2)) == 2


class TestValidation:
    def test_unknown_key_raises_rather_than_being_ignored(self):
        with pytest.raises(F.FilterError, match="unknown filter field"):
            F.validate({"vendorr": "apache"})

    def test_unknown_key_raises_through_the_lexical_index(self):
        with pytest.raises(F.FilterError):
            LX._where_clause({"serverity": "CRITICAL"})

    def test_unknown_key_raises_through_build_retriever(self, backends):
        collection, conn = backends
        with pytest.raises(F.FilterError):
            R.build_retriever("bm25", lexical_conn=conn, filters={"nope": 1})

    def test_range_bounds_must_be_numbers(self):
        with pytest.raises(F.FilterError, match="must be a number"):
            F.validate({"min_cvss": "high"})

    def test_swapped_cvss_bounds_are_rejected(self):
        with pytest.raises(F.FilterError, match="exceeds max_cvss"):
            F.validate({"min_cvss": 9.0, "max_cvss": 7.0})

    def test_empty_spec_is_valid(self):
        assert F.validate(None) == {}
        assert F.validate({}) == {}


class TestChromaTranslation:
    def test_single_condition_is_not_wrapped_in_and(self):
        assert F.to_chroma_where({"severity": "CRITICAL"}) == {"severity": {"$eq": "CRITICAL"}}

    def test_multiple_conditions_are_combined_with_and(self):
        where = F.to_chroma_where({"severity": "CRITICAL", "min_cvss": 9.0})
        assert "$and" in where and len(where["$and"]) == 2

    def test_list_value_becomes_in(self):
        assert F.to_chroma_where({"year": ["2014", "2021"]}) == \
            {"year": {"$in": ["2014", "2021"]}}

    def test_ranges_map_to_the_timestamp_and_score_fields(self):
        assert F.to_chroma_where({"published_after": 100}) == \
            {"published_ts": {"$gte": 100}}
        assert F.to_chroma_where({"max_cvss": 7.0}) == \
            {"cvss_base_score": {"$lte": 7.0}}

    def test_packed_list_fields_are_excluded_from_the_where_clause(self):
        """They are unrepresentable in Chroma; emitting a partial clause would
        silently widen the filter."""
        assert F.to_chroma_where({"vendor": "apache"}) is None
        assert F.to_chroma_where({"vendor": "apache", "severity": "HIGH"}) == \
            {"severity": {"$eq": "HIGH"}}

    def test_no_filters_means_no_clause(self):
        assert F.to_chroma_where(None) is None
        assert F.to_chroma_where({}) is None


class TestAllowlist:
    def test_resolves_only_the_list_valued_part(self, backends):
        _, conn = backends
        assert F.resolve_allowlist(conn, {"severity": "CRITICAL"}) is None
        assert F.resolve_allowlist(conn, {"vendor": "apache"}) == ["CVE-2021-44228"]

    def test_none_means_no_allow_list_while_empty_means_nothing_matches(self, backends):
        _, conn = backends
        assert F.resolve_allowlist(conn, {}) is None
        assert F.resolve_allowlist(conn, {"vendor": "nobody"}) == []

    def test_dense_mode_needs_the_lexical_index_for_packed_list_fields(self, backends):
        collection, _ = backends
        with pytest.raises(R.RetrievalError, match="packed-list"):
            R.build_retriever("dense", collection=collection,
                              embedder=StubEmbedder(), filters={"vendor": "apache"})

    def test_describe_is_stable_and_readable(self):
        assert F.describe({"severity": "HIGH", "min_cvss": 7.0}) == \
            "min_cvss=7.0, severity=HIGH"
        assert F.describe(None) == "none"
