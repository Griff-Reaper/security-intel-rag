"""
Tests for the retrieval backends and rank fusion.

The fusion tests use hand-built ranked lists rather than a live index, because
what needs pinning down is the arithmetic and the ordering policy - including
the tie behaviour, which is the part most likely to be quietly "fixed" later
into an unstated arm weighting.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import retrieval as R


class TestReciprocalRankFusion:
    def test_score_matches_the_formula(self):
        fused = dict(R.reciprocal_rank_fusion([["a", "b"], ["b", "a"]], k=60))
        # Both documents sit at ranks 1 and 2, so both score 1/61 + 1/62.
        expected = 1 / 61 + 1 / 62
        assert fused["a"] == pytest.approx(expected)
        assert fused["b"] == pytest.approx(expected)

    @staticmethod
    def _two_arms_agreeing_at(rank: int):
        """Arms that each rank a private document first and 'shared' at `rank`."""
        pad_a = [f"pad_a{i}" for i in range(rank - 2)]
        pad_b = [f"pad_b{i}" for i in range(rank - 2)]
        return (["only_a"] + pad_a + ["shared"], ["only_b"] + pad_b + ["shared"])

    @pytest.mark.parametrize("rank,agreement_wins", [(2, True), (61, True), (63, False)])
    def test_agreement_outranks_a_lone_rank_one_up_to_the_crossover(
        self, rank, agreement_wins
    ):
        """
        With two arms and k=60, a document both arms rank at position r beats a
        document one arm alone ranks first exactly while 2/(60+r) > 1/61, i.e.
        for r up to 61. Pinning the crossover keeps a later change to k from
        silently redefining how much arm agreement is worth.
        """
        arm_a, arm_b = self._two_arms_agreeing_at(rank)
        fused = dict(R.reciprocal_rank_fusion([arm_a, arm_b], k=60))
        assert (fused["shared"] > fused["only_a"]) is agreement_wins

    def test_missing_from_an_arm_contributes_nothing(self):
        fused = dict(R.reciprocal_rank_fusion([["a"], ["b"]], k=60))
        assert fused["a"] == pytest.approx(1 / 61)
        assert fused["b"] == pytest.approx(1 / 61)

    def test_k_controls_how_sharply_the_head_is_favoured(self):
        arm = ["first", "second"]
        sharp = dict(R.reciprocal_rank_fusion([arm], k=1))
        flat = dict(R.reciprocal_rank_fusion([arm], k=1000))
        assert sharp["first"] / sharp["second"] > flat["first"] / flat["second"]

    def test_disjoint_arms_tie_at_every_rank(self):
        """The degenerate case the tie-break exists for: no shared candidates."""
        arms = [["d0", "d1", "d2"], ["l0", "l1", "l2"]]
        scores = [score for _, score in R.reciprocal_rank_fusion(arms)]
        assert scores[0] == pytest.approx(scores[1])
        assert scores[2] == pytest.approx(scores[3])

    def test_without_a_tie_break_arm_order_falls_to_document_id(self):
        forward = [d for d, _ in R.reciprocal_rank_fusion([["zebra"], ["alpha"]])]
        backward = [d for d, _ in R.reciprocal_rank_fusion([["alpha"], ["zebra"]])]
        assert forward == backward == ["alpha", "zebra"]

    def test_tie_break_arm_wins_ties_regardless_of_document_id(self):
        """The preferred arm's pick comes first even when the ID sorts later."""
        arms = [["alpha"], ["zebra"]]
        assert [d for d, _ in R.reciprocal_rank_fusion(arms, tie_break_arm=1)][0] == "zebra"
        assert [d for d, _ in R.reciprocal_rank_fusion(arms, tie_break_arm=0)][0] == "alpha"

    def test_tie_break_cannot_override_a_real_score_difference(self):
        """A tie-break must only order equals, never promote a lower score."""
        arms = [["winner", "loser"], ["winner", "other"]]
        fused = R.reciprocal_rank_fusion(arms, tie_break_arm=1)
        assert fused[0][0] == "winner"

    def test_documents_absent_from_the_tie_break_arm_sort_last_within_a_tie(self):
        arms = [["only_dense"], ["in_lexical"]]
        order = [d for d, _ in R.reciprocal_rank_fusion(arms, tie_break_arm=1)]
        assert order == ["in_lexical", "only_dense"]

    def test_out_of_range_tie_break_arm_is_ignored_not_fatal(self):
        assert [d for d, _ in R.reciprocal_rank_fusion([["b"], ["a"]], tie_break_arm=9)] \
            == ["a", "b"]

    def test_shipped_tie_break_prefers_the_lexical_arm(self):
        assert R.TIE_BREAK_ARM == R.LEXICAL_ARM == 1

    def test_empty_input(self):
        assert R.reciprocal_rank_fusion([]) == []
        assert R.reciprocal_rank_fusion([[], []]) == []

    def test_default_k_is_the_module_constant(self):
        assert R.RRF_K == 60
        assert (R.reciprocal_rank_fusion([["a"]])[0][1]
                == pytest.approx(1 / (R.RRF_K + 1)))


class TestPercentile:
    def test_known_values(self):
        values = list(range(1, 101))
        assert R.percentile(values, 50) == 50
        assert R.percentile(values, 95) == 95
        assert R.percentile(values, 0) == 1
        assert R.percentile(values, 100) == 100

    def test_reported_values_are_observations_not_interpolations(self):
        assert R.percentile([10.0, 20.0], 50) in (10.0, 20.0)

    def test_empty(self):
        assert R.percentile([], 50) == 0.0

    def test_unsorted_input(self):
        assert R.percentile([9, 1, 5], 50) == 5


class TestLatencyRecorder:
    def test_summary_shape(self):
        rec = R.LatencyRecorder()
        for ms in (10.0, 20.0, 30.0):
            rec.record(ms)
        summary = rec.summary()
        assert summary["queries"] == 3
        assert summary["mean_ms"] == 20.0
        assert summary["p50_ms"] == 20.0

    def test_empty_summary_does_not_divide_by_zero(self):
        assert R.LatencyRecorder().summary()["queries"] == 0


# ── Backends against stub arms ───────────────────────────────────────────────
class StubCollection:
    """Minimal ChromaDB stand-in returning a fixed dense ranking."""

    name = "stub"

    def __init__(self, ranking, documents=None):
        self.ranking = ranking
        self.documents = documents or {}
        self.last_n_results = None

    def query(self, query_embeddings, n_results, where=None, ids=None):
        """Mirrors the Chroma signature the dense arm calls.

        `ids` is honoured because it is how packed-list filters reach Chroma;
        `where` is only recorded, since reimplementing Chroma's metadata
        operators in a stub would test the stub. Filter semantics are covered
        against a real collection in tests/test_filters.py.
        """
        self.last_n_results = n_results
        self.last_where = where
        candidates = self.ranking
        if ids is not None:
            allowed = set(ids)
            candidates = [d for d in candidates if d in allowed]
        return {"ids": [candidates[:n_results]]}

    def get(self, ids, include=None):
        ids = [i for i in ids if i in self.documents]
        return {"ids": ids, "documents": [self.documents[i] for i in ids]}

    def count(self):
        return len(self.ranking)


class StubEmbedder:
    def get_embedding(self, text):
        return [0.0] * 384


@pytest.fixture
def lexical(tmp_path):
    """A tiny real FTS index, so the lexical arm is exercised for real."""
    import lexical_index as LX

    conn = LX.connect(tmp_path / "fts.sqlite3")
    LX.create_schema(conn)
    LX.insert_batch(conn, [
        {"id": "CVE-2021-44228",
         "document": "CVE-2021-44228: Apache Log4j2 JNDI remote code execution.",
         "metadata": {"severity": "CRITICAL", "cvss_base_score": 10.0}},
        {"id": "CVE-2014-0160",
         "document": "CVE-2014-0160: OpenSSL heartbeat information disclosure.",
         "metadata": {"severity": "HIGH", "cvss_base_score": 7.5}},
    ])
    conn.commit()
    yield conn
    conn.close()


class TestBackends:
    def test_dense_returns_the_collection_ranking(self):
        collection = StubCollection(["a", "b", "c"])
        r = R.build_retriever("dense", collection=collection, embedder=StubEmbedder())
        assert r.search("anything", 2) == ["a", "b"]
        assert r.name == "dense"

    def test_bm25_finds_an_identifier_dense_would_miss(self, lexical):
        r = R.build_retriever("bm25", lexical_conn=lexical)
        assert r.search("CVE-2014-0160", 5)[0] == "CVE-2014-0160"

    def test_hybrid_pulls_arm_depth_not_result_depth(self, lexical):
        """Fusion must see ARM_DEPTH candidates even when asked for 10."""
        collection = StubCollection([f"doc{i}" for i in range(300)])
        r = R.build_retriever("hybrid", collection=collection,
                              embedder=StubEmbedder(), lexical_conn=lexical)
        r.search("openssl", 10)
        assert collection.last_n_results == R.ARM_DEPTH

    def test_hybrid_recovers_what_the_dense_arm_ranked_last(self, lexical):
        """The whole point: a lexical rank-1 hit surfaces despite a bad dense arm."""
        collection = StubCollection([f"noise{i}" for i in range(100)])
        r = R.build_retriever("hybrid", collection=collection,
                              embedder=StubEmbedder(), lexical_conn=lexical)
        assert "CVE-2014-0160" in r.search("CVE-2014-0160", 10)

    def test_hybrid_respects_the_requested_depth(self, lexical):
        collection = StubCollection([f"noise{i}" for i in range(100)])
        r = R.build_retriever("hybrid", collection=collection,
                              embedder=StubEmbedder(), lexical_conn=lexical)
        assert len(r.search("openssl heartbeat", 5)) == 5

    def test_latency_is_recorded_per_query(self, lexical):
        r = R.build_retriever("bm25", lexical_conn=lexical)
        r.search("openssl", 5)
        r.search("log4j", 5)
        assert r.stats()["end_to_end"]["queries"] == 2

    def test_hybrid_reports_both_arms_separately(self, lexical):
        collection = StubCollection(["a", "b"])
        r = R.build_retriever("hybrid", collection=collection,
                              embedder=StubEmbedder(), lexical_conn=lexical)
        r.search("openssl", 5)
        stats = r.stats()
        assert stats["dense_arm"]["queries"] == 1
        assert stats["lexical_arm"]["queries"] == 1
        assert stats["rrf_k"] == R.RRF_K


class TestRerankOrdering:
    """Reranking is exercised with a stub scorer; the model itself is not under test."""

    class StubHybridRerank(R.HybridRerankRetriever):
        def __init__(self, collection, embedder, conn, scores):
            # Skip the parent __init__ so no cross-encoder is downloaded.
            R.HybridRetriever.__init__(self, collection, embedder, conn)
            self.rerank_depth = 3
            self.model_name = "stub"
            self.rerank_latency = R.LatencyRecorder()
            self.cross_encoder = self._Scorer(scores)

        class _Scorer:
            def __init__(self, scores):
                self.scores = scores

            def predict(self, pairs, **kwargs):
                return [self.scores.get(doc, 0.0) for _, doc in pairs]

    def _build(self, scores):
        documents = {f"d{i}": f"text{i}" for i in range(6)}
        collection = StubCollection([f"d{i}" for i in range(6)], documents)
        conn = None
        r = self.StubHybridRerank(collection, StubEmbedder(), conn, scores)
        # No lexical arm in this fixture; the dense arm alone defines the order.
        r._arms = lambda query: [[f"d{i}" for i in range(6)]]
        return r

    def test_head_is_reordered_by_the_cross_encoder(self):
        r = self._build({"text2": 9.0, "text0": 1.0, "text1": 0.5})
        assert r.search("q", 6)[:3] == ["d2", "d0", "d1"]

    def test_tail_below_the_rerank_depth_keeps_its_fused_order(self):
        r = self._build({"text2": 9.0, "text0": 1.0, "text1": 0.5})
        assert r.search("q", 6)[3:] == ["d3", "d4", "d5"]

    def test_reranking_cannot_change_the_candidate_set(self):
        """Same documents in, same documents out - only the order may differ."""
        r = self._build({"text2": 9.0})
        assert sorted(r.search("q", 6)) == [f"d{i}" for i in range(6)]

    def test_an_indifferent_scorer_degrades_to_plain_hybrid(self):
        r = self._build({})
        assert r.search("q", 6) == [f"d{i}" for i in range(6)]

    def test_rerank_latency_is_tracked_separately(self):
        r = self._build({"text0": 1.0})
        r.search("q", 6)
        stats = r.stats()
        assert stats["rerank"]["queries"] == 1
        assert stats["rerank_depth"] == 3


class TestDirectIdRouting:
    """Query routing: exact CVE IDs are fetched by key, not ranked."""

    def _router(self, lexical, inner_ranking=None, filters=None):
        collection = StubCollection(inner_ranking or ["noise1", "noise2", "noise3"])
        return R.build_retriever("dense", collection=collection,
                                 embedder=StubEmbedder(), lexical_conn=lexical,
                                 filters=filters, direct_id=True)

    def test_pattern_matches_both_id_generations(self):
        """Four digits pre-2014, variable length after."""
        assert R.CVE_ID_PATTERN.findall("CVE-2014-0160 and CVE-2021-44228") == \
            ["CVE-2014-0160", "CVE-2021-44228"]

    def test_pattern_rejects_short_and_malformed(self):
        for text in ("CVE-2021-123", "CVE-21-44228", "CVE_2021_44228", "notacve"):
            assert R.CVE_ID_PATTERN.findall(text) == []

    def test_exact_id_is_promoted_to_rank_one(self, lexical):
        assert self._router(lexical).search("CVE-2014-0160", 5)[0] == "CVE-2014-0160"

    def test_routing_is_case_insensitive(self, lexical):
        assert self._router(lexical).search("cve-2014-0160", 5)[0] == "CVE-2014-0160"

    def test_id_embedded_in_a_longer_question_still_routes(self, lexical):
        hits = self._router(lexical).search("what mitigates CVE-2014-0160 today?", 5)
        assert hits[0] == "CVE-2014-0160"

    def test_context_is_still_retrieved_alongside_the_routed_hit(self, lexical):
        """Routing prepends; it does not replace the ranked results."""
        hits = self._router(lexical).search("CVE-2014-0160", 5)
        assert hits[1:] == ["noise1", "noise2", "noise3"]

    def test_multiple_ids_are_all_promoted_in_order(self, lexical):
        hits = self._router(lexical).search("compare CVE-2021-44228 with CVE-2014-0160", 5)
        assert hits[:2] == ["CVE-2021-44228", "CVE-2014-0160"]

    def test_a_routed_id_is_not_duplicated_in_the_tail(self, lexical):
        router = self._router(lexical, inner_ranking=["CVE-2014-0160", "noise1"])
        hits = router.search("CVE-2014-0160", 5)
        assert hits.count("CVE-2014-0160") == 1
        assert hits == ["CVE-2014-0160", "noise1"]

    def test_well_formed_but_absent_id_falls_through(self, lexical):
        """A withdrawn or invented ID must not fabricate a result."""
        hits = self._router(lexical).search("CVE-1999-99999", 5)
        assert hits == ["noise1", "noise2", "noise3"]

    def test_query_without_an_id_is_untouched(self, lexical):
        assert self._router(lexical).search("heartbeat disclosure", 3) == \
            ["noise1", "noise2", "noise3"]

    def test_depth_is_respected_after_promotion(self, lexical):
        assert len(self._router(lexical).search("CVE-2014-0160", 2)) == 2

    def test_routing_respects_the_active_filter(self, lexical):
        """
        The record is relevant to the query but outside what the caller asked
        for. Routing must not become a way around the filter.
        """
        router = self._router(lexical, filters={"severity": "CRITICAL"})
        assert "CVE-2014-0160" not in router.search("CVE-2014-0160", 5)

    def test_routing_promotes_a_record_that_passes_the_filter(self, lexical):
        router = self._router(lexical, filters={"severity": "CRITICAL"})
        assert router.search("CVE-2021-44228", 5)[0] == "CVE-2021-44228"

    def test_stats_report_how_often_routing_fired(self, lexical):
        router = self._router(lexical)
        router.search("CVE-2014-0160", 5)
        router.search("no identifier here", 5)
        stats = router.stats()
        assert stats["queries_seen"] == 2
        assert stats["queries_routed"] == 1
        assert stats["routed_share"] == 0.5

    def test_name_marks_routing_separately_from_the_ranking(self, lexical):
        assert self._router(lexical).name == "dense+direct_id"

    def test_routing_needs_the_lexical_index(self):
        with pytest.raises(R.RetrievalError, match="keyed lookup"):
            R.build_retriever("dense", collection=StubCollection([]),
                              embedder=StubEmbedder(), direct_id=True)


class TestRegistry:
    def test_every_mode_is_constructible_or_explains_itself(self):
        assert R.MODES == ("dense", "bm25", "hybrid", "hybrid_rerank")

    def test_unknown_mode(self):
        with pytest.raises(ValueError, match="unknown retrieval mode"):
            R.build_retriever("magic")

    def test_missing_lexical_index_names_the_fix(self):
        with pytest.raises(R.RetrievalError, match="build_fts"):
            R.build_retriever("bm25")

    def test_missing_embedder(self):
        with pytest.raises(R.RetrievalError, match="collection and an embedder"):
            R.build_retriever("dense", collection=StubCollection([]))
