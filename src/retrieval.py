"""
Retrieval backends: dense, lexical, and their fusions.

Four configurations, all returning document IDs in rank order so they are
interchangeable wherever ranked retrieval is needed:

  dense           cosine similarity over all-MiniLM-L6-v2 embeddings (ChromaDB)
  bm25            BM25 over the SQLite FTS5 index (src/lexical_index.py)
  hybrid          reciprocal rank fusion of the two arms above
  hybrid_rerank   hybrid, with a cross-encoder re-scoring the fused head

The two arms fail in opposite directions, which is the reason to fuse them.
Dense retrieval understands "remote code execution in a logging library" and is
blind to "CVE-2021-44228", because a 384-dimensional vector of an identifier is
nearly indistinguishable from a vector of any other identifier. BM25 is the
mirror image: it matches the identifier exactly and has no notion that "logging
library" and "Log4j" are related.

Fusion is done on *ranks*, not scores. Cosine distance and BM25 live on
incomparable scales - one is bounded in [0, 2], the other is unbounded and
depends on corpus statistics - so any attempt to combine the raw numbers
requires a normalization that is itself a tuned parameter. Rank fusion sidesteps
that: it only asks where each arm placed a document, not how confident it was.
The cost is that it discards confidence entirely, including the case where one
arm is certain and the other is guessing. See RRF_K below.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict

import filters as filters_mod
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

# ── Fusion parameters ────────────────────────────────────────────────────────
# Reciprocal rank fusion: score(d) = sum over arms of 1 / (k + rank_of_d_in_arm).
#
# k = 60 is the value from Cormack et al. (2009), where it was chosen by
# experiment and has since become the field default. It sets how far agreement
# between arms outweighs one arm's strong opinion. Concretely, with two arms, a
# document both arms rank at position r beats a document one arm alone ranks
# first whenever 2/(60+r) > 1/61, that is for every r up to 61. Agreement
# dominates over most of the retrieved depth. Smaller k narrows that window and
# lets each arm's head dominate; larger k widens it.
#
# The consequence that matters here: two documents that each appear at rank r in
# exactly one arm receive *identical* scores. When the arms return disjoint
# candidates - which is nearly always true for identifier queries, where dense
# retrieval finds the target 0.5% of the time - every rank produces a two-way
# tie, and the tie-break, not the formula, decides the ranking. See
# TIE_BREAK_ARM.
RRF_K = 60

# Which arm wins a score tie, as an index into the rankings passed to
# reciprocal_rank_fusion. Ties are then broken by document ID so the order is
# always deterministic.
#
# This is an arm weighting and is labelled as one. It was measured, not assumed:
# experiments/rrf_ties.py, run on a dev sample disjoint from the pinned
# evaluation sample, found that on bare CVE IDs 100% of targets land in a tie
# (mean group size 2.0), that the best Recall@1 any tie-break could reach is
# 0.985, and that the three candidate policies score:
#
#     document ID (arbitrary)   0.720
#     prefer the lexical arm    0.985   <- ceiling
#     prefer the dense arm      0.000
#
# On product + version queries only 36% of targets are tied at all and the same
# three policies score 0.121 / 0.126 / 0.095 against a ceiling of 0.126, so the
# choice is worth 26 points where the arms disagree completely and half a point
# where they do not. Breaking on document ID is not the neutral option - it is a
# coin flip that discards a quarter of the lexical arm's accuracy.
LEXICAL_ARM = 1
TIE_BREAK_ARM = LEXICAL_ARM

# Candidates pulled from each arm before fusion. Deeper costs little (both arms
# are index lookups) and gives fusion a chance to find agreement outside each
# arm's top few, which is where RRF earns its keep.
ARM_DEPTH = 200

# How far down the fused list the cross-encoder re-scores. Reranking is the
# expensive step - a full transformer forward pass per (query, document) pair,
# against a single vector lookup for the arms - so it is spent only where a
# reordering can still change Recall@1 and Recall@10.
RERANK_DEPTH = 50

# Cross-encoder for reranking. Unlike the bi-encoder used for the dense arm,
# which embeds query and document separately, a cross-encoder reads both at once
# and can model their interaction. It is far more accurate and far too slow to
# run over a corpus, which is exactly why it goes last over a short list.
CROSS_ENCODER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# The cross-encoder truncates at its positional limit; CVE documents run to a
# little over a thousand characters, so most fit and the longest lose their tail.
CROSS_ENCODER_MAX_LENGTH = 512
CROSS_ENCODER_BATCH_SIZE = 32


class RetrievalError(RuntimeError):
    """Raised when a backend cannot be constructed or run."""


# ── Latency ──────────────────────────────────────────────────────────────────
def percentile(values: Sequence[float], pct: float) -> float:
    """
    Nearest-rank percentile: the smallest observed value at or above `pct` of
    the distribution. No interpolation, so every number reported is a latency
    that was actually measured rather than an average of two that were.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = math.ceil((pct / 100.0) * len(ordered)) - 1
    return ordered[max(0, min(len(ordered) - 1, idx))]


class LatencyRecorder:
    """Per-query wall-clock timings.

    Retrieval quality is only half of a retrieval change: a configuration that
    adds two points of Recall@1 for ten times the latency is a different
    engineering decision than one that adds them for free. Percentiles rather
    than a mean because the tail is what a user notices.
    """

    def __init__(self) -> None:
        self.samples_ms: List[float] = []

    def record(self, elapsed_ms: float) -> None:
        self.samples_ms.append(elapsed_ms)

    def summary(self) -> Dict[str, float]:
        return {
            "queries": len(self.samples_ms),
            "mean_ms": round(sum(self.samples_ms) / len(self.samples_ms), 2)
            if self.samples_ms else 0.0,
            "p50_ms": round(percentile(self.samples_ms, 50), 2),
            "p95_ms": round(percentile(self.samples_ms, 95), 2),
        }


# ── Fusion ───────────────────────────────────────────────────────────────────
def reciprocal_rank_fusion(
    rankings: Sequence[Sequence[str]],
    k: int = RRF_K,
    tie_break_arm: Optional[int] = None,
) -> List[Tuple[str, float]]:
    """
    Fuse several ranked ID lists into one, best first.

    score(d) = sum over arms of 1 / (k + rank of d in that arm), with ranks
    1-based and arms that did not return d contributing nothing.

    Args:
        rankings: One ranked list of document IDs per arm.
        k: The RRF constant. See RRF_K.
        tie_break_arm: Index into `rankings`. Documents with equal scores are
            ordered by their rank in that arm, unranked last. None falls back to
            document ID alone, which is deterministic but arbitrary - see
            TIE_BREAK_ARM for what that costs.

    Returns:
        (document_id, score) pairs, best first. Document ID is always the final
        tie-break, so the order never depends on dict or input ordering.
    """
    scores: Dict[str, float] = defaultdict(float)
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] += 1.0 / (k + rank)

    if tie_break_arm is None or not (0 <= tie_break_arm < len(rankings)):
        return sorted(scores.items(), key=lambda item: (-item[1], item[0]))

    preferred = {doc: rank for rank, doc in enumerate(rankings[tie_break_arm])}
    unranked = len(rankings[tie_break_arm])
    return sorted(
        scores.items(),
        key=lambda item: (-item[1], preferred.get(item[0], unranked), item[0]),
    )


# ── Backends ─────────────────────────────────────────────────────────────────
class Retriever(Protocol):
    """A ranked-ID search over the CVE corpus."""

    name: str
    description: str

    def search(self, query: str, depth: int) -> List[str]:
        """Return up to `depth` document IDs, best first."""

    def stats(self) -> Dict[str, Any]:
        """Latency and configuration accumulated over the queries served."""


class BaseRetriever:
    """Timing and reporting shared by every backend.

    Subclasses implement `_search`; `search` wraps it so that every backend is
    measured the same way and none can forget to.
    """

    name = ""
    description = ""

    def __init__(self) -> None:
        self.latency = LatencyRecorder()

    def search(self, query: str, depth: int) -> List[str]:
        start = time.perf_counter()
        try:
            return self._search(query, depth)
        finally:
            self.latency.record((time.perf_counter() - start) * 1000.0)

    def _search(self, query: str, depth: int) -> List[str]:
        raise NotImplementedError

    def stats(self) -> Dict[str, Any]:
        """Latency and configuration, for the results file."""
        return {"end_to_end": self.latency.summary()}


class _DenseArm:
    """The Chroma side of retrieval, with filtering applied before ranking.

    Filters reach Chroma two ways because Chroma can only express one of them.
    Scalar fields become a `where` clause; the packed-list fields (vendor,
    product, cwe) have no representable operator and arrive as an explicit ID
    allow-list resolved from the lexical index. Both are pre-filters - Chroma
    applies them while selecting neighbours, so `depth` results means `depth`
    matching results, not however many survive a trim.
    """

    def __init__(self, collection, embedder, filters=None, allowlist=None) -> None:
        self.collection = collection
        self.embedder = embedder
        self.filters = filters or {}
        self.allowlist = allowlist
        self.where = filters_mod.to_chroma_where(self.filters)

    def rank(self, query: str, depth: int) -> List[str]:
        if self.allowlist is not None and not self.allowlist:
            return []
        kwargs: Dict[str, Any] = {
            "query_embeddings": [self.embedder.get_embedding(query)],
            "n_results": depth,
        }
        if self.where is not None:
            kwargs["where"] = self.where
        if self.allowlist is not None:
            kwargs["ids"] = self.allowlist
        return self.collection.query(**kwargs)["ids"][0]


class DenseRetriever(BaseRetriever):
    """Cosine similarity over sentence-transformer embeddings (the baseline)."""

    name = "dense"
    description = "dense-only (cosine over all-MiniLM-L6-v2)"

    def __init__(self, collection, embedder, filters=None, allowlist=None) -> None:
        super().__init__()
        self.filters = filters_mod.validate(filters)
        self.arm = _DenseArm(collection, embedder, self.filters, allowlist)
        self.collection = collection
        self.embedder = embedder

    def _search(self, query: str, depth: int) -> List[str]:
        if filters_mod.matches_nothing(self.filters):
            return []
        return self.arm.rank(query, depth)

    def stats(self) -> Dict[str, Any]:
        return {"end_to_end": self.latency.summary(),
                "filters": filters_mod.describe(self.filters)}


class BM25Retriever(BaseRetriever):
    """BM25 over the FTS5 index."""

    name = "bm25"
    description = "lexical-only (BM25 over SQLite FTS5)"

    def __init__(self, conn, filters=None) -> None:
        super().__init__()
        self.conn = conn
        self.filters = filters_mod.validate(filters)

    def _search(self, query: str, depth: int) -> List[str]:
        # lexical_index.search escapes the query and returns (id, score) with
        # larger-is-better; only the order is needed here. Filtering is a join
        # predicate inside that call, so it too is a pre-filter.
        import lexical_index as LX

        if filters_mod.matches_nothing(self.filters):
            return []
        return [
            doc_id for doc_id, _ in
            LX.search(self.conn, query, depth, filters=self.filters or None)
        ]

    def stats(self) -> Dict[str, Any]:
        return {"end_to_end": self.latency.summary(),
                "filters": filters_mod.describe(self.filters)}


class HybridRetriever(BaseRetriever):
    """Reciprocal rank fusion of the dense and lexical arms."""

    name = "hybrid"
    description = (
        f"RRF(dense, bm25), k={RRF_K}, top {ARM_DEPTH} per arm, ties to lexical"
    )

    def __init__(
        self,
        collection,
        embedder,
        conn,
        arm_depth: int = ARM_DEPTH,
        rrf_k: int = RRF_K,
        tie_break_arm: Optional[int] = TIE_BREAK_ARM,
        filters: Optional[Dict[str, Any]] = None,
        allowlist: Optional[List[str]] = None,
    ) -> None:
        super().__init__()
        self.collection = collection
        self.embedder = embedder
        self.conn = conn
        self.arm_depth = arm_depth
        self.rrf_k = rrf_k
        self.tie_break_arm = tie_break_arm
        self.filters = filters_mod.validate(filters)
        # Both arms get the same spec. Fusing a filtered arm with an unfiltered
        # one would rank a candidate set that neither arm endorses, and the
        # out-of-filter records would arrive with real-looking scores.
        self.dense_arm = _DenseArm(collection, embedder, self.filters, allowlist)
        self.dense_latency = LatencyRecorder()
        self.lexical_latency = LatencyRecorder()

    def _fuse(self, arms: List[List[str]]) -> List[str]:
        """Rank the fused candidates, best first."""
        return [
            doc_id for doc_id, _ in reciprocal_rank_fusion(
                arms, k=self.rrf_k, tie_break_arm=self.tie_break_arm
            )
        ]

    def _arms(self, query: str) -> List[List[str]]:
        """Run both arms at ARM_DEPTH and return their ranked ID lists.

        Order matters: index 0 is dense, index 1 is lexical, and TIE_BREAK_ARM
        indexes into this list.
        """
        import lexical_index as LX

        start = time.perf_counter()
        dense = self.dense_arm.rank(query, self.arm_depth)
        self.dense_latency.record((time.perf_counter() - start) * 1000.0)

        start = time.perf_counter()
        lexical = [
            doc_id for doc_id, _ in
            LX.search(self.conn, query, self.arm_depth, filters=self.filters or None)
        ]
        self.lexical_latency.record((time.perf_counter() - start) * 1000.0)

        return [dense, lexical]

    def _search(self, query: str, depth: int) -> List[str]:
        if filters_mod.matches_nothing(self.filters):
            return []
        return self._fuse(self._arms(query))[:depth]

    def stats(self) -> Dict[str, Any]:
        return {
            "end_to_end": self.latency.summary(),
            "dense_arm": self.dense_latency.summary(),
            "lexical_arm": self.lexical_latency.summary(),
            "rrf_k": self.rrf_k,
            "arm_depth": self.arm_depth,
            "tie_break_arm": (
                "lexical" if self.tie_break_arm == LEXICAL_ARM
                else "document_id" if self.tie_break_arm is None
                else f"arm[{self.tie_break_arm}]"
            ),
            "filters": filters_mod.describe(self.filters),
        }


class HybridRerankRetriever(HybridRetriever):
    """Hybrid, with a cross-encoder re-scoring the fused head.

    Only the top RERANK_DEPTH of the fused list is re-scored; everything below
    keeps its fused order and is appended unchanged. Reranking therefore cannot
    change how often the target is found within the search depth at all - it can
    only move it up or down inside the head. Any change in found-in-top-N between
    hybrid and hybrid_rerank would mean a bug, which makes that column a free
    consistency check on this backend.
    """

    name = "hybrid_rerank"
    description = (
        f"RRF(dense, bm25) k={RRF_K}, ties to lexical + cross-encoder rerank "
        f"of top {RERANK_DEPTH}"
    )

    def __init__(
        self,
        collection,
        embedder,
        conn,
        arm_depth: int = ARM_DEPTH,
        rrf_k: int = RRF_K,
        tie_break_arm: Optional[int] = TIE_BREAK_ARM,
        filters: Optional[Dict[str, Any]] = None,
        allowlist: Optional[List[str]] = None,
        rerank_depth: int = RERANK_DEPTH,
        model_name: str = CROSS_ENCODER_MODEL,
    ) -> None:
        super().__init__(collection, embedder, conn, arm_depth=arm_depth,
                         rrf_k=rrf_k, tie_break_arm=tie_break_arm,
                         filters=filters, allowlist=allowlist)
        self.rerank_depth = rerank_depth
        self.model_name = model_name
        self.rerank_latency = LatencyRecorder()
        try:
            from sentence_transformers import CrossEncoder
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise RetrievalError(
                "hybrid_rerank needs sentence-transformers: pip install -r requirements.txt"
            ) from exc
        self.cross_encoder = CrossEncoder(
            model_name, max_length=CROSS_ENCODER_MAX_LENGTH
        )

    def _documents(self, ids: Sequence[str]) -> Dict[str, str]:
        """Fetch document text for the candidates, keyed by ID.

        Read from ChromaDB rather than the FTS table: `cve_id` is UNINDEXED
        there, so a lookup by ID would scan every row. The two stores hold
        byte-identical text (checked by src/build_fts.py), so the choice is
        purely about which one can answer a key lookup.
        """
        if not ids:
            return {}
        got = self.collection.get(ids=list(ids), include=["documents"])
        return dict(zip(got["ids"], got["documents"]))

    def _rerank(self, query: str, ids: Sequence[str]) -> List[str]:
        """Re-score candidates with the cross-encoder, best first."""
        if not ids:
            return []
        start = time.perf_counter()
        documents = self._documents(ids)
        pairs = [(query, documents.get(doc_id, "")) for doc_id in ids]
        scores = self.cross_encoder.predict(
            pairs, batch_size=CROSS_ENCODER_BATCH_SIZE, show_progress_bar=False
        )
        # Ties fall back to the fused position, so an indifferent cross-encoder
        # degrades to plain hybrid rather than to an arbitrary shuffle.
        order = sorted(range(len(ids)), key=lambda i: (-float(scores[i]), i))
        self.rerank_latency.record((time.perf_counter() - start) * 1000.0)
        return [ids[i] for i in order]

    def _search(self, query: str, depth: int) -> List[str]:
        fused = self._fuse(self._arms(query))
        head = fused[: self.rerank_depth]
        tail = fused[self.rerank_depth : depth]
        return (self._rerank(query, head) + tail)[:depth]

    def stats(self) -> Dict[str, Any]:
        base = super().stats()
        base["rerank"] = self.rerank_latency.summary()
        base["rerank_depth"] = self.rerank_depth
        base["cross_encoder"] = self.model_name
        return base


# ── Registry ─────────────────────────────────────────────────────────────────
MODES = ("dense", "bm25", "hybrid", "hybrid_rerank")


def build_retriever(
    mode: str,
    collection=None,
    embedder=None,
    lexical_conn=None,
    filters: Optional[Dict[str, Any]] = None,
) -> Retriever:
    """
    Construct a retrieval backend by name.

    Args:
        mode: One of MODES.
        collection: An open ChromaDB collection (dense, hybrid, hybrid_rerank).
        embedder: An EmbeddingService (dense, hybrid, hybrid_rerank).
        lexical_conn: An open FTS index connection. Also required by `dense`
            when the filter names a packed-list field, since only the lexical
            index can resolve those into IDs.
        filters: A metadata pre-filter spec. See src/filters.py.

    Raises:
        RetrievalError: A dependency the mode needs was not supplied.
        FilterError: The filter spec is malformed.
        ValueError: Unknown mode.
    """
    filters = filters_mod.validate(filters)
    needs_dense = mode in ("dense", "hybrid", "hybrid_rerank")
    needs_lexical = mode in ("bm25", "hybrid", "hybrid_rerank")
    if needs_dense and (collection is None or embedder is None):
        raise RetrievalError(f"retrieval mode '{mode}' needs a collection and an embedder")
    if needs_lexical and lexical_conn is None:
        raise RetrievalError(
            f"retrieval mode '{mode}' needs the lexical index. "
            "Build it with: python src/build_fts.py"
        )

    # Resolved once here, not per query: the spec is fixed for the retriever's
    # life and the underlying scan is the expensive part of filtering.
    allowlist = None
    if needs_dense and filters_mod.list_filter_subset(filters):
        if lexical_conn is None:
            raise RetrievalError(
                f"filtering on {', '.join(filters_mod.list_filter_subset(filters))} "
                "needs the lexical index even in dense mode: Chroma has no "
                "operator for the packed-list fields."
            )
        allowlist = filters_mod.resolve_allowlist(lexical_conn, filters)

    if mode == "dense":
        return DenseRetriever(collection, embedder, filters=filters, allowlist=allowlist)
    if mode == "bm25":
        return BM25Retriever(lexical_conn, filters=filters)
    if mode == "hybrid":
        return HybridRetriever(collection, embedder, lexical_conn,
                               filters=filters, allowlist=allowlist)
    if mode == "hybrid_rerank":
        return HybridRerankRetriever(collection, embedder, lexical_conn,
                                     filters=filters, allowlist=allowlist)
    raise ValueError(f"unknown retrieval mode: {mode!r}")
