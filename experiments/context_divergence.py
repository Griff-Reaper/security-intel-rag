"""
How often do two retrieval configurations hand the generator a different prompt?

This is the input the answer-quality comparison is sized on, so it is measured
directly rather than inferred. experiments/power.py originally took its
discordance rate from `ranks_by_cve`, which records only whether the *target*
CVE landed inside the top five. That is a weaker statement than it looks: two
configs can agree that the target is at rank 2 and still differ on the other
four documents, and the generator reads all five.

If the document sets diverge much more often than the target indicator does,
the power calculation was optimistic and the planned comparison is smaller than
it appears. If they diverge at about the same rate, the sizing stands.

Either way the per-question flag written here is what makes the conditional
analysis possible afterwards: on the questions where both configs produced an
identical prompt, any difference in grade is generator sampling noise, and
separating those out turns one blunt comparison into a mechanism and a bound.

    python experiments/context_divergence.py

Writes experiments/results/context_divergence.json, committed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import chromadb
from chromadb.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import lexical_index as LX  # noqa: E402
import provenance  # noqa: E402
import retrieval as retrieval_mod  # noqa: E402
from embeddings import EmbeddingService  # noqa: E402

EVAL_PATH = PROJECT_ROOT / "experiments" / "samples" / "paraphrased_eval.json"
OUT_PATH = PROJECT_ROOT / "experiments" / "results" / "context_divergence.json"
LEXICAL_DB = PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"

# Must match answer_quality.N_RETRIEVED. The whole question is what the
# generator was shown, so measuring at any other depth answers a different one.
DEPTH = 5
MODES = ("hybrid_rerank", "bm25")


def retrieved_ids(retriever, question: str, depth: int) -> List[str]:
    return list(retriever.search(question, depth))


def main() -> None:
    provenance.require_layout_match()

    items = json.loads(EVAL_PATH.read_text(encoding="utf-8"))["items"]
    client = chromadb.PersistentClient(
        path=str(PROJECT_ROOT / "chroma_db"),
        settings=Settings(anonymized_telemetry=False),
    )
    collection = client.get_collection("nvd_cve")
    embedder = EmbeddingService()
    conn = LX.connect(LEXICAL_DB, read_only=True)

    retrievers = {
        mode: retrieval_mod.build_retriever(
            mode, collection, embedder, conn, filters=None, direct_id=True
        )
        for mode in MODES
    }

    records: List[Dict[str, Any]] = []
    for index, item in enumerate(items, 1):
        question = item["question"]
        sets = {m: retrieved_ids(retrievers[m], question, DEPTH) for m in MODES}
        a, b = set(sets[MODES[0]]), set(sets[MODES[1]])
        overlap = len(a & b)
        records.append({
            "cve_id": item["cve_id"],
            "identical_set": a == b,
            # Order matters to a language model reading a numbered list, so it
            # is tracked separately from set membership rather than folded in.
            "identical_order": sets[MODES[0]] == sets[MODES[1]],
            "overlap": overlap,
            "target_in_both": all(item["cve_id"] in sets[m] for m in MODES),
            "target_in_neither": not any(item["cve_id"] in sets[m] for m in MODES),
        })
        if index % 25 == 0:
            print(f"  {index}/{len(items)}", flush=True)

    n = len(records)
    identical_set = sum(1 for r in records if r["identical_set"])
    identical_order = sum(1 for r in records if r["identical_order"])
    target_discordant = sum(
        1 for r in records if not r["target_in_both"] and not r["target_in_neither"]
    )
    mean_overlap = sum(r["overlap"] for r in records) / n

    payload = {
        **provenance.stamp(),
        "modes": list(MODES),
        "depth": DEPTH,
        "queries": n,
        "eval_set": str(EVAL_PATH.relative_to(PROJECT_ROOT)),
        "identical_document_set": identical_set,
        "identical_document_set_rate": round(identical_set / n, 4),
        "identical_document_order": identical_order,
        "identical_document_order_rate": round(identical_order / n, 4),
        "different_document_set_rate": round(1 - identical_set / n, 4),
        "mean_overlap_of_%d" % DEPTH: round(mean_overlap, 3),
        "target_indicator_discordance": round(target_discordant / n, 4),
        "note": (
            "different_document_set_rate is the share of questions where the "
            "two configs build different prompts, and is the discordance rate "
            "an answer-quality comparison is actually exposed to. "
            "target_indicator_discordance is the weaker measure taken from "
            "ranks_by_cve, kept here so the two can be compared."
        ),
        "records": records,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print()
    print(f"{n} questions, {MODES[0]} vs {MODES[1]}, depth {DEPTH}")
    print(f"  identical document set   {identical_set:>4}/{n} "
          f"= {identical_set / n:.3f}")
    print(f"  identical set and order  {identical_order:>4}/{n} "
          f"= {identical_order / n:.3f}")
    print(f"  different prompt         {n - identical_set:>4}/{n} "
          f"= {1 - identical_set / n:.3f}   <- the real discordance rate")
    print(f"  target-indicator only    {target_discordant:>4}/{n} "
          f"= {target_discordant / n:.3f}   <- what power.py assumed")
    print(f"  mean overlap of {DEPTH}        {mean_overlap:.2f} documents")
    print()
    print(f"wrote {OUT_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
