"""
Document-layout selection experiment.

Question: how should a CVE be laid out in the text that gets embedded? Both the
ordering (description first vs. metadata first) and the caps on how many
vendor/product names are included are free choices, and both measurably change
retrieval.

Method. Sample N CVEs. For each, use the first sentence of its description as a
stand-in for an analyst's natural-language query, embed every sampled document
under each candidate layout, and rank the documents against each query. Report
recall@1 and MRR overall, then stratified by how many affected products the CVE
carries - which is where the layouts were expected to diverge.

    python experiments/document_layout.py

Results are written to experiments/results/document_layout.json.

IMPORTANT - what this is not. This is a design-selection experiment, not the
project's retrieval evaluation. The queries are drawn from the documents
themselves, so they share vocabulary with the text being retrieved; that makes
the task substantially easier than a real analyst query and inflates every
absolute number here. Only the *relative* comparison between layouts is
meaningful. A proper evaluation needs a committed eval set with paraphrased
questions and is a separate piece of work.
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import nvd_feeds
import nvd_normalize as N
import provenance
from embeddings import EmbeddingService

DEFAULT_YEARS = ["2016", "2019", "2021", "2024"]
DEFAULT_PER_YEAR = 300
SEED = 20260812

RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "document_layout.json"

# Product-count buckets. Most CVEs name only a handful of products; the
# interesting behaviour is in the long tail of heavily-bundled ones.
BUCKETS = [(0, 1, "0"), (1, 6, "1-5"), (6, 21, "6-20"), (21, 61, "21-60"), (61, 10**9, "61+")]


def first_sentence(text: str, limit: int = 240) -> str:
    """A crude stand-in for a natural query: the description's opening sentence."""
    cut = text.find(". ")
    return (text[: cut + 1] if 0 < cut < limit else text[:limit]).strip()


def _metadata_first(rec, vendors, products, cwes, cvss, desc, vcap, pcap) -> str:
    lines = [f"CVE ID: {rec['id']}"]
    if cvss["severity"]:
        lines.append(f"Severity: {cvss['severity']}")
    if vendors:
        lines.append(f"Affected vendors: {', '.join(vendors[:vcap])}")
    if products:
        lines.append(f"Affected products: {', '.join(products[:pcap])}")
    if cwes:
        lines.append(f"Weaknesses: {', '.join(cwes)}")
    lines += ["", f"Description: {desc}"]
    return "\n".join(lines)


def _description_first(rec, vendors, products, cwes, cvss, desc, vcap, pcap) -> str:
    lines = [f"{rec['id']}: {desc}", ""]
    if vendors:
        lines.append(f"Affected vendors: {', '.join(vendors[:vcap])}")
    if products:
        lines.append(f"Affected products: {', '.join(products[:pcap])}")
    if cwes:
        lines.append(f"Weaknesses: {', '.join(cwes)}")
    if cvss["severity"]:
        lines.append(f"Severity: {cvss['severity']}")
    return "\n".join(lines)


LAYOUTS: Dict[str, Callable] = {
    "metadata-first 12v/20p": lambda *a: _metadata_first(*a, 12, 20),
    "description-first 12v/20p": lambda *a: _description_first(*a, 12, 20),
    "description-first 6v/8p": lambda *a: _description_first(*a, 6, 8),
    "description-first 4v/5p": lambda *a: _description_first(*a, 4, 5),
    # Upper bound on semantic performance, but it strips the product and vendor
    # strings that identifier-style queries need, so it is a reference point
    # rather than a candidate.
    "description only": lambda rec, v, p, c, s, d: f"{rec['id']}: {d}",
}


def load_sample(raw_dir: Path, years: List[str], per_year: int) -> List[Dict[str, Any]]:
    rng = random.Random(SEED)
    pool = []
    for year in years:
        path = raw_dir / f"CVE-{year}.json.xz"
        if not path.exists():
            raise SystemExit(f"missing feed {path}; run: python src/nvd_feeds.py --dest {raw_dir}")
        records = [r for r in nvd_feeds.iter_records(path) if N.should_index(r)[0]]
        pool.extend(rng.sample(records, min(per_year, len(records))))
    return pool


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", default=str(PROJECT_ROOT / "data" / "raw"))
    parser.add_argument("--years", nargs="*", default=DEFAULT_YEARS)
    parser.add_argument("--per-year", type=int, default=DEFAULT_PER_YEAR)
    args = parser.parse_args()

    records = load_sample(Path(args.raw_dir), args.years, args.per_year)
    print(f"sampled {len(records)} CVEs from {args.years} (seed {SEED})\n")

    parsed = []
    for rec in records:
        _, vendors, products = N.extract_cpe_entries(rec)
        parsed.append(
            (rec, vendors, products, N.extract_cwes(rec), N.extract_cvss(rec),
             N.extract_english_description(rec))
        )

    embedder = EmbeddingService()
    queries = [first_sentence(p[5]) for p in parsed]
    query_vecs = np.array(embedder.get_embeddings(queries, show_progress=False))
    product_counts = np.array([len(p[2]) for p in parsed])
    truth = np.arange(len(parsed))

    results: Dict[str, Any] = {
        # Stamped, but deliberately *not* guarded by provenance.require_layout_match():
        # this experiment exists to compare layouts against each other, so a
        # mismatch with the shipped layout is its normal operating condition
        # rather than an error. The stamp records the layout that is currently
        # the default, which is the one the "description-first" arm represents.
        **provenance.stamp(),
        "sample_size": len(parsed),
        "years": args.years,
        "seed": SEED,
        "embedding_model": embedder.model_name,
        "caveat": (
            "Queries are the first sentence of each document's own description, so they "
            "share vocabulary with the target. Absolute numbers are inflated; only the "
            "relative comparison between layouts is meaningful."
        ),
        "layouts": {},
    }

    print(f"{'layout':<30}{'recall@1':>10}{'MRR':>8}{'mean chars':>12}")
    print("-" * 60)
    ranks_by_layout = {}
    for name, build in LAYOUTS.items():
        docs = [build(*p) for p in parsed]
        doc_vecs = np.array(embedder.get_embeddings(docs, show_progress=False))
        # Both sides are L2-normalized, so the dot product is cosine similarity.
        order = np.argsort(-(query_vecs @ doc_vecs.T), axis=1)
        ranks = np.array([np.where(order[i] == truth[i])[0][0] + 1 for i in truth])
        ranks_by_layout[name] = ranks
        results["layouts"][name] = {
            "recall_at_1": round(float((ranks == 1).mean()), 4),
            "mrr": round(float((1 / ranks).mean()), 4),
            "mean_document_chars": round(float(np.mean([len(d) for d in docs])), 1),
        }
        print(f"{name:<30}{(ranks == 1).mean():>10.3f}{(1 / ranks).mean():>8.3f}"
              f"{np.mean([len(d) for d in docs]):>12.0f}")

    baseline, chosen = "metadata-first 12v/20p", "description-first 6v/8p"
    print(f"\nrecall@1 by affected-product count ({baseline} -> {chosen})")
    print(f"{'products':<12}{'n':>6}{'baseline':>11}{'chosen':>9}{'delta':>9}")
    print("-" * 48)
    stratified = {}
    for low, high, label in BUCKETS:
        mask = (product_counts >= low) & (product_counts < high)
        if not mask.sum():
            continue
        base = float((ranks_by_layout[baseline][mask] == 1).mean())
        new = float((ranks_by_layout[chosen][mask] == 1).mean())
        stratified[label] = {"n": int(mask.sum()), "baseline_recall_at_1": round(base, 4),
                             "chosen_recall_at_1": round(new, 4), "delta": round(new - base, 4)}
        print(f"{label:<12}{mask.sum():>6}{base:>11.3f}{new:>9.3f}{new - base:>+9.3f}")

    results["stratified_by_product_count"] = {
        "baseline": baseline, "chosen": chosen, "buckets": stratified
    }
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {RESULTS_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
