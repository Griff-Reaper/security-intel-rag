"""
Does the answer follow from the retrieved documents, and does the system decline
when it cannot know?

Retrieval quality is measured elsewhere. This measures what a user actually
receives: whether the generated answer is supported by the context it was given,
whether the CVE IDs it names are real, and whether a question the corpus cannot
answer produces an admission rather than an invention.

    python experiments/answer_quality.py --build      # build the unanswerable set
    python experiments/answer_quality.py --run        # generate + judge (resumable)
    python experiments/answer_quality.py --report     # summarize what exists

Writes experiments/samples/unanswerable_questions.json and
experiments/results/answer_quality.json, both committed.

Three measurements, deliberately of different kinds:

1. Citation validity - deterministic. Every CVE ID appearing in the answer text
   is checked against the IDs actually retrieved. This needs no judge and cannot
   be argued with: an ID in the answer that was not in the context was invented,
   whatever the prose around it claims.

2. Groundedness - judged. Whether each claim follows from the context is not
   mechanically checkable, so a model judges it. That makes the judge part of
   the instrument, which is why it is calibrated (below) rather than trusted.

3. Abstention - judged, on questions built to be unanswerable. Two kinds:
   products that do not exist in the corpus (verified by search, not assumed),
   and questions about real CVEs whose answers NVD records do not contain, such
   as attribution or patch procedure.

**Judge calibration.** A judge that approves everything scores a perfect system
and is worthless. So a set of deliberately corrupted answers - real answers with
a fabricated CVE ID, an invented CVSS score, or an unsupported claim spliced in -
is judged alongside the real ones. The rate at which the judge catches those is
reported next to the groundedness figure, and the groundedness figure means
nothing without it.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import chromadb
from chromadb.config import Settings
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "config"))

import claude_client  # noqa: E402
import lexical_index as LX  # noqa: E402
import provenance  # noqa: E402

EVAL_PATH = PROJECT_ROOT / "experiments" / "samples" / "paraphrased_eval.json"
UNANSWERABLE_PATH = PROJECT_ROOT / "experiments" / "samples" / "unanswerable_questions.json"
RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "answer_quality.json"
LEXICAL_DB = PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"

SEED = 20260813
N_ANSWERABLE = 40
N_RETRIEVED = 5
JUDGE_MAX_TOKENS = 700
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Invented vendor/product names. Verified against the index before use - a name
# that turns out to exist would make the question answerable and the measurement
# meaningless.
FABRICATED = [
    ("Zyphergate", "Mailhub"), ("Nordvale", "EdgeProxy"), ("Kestrelix", "VaultSync"),
    ("Obsidianware", "FleetPilot"), ("Tarnhelm", "SecureBridge"), ("Vellichor", "DataForge"),
    ("Quillfeather", "AuthGate"), ("Marrowstone", "NetPulse"), ("Ashgrove", "CipherDesk"),
    ("Halcyonix", "StreamGuard"), ("Brackenfell", "LogVault"), ("Duskwind", "APIShield"),
]
FABRICATED_TEMPLATES = [
    "What is the remote code execution vulnerability in {vendor} {product} 4.2?",
    "Which versions of {vendor} {product} are affected by the authentication bypass?",
    "How severe is the SQL injection in {vendor}'s {product} platform?",
]

# Questions about *real* CVEs whose answers an NVD record does not contain.
OUT_OF_SCOPE_TEMPLATES = [
    "Which threat actor group has been observed exploiting {cve} in the wild?",
    "What are the exact vendor patch steps to remediate {cve}?",
    "Is there public exploit code available for {cve}, and where is it hosted?",
    "How many organisations were breached through {cve}?",
    "What did the vendor's incident post-mortem for {cve} conclude?",
]

JUDGE_PROMPT = """You are grading a security assistant's answer for faithfulness.

You are given the CONTEXT the assistant was shown and the ANSWER it produced.

Judge only whether the answer is supported by the context. Do not judge whether \
the answer is well written, and do not use your own knowledge of the subject - \
a claim that is true in the world but absent from the context is UNSUPPORTED.

Grade:
- "grounded": every factual claim follows from the context.
- "unsupported": at least one factual claim is absent from or contradicts the context.
- "abstained": the answer declines to answer, or states the context does not \
contain the information, without asserting substantive facts of its own.

CONTEXT:
{context}

ANSWER:
{answer}

Respond with only a JSON object:
{{"grade": "grounded" | "unsupported" | "abstained", "reason": "one short sentence"}}"""

# How a real answer is corrupted to calibrate the judge. Each introduces a claim
# the context cannot support, of a kind the system could plausibly produce.
CORRUPTIONS = (
    ("fabricated_cve",
     "\n\nThis issue is closely related to CVE-2019-88888, which affects the same component."),
    ("invented_score",
     "\n\nThe CVSS v3.1 base score for this vulnerability is 9.9 (CRITICAL)."),
    ("unsupported_claim",
     "\n\nThis vulnerability is being actively exploited by the Lazarus Group in "
     "ransomware campaigns against healthcare providers."),
)


def build_unanswerable(conn, collection) -> Dict[str, Any]:
    """
    Construct and verify the unanswerable question set.

    Fabricated names are checked against the lexical index: any that actually
    match a record are discarded, because a question with a real answer would be
    scored as a hallucination when the system answers it correctly.
    """
    rng = random.Random(SEED)
    items: List[Dict[str, Any]] = []

    rejected = []
    for vendor, product in FABRICATED:
        hits = LX.search(conn, f"{vendor} {product}", 5)
        if hits:
            rejected.append(f"{vendor} {product}")
            continue
        template = FABRICATED_TEMPLATES[len(items) % len(FABRICATED_TEMPLATES)]
        items.append({
            "id": f"fabricated-{len(items):02d}",
            "kind": "fabricated_product",
            "question": template.format(vendor=vendor, product=product),
            "why_unanswerable": "vendor and product do not appear in the corpus "
                                "(verified: zero lexical matches)",
        })

    real_ids = collection.get(include=[], limit=5000)["ids"]
    for index, template in enumerate(OUT_OF_SCOPE_TEMPLATES * 2):
        cve_id = rng.choice(real_ids)
        items.append({
            "id": f"out-of-scope-{index:02d}",
            "kind": "out_of_scope",
            "question": template.format(cve=cve_id),
            "why_unanswerable": "NVD records do not carry attribution, patch "
                                "procedure, exploit availability or breach counts",
        })

    payload = {
        **provenance.stamp(),
        "purpose": "questions the corpus cannot answer; the system should decline",
        "verification": "fabricated names searched against the lexical index; "
                        "any with matches were discarded",
        "discarded_names": rejected,
        "items": items,
    }
    UNANSWERABLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    UNANSWERABLE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def cited_ids(text: str) -> List[str]:
    return sorted({m.upper() for m in CVE_PATTERN.findall(text or "")})


def judge(client, model: str, context: str, answer: str) -> Optional[Dict[str, Any]]:
    """Grade one answer against its context, or None if the judge gave nothing usable."""
    for attempt in range(3):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=JUDGE_MAX_TOKENS,
                messages=[{"role": "user", "content": JUDGE_PROMPT.format(
                    context=context[:20000], answer=answer[:8000])}],
            )
        except Exception:  # noqa: BLE001
            time.sleep(1.5 * (attempt + 1))
            continue
        if response.stop_reason == "refusal":
            return None
        text = next((b.text for b in response.content if b.type == "text"), "")
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if parsed.get("grade") in ("grounded", "unsupported", "abstained"):
                    return parsed
            except json.JSONDecodeError:
                pass
    return None


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate one group of graded answers."""
    graded = [r for r in records if r.get("grade")]
    n = max(len(graded), 1)
    counts: Dict[str, int] = {}
    for r in graded:
        counts[r["grade"]] = counts.get(r["grade"], 0) + 1
    with_citations = [r for r in records if r.get("cited_ids")]
    invalid = [r for r in records if r.get("invalid_citations")]
    return {
        "answers": len(records),
        "graded": len(graded),
        "grades": counts,
        "grounded_rate": round(counts.get("grounded", 0) / n, 4),
        "unsupported_rate": round(counts.get("unsupported", 0) / n, 4),
        "abstained_rate": round(counts.get("abstained", 0) / n, 4),
        "answers_citing_a_cve": len(with_citations),
        "answers_with_an_invented_cve": len(invalid),
        "citation_validity": round(
            1 - len(invalid) / max(len(with_citations), 1), 4
        ),
    }


def load_state() -> Dict[str, Any]:
    """Existing graded answers, so a run can resume without re-paying for them."""
    if not RESULTS_PATH.exists():
        return {"answerable": {}, "unanswerable": {}, "calibration": {}}
    payload = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    return {
        group: {r["id"]: r for r in payload.get("records", {}).get(group, [])}
        for group in ("answerable", "unanswerable", "calibration")
    }


def write_state(state: Dict[str, Any], extra: Dict[str, Any]) -> None:
    groups = {g: list(state[g].values()) for g in state}
    payload = {
        **provenance.stamp(),
        **extra,
        "summary": {g: summarize(v) for g, v in groups.items() if v},
        "records": groups,
    }
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run(args) -> None:
    """Generate answers and grade them, resumably."""
    from query import SecurityRAG

    load_dotenv()
    provenance.require_layout_match()

    conn = LX.connect(Path(args.lexical_db), read_only=True)
    client_db = chromadb.PersistentClient(
        path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
    )
    collection = client_db.get_collection(args.collection)

    if not UNANSWERABLE_PATH.exists():
        print("building the unanswerable set ...")
        build_unanswerable(conn, collection)
    unanswerable = json.loads(UNANSWERABLE_PATH.read_text(encoding="utf-8"))["items"]

    eval_items = json.loads(EVAL_PATH.read_text(encoding="utf-8"))["items"]
    answerable = random.Random(SEED).sample(
        eval_items, min(N_ANSWERABLE, len(eval_items))
    )

    rag = SecurityRAG()
    judge_client = claude_client.build_client()
    state = load_state()
    budget = args.limit or 10 ** 6
    spent = 0

    def record(group: str, item_id: str, question: str, expected: str,
               extra: Dict[str, Any]) -> bool:
        """Answer and grade one question. Returns False when the budget is spent."""
        nonlocal spent
        if item_id in state[group] or spent >= budget:
            return spent < budget
        result = rag.query(question, n_results=N_RETRIEVED, return_context=True)
        answer = result.get("answer", "")
        context = result.get("context", "")
        if result.get("error"):
            # An API failure is not an answer. Persisting it would let a billing
            # error or a rate limit be scored as a hallucination, and the run is
            # resumable, so leaving the item unrecorded is the right outcome.
            print(f"  {item_id}: generation failed ({result['error'][:80]}); "
                  f"not recorded", flush=True)
            return False
        retrieved = cited_ids(context)
        cited = cited_ids(answer)
        verdict = judge(judge_client, args.model, context, answer)
        state[group][item_id] = {
            "id": item_id,
            "question": question,
            "expected": expected,
            "answer": answer,
            "grade": (verdict or {}).get("grade"),
            "judge_reason": (verdict or {}).get("reason"),
            "cited_ids": cited,
            "retrieved_ids": retrieved,
            # The deterministic check: an ID in the answer that was never
            # retrieved was invented, whatever the surrounding prose says.
            "invalid_citations": [c for c in cited if c not in retrieved],
            **extra,
        }
        spent += 1
        if spent % 5 == 0:
            write_state(state, {"in_progress": True})
            print(f"  {spent} answered and graded", flush=True)
        return spent < budget

    print(f"answerable: {len(answerable)} | unanswerable: {len(unanswerable)}")
    for item in answerable:
        if not record("answerable", item["cve_id"], item["question"],
                      "grounded", {"target_cve": item["cve_id"]}):
            break
    for item in unanswerable:
        if not record("unanswerable", item["id"], item["question"],
                      "abstained", {"kind": item["kind"]}):
            break

    # Judge calibration: corrupt real answers and check the judge notices.
    graded = [r for r in state["answerable"].values() if r.get("answer")]
    for index, source in enumerate(graded[: args.calibration]):
        kind, injected = CORRUPTIONS[index % len(CORRUPTIONS)]
        item_id = f"corrupt-{kind}-{source['id']}"
        if item_id in state["calibration"] or spent >= budget:
            continue
        corrupted = source["answer"] + injected
        context_result = rag.retrieve_context(source["question"], n_results=N_RETRIEVED)
        context = "\n\n".join(context_result["documents"])
        verdict = judge(judge_client, args.model, context, corrupted)
        state["calibration"][item_id] = {
            "id": item_id,
            "corruption": kind,
            "question": source["question"],
            "expected": "unsupported",
            "answer": corrupted,
            "grade": (verdict or {}).get("grade"),
            "judge_reason": (verdict or {}).get("reason"),
            "cited_ids": cited_ids(corrupted),
            "retrieved_ids": cited_ids(context),
            "invalid_citations": [c for c in cited_ids(corrupted)
                                  if c not in cited_ids(context)],
        }
        spent += 1

    write_state(state, {
        "judge_model": args.model,
        "documents_per_answer": N_RETRIEVED,
        "retrieval": rag.retrieval_mode + (" + direct_id" if rag.direct_id else ""),
    })
    conn.close()
    report()


def report() -> None:
    if not RESULTS_PATH.exists():
        raise SystemExit("no results yet; run with --run")
    payload = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})

    print()
    for group in ("answerable", "unanswerable", "calibration"):
        s = summary.get(group)
        if not s:
            continue
        print(f"{group} (n={s['answers']}, graded {s['graded']})")
        print(f"  grounded    {s['grounded_rate']:.3f}")
        print(f"  unsupported {s['unsupported_rate']:.3f}")
        print(f"  abstained   {s['abstained_rate']:.3f}")
        print(f"  answers citing a CVE {s['answers_citing_a_cve']}, "
              f"invented citations {s['answers_with_an_invented_cve']}, "
              f"citation validity {s['citation_validity']:.3f}")
        print()

    calib = summary.get("calibration")
    if calib:
        caught = calib["unsupported_rate"]
        print(f"judge calibration: caught {caught:.1%} of deliberately "
              f"corrupted answers")
        if caught < 0.8:
            print("  WARNING: the judge misses corruptions it was shown, so the "
                  "groundedness figure above is an upper bound at best")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--lexical-db", default=str(LEXICAL_DB))
    parser.add_argument("--model", default=os.getenv("CLAUDE_MODEL", "claude-opus-5"))
    parser.add_argument("--limit", type=int, help="stop after this many API pairs")
    parser.add_argument("--calibration", type=int, default=12,
                        help="how many corrupted answers to grade")
    parser.add_argument("--build", action="store_true",
                        help="build the unanswerable set and exit")
    parser.add_argument("--run", action="store_true", help="generate and grade")
    parser.add_argument("--report", action="store_true",
                        help="summarize existing results")
    args = parser.parse_args()

    if args.build:
        conn = LX.connect(Path(args.lexical_db), read_only=True)
        client_db = chromadb.PersistentClient(
            path=args.persist_dir, settings=Settings(anonymized_telemetry=False)
        )
        payload = build_unanswerable(conn, client_db.get_collection(args.collection))
        kinds: Dict[str, int] = {}
        for item in payload["items"]:
            kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
        print(f"built {len(payload['items'])} unanswerable questions: {kinds}")
        if payload["discarded_names"]:
            print(f"discarded (exist in corpus): {payload['discarded_names']}")
        print(f"wrote {UNANSWERABLE_PATH.relative_to(PROJECT_ROOT)}")
        conn.close()
        return
    if args.report:
        report()
        return
    if args.run:
        run(args)
        return
    parser.error("choose --build, --run or --report")


if __name__ == "__main__":
    main()
