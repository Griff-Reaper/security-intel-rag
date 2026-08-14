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
import math
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

import api_ledger  # noqa: E402
import claude_client  # noqa: E402
import lexical_index as LX  # noqa: E402
import provenance  # noqa: E402

EVAL_PATH = PROJECT_ROOT / "experiments" / "samples" / "paraphrased_eval.json"
UNANSWERABLE_PATH = PROJECT_ROOT / "experiments" / "samples" / "unanswerable_questions.json"
RESULTS_PATH = PROJECT_ROOT / "experiments" / "results" / "answer_quality.json"
LEXICAL_DB = PROJECT_ROOT / "chroma_db" / "lexical.sqlite3"

SEED = 20260813
N_ANSWERABLE = 40
# Grading is a much easier task than answering, so it does not need the same
# model. Whether this one is good enough is not assumed - the calibration set
# measures it, and the run reports the result next to every grade.
DEFAULT_JUDGE_MODEL = "claude-haiku-4-5-20251001"
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

DECLINE_PROMPT = """A question was asked that the provided context cannot answer.

Judge only one thing: did the answer make clear that the requested information is not available, rather than supplying it anyway?

QUESTION:
{question}

CONTEXT THE ASSISTANT WAS SHOWN:
{context}

ANSWER:
{answer}

Set "declined" to true if the answer states that the information is absent, unavailable, or not covered by the context. It still counts as declining if the answer goes on to describe what the context *does* contain - that is helpful, not evasive.

Set "fabricated" to true if the answer supplies a specific factual claim about the thing asked for - a version range, a severity, a threat actor, a patch step, an exploit location - that does not appear in the context.

Respond with only a JSON object:
{{"declined": true or false, "fabricated": true or false, "reason": "one short sentence"}}"""

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
    """Grade one answer against its context, or None if the judge gave nothing usable.

    Returns the verdict with the call's exact token usage attached, so the cost
    of running this evaluation is a measured number rather than an estimate.
    """
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
        api_ledger.record(response, model, "answer_quality:groundedness_judge")
        if response.stop_reason == "refusal":
            return None
        text = next((b.text for b in response.content if b.type == "text"), "")
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if parsed.get("grade") in ("grounded", "unsupported", "abstained"):
                    parsed["usage"] = {
                        "input_tokens": getattr(response.usage, "input_tokens", None),
                        "output_tokens": getattr(response.usage, "output_tokens", None),
                    }
                    return parsed
            except json.JSONDecodeError:
                pass
    return None


def judge_decline(client, model: str, question: str, context: str,
                  answer: str) -> Optional[Dict[str, Any]]:
    """Did the answer decline, and did it invent anything? For unanswerable items."""
    for attempt in range(3):
        try:
            response = client.messages.create(
                model=model, max_tokens=JUDGE_MAX_TOKENS,
                messages=[{"role": "user", "content": DECLINE_PROMPT.format(
                    question=question, context=context[:20000], answer=answer[:8000])}],
            )
        except Exception:  # noqa: BLE001
            time.sleep(1.5 * (attempt + 1))
            continue
        api_ledger.record(response, model, "answer_quality:decline_judge")
        if response.stop_reason == "refusal":
            return None
        text = next((b.text for b in response.content if b.type == "text"), "")
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if isinstance(parsed.get("declined"), bool):
                    return parsed
            except json.JSONDecodeError:
                pass
    return None


# Groups where declining to answer is the wrong outcome. Abstention is scored
# the same way everywhere, but it means opposite things: on a question the
# corpus answers, a refusal is a failure, and reporting it inside a single
# "abstained_rate" lets a system that refuses indiscriminately look good on the
# unanswerable set for entirely the wrong reason.
ABSTENTION_IS_A_FAILURE = ("answerable", "calibration_verbatim")

# What query.py substitutes when the API returns stop_reason "refusal". The
# request is declined by a safety classifier: HTTP 200, no content, no usage.
#
# This string reached the judge as though it were an answer, and the judge - not
# unreasonably - graded it "abstained". Two of eighteen baseline questions were
# therefore counted as the system refusing to answer something it could answer,
# when the system had never been asked. Any record carrying it is excluded from
# every rate and reported separately, including in artifacts written before the
# run loop learned to skip them.
REFUSAL_PLACEHOLDER = "The model declined to answer this query."


def is_provider_refusal(record: Dict[str, Any]) -> bool:
    return (record.get("error") == "refusal"
            or (record.get("answer") or "").strip() == REFUSAL_PLACEHOLDER)


def summarize(records: List[Dict[str, Any]],
              group: str = "") -> Dict[str, Any]:
    """Aggregate one group of graded answers."""
    refusals = [r for r in records if is_provider_refusal(r)]
    records = [r for r in records if not is_provider_refusal(r)]
    graded = [r for r in records if r.get("grade")]
    n = max(len(graded), 1)
    counts: Dict[str, int] = {}
    for r in graded:
        counts[r["grade"]] = counts.get(r["grade"], 0) + 1
    declined = [r for r in records if r.get("declined") is True]
    fabricated = [r for r in records if r.get("fabricated") is True]
    judged_decline = [r for r in records if r.get("declined") is not None]
    with_citations = [r for r in records if r.get("cited_ids")]
    invalid = [r for r in records if r.get("invalid_citations")]
    block = {
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
        # Only meaningful for the unanswerable group.
        "decline_judged": len(judged_decline),
        "declined_rate": round(len(declined) / max(len(judged_decline), 1), 4),
        "fabricated_rate": round(len(fabricated) / max(len(judged_decline), 1), 4),
    }
    if refusals:
        block["provider_refusals"] = len(refusals)
        block["provider_refusal_ids"] = [r["id"] for r in refusals]
        block["note"] = ("provider refusals are excluded from every rate above; "
                         "they are the API declining the request, not the "
                         "system declining to answer")
    if group in ABSTENTION_IS_A_FAILURE:
        # The cost side of the refusal metric. Read it next to the unanswerable
        # group's abstention rate, never alone: driving one to a good number by
        # making the system more reluctant drives this one the wrong way.
        block["false_abstention_rate"] = block["abstained_rate"]
        block["false_abstentions"] = counts.get("abstained", 0)
    return block


def rebuild_context(rag, question: str) -> str:
    """
    Reconstruct exactly the context string the answer model was shown.

    Not `"
".join(documents)`: the prompt the model receives is built by
    format_context_documents(), which folds in metadata the document text does
    not contain - publication date, CVSS score, CWE list. Judging an answer
    against the raw documents shows the judge *less* than the model saw, so
    every metadata-derived fact in a correct answer looks invented.

    That is not hypothetical. An earlier version of this script did exactly
    that, and both judges duly reported that the system was hallucinating
    publication dates. The dates were in the prompt all along.

    The enrichment snapshot is threaded through for the same reason. It is a
    keyword argument with a default, which is precisely how the first version of
    this bug survived review, so tests assert the two call sites agree rather
    than trusting that they look similar.
    """
    from prompts import format_context_documents

    retrieved = rag.retrieve_context(question, n_results=N_RETRIEVED)
    return format_context_documents(retrieved["documents"], retrieved["metadatas"],
                                    enrichment=rag.enrichment_snapshot)


def verbatim_answer(context: str, lines: int = 6) -> str:
    """
    An "answer" quoted directly out of the context.

    The mirror of a corrupted answer, and the half of calibration that was
    missing. Corruptions measure whether the judge *catches* an unsupported
    claim; they say nothing about whether it wrongly flags a supported one. A
    judge with perfect recall and poor precision passes a one-sided calibration
    and then reports a healthy system as broken - which is exactly what happened
    here on the first pass.

    An answer copied verbatim from the context cannot contain an unsupported
    claim, so any grade other than "grounded" is a false positive by construction.
    """
    body = [ln for ln in context.splitlines()
            if ln.strip() and not ln.startswith("---")]
    return "Based on the retrieved documents:\n\n" + "\n".join(body[:lines])


def load_state(results_path: Path) -> Dict[str, Any]:
    """Existing graded answers, so a run can resume without re-paying for them.

    The resume behaviour is why the destination is a parameter rather than a
    constant. Re-running after a prompt change writes into the same file and
    skips every question already present, so a comparison against the previous
    prompt would silently be a comparison of a prompt against itself. Separate
    prompts go to separate files.
    """
    if not Path(results_path).exists():
        return {"answerable": {}, "unanswerable": {},
                "calibration_corrupted": {}, "calibration_verbatim": {}}
    payload = json.loads(Path(results_path).read_text(encoding="utf-8"))
    return {
        group: {r["id"]: r for r in payload.get("records", {}).get(group, [])}
        for group in ("answerable", "unanswerable",
                      "calibration_corrupted", "calibration_verbatim")
    }


def write_state(state: Dict[str, Any], extra: Dict[str, Any],
                results_path: Path) -> None:
    groups = {g: list(state[g].values()) for g in state}
    payload = {
        **provenance.stamp(),
        **extra,
        "summary": {g: summarize(v, g) for g, v in groups.items() if v},
        "records": groups,
    }
    Path(results_path).parent.mkdir(parents=True, exist_ok=True)
    Path(results_path).write_text(json.dumps(payload, indent=2) + "\n",
                                 encoding="utf-8")


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
    if args.holdout_from:
        # Exclusion, not resampling. The held-out set is defined as "everything
        # the prompt fix was not developed against", so it stays identical
        # across configs and cannot drift with a seed or a count.
        spent_on_development = set()
        for path in args.holdout_from:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
            for group in payload.get("records", {}).values():
                spent_on_development.update(r["id"] for r in group)
        before = len(eval_items)
        eval_items = [i for i in eval_items
                      if i["cve_id"] not in spent_on_development]
        print(f"held out {len(eval_items)} of {before} questions "
              f"({before - len(eval_items)} spent on development)")
    answerable = random.Random(SEED).sample(
        eval_items, min(args.answerable, len(eval_items))
    )

    rag = SecurityRAG(retrieval=args.retrieval)
    judge_client = claude_client.build_client()
    results_path = Path(args.results)
    state = load_state(results_path)
    budget = args.limit or 10 ** 6
    spent = 0
    failures: List[str] = []

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
                  f"skipped", flush=True)
            failures.append(item_id)
            # Skip this item, but keep going: one refusal must not silently
            # truncate the rest of the set and leave a smaller n unremarked.
            return spent < budget
        retrieved = cited_ids(context)
        cited = cited_ids(answer)
        verdict = judge(judge_client, args.judge_model, context, answer)
        state[group][item_id] = {
            "id": item_id,
            "question": question,
            "expected": expected,
            "answer": answer,
            "grade": (verdict or {}).get("grade"),
            "judge_reason": (verdict or {}).get("reason"),
            "usage": result.get("usage"),
            "judge_usage": (verdict or {}).get("usage"),
            "cited_ids": cited,
            "retrieved_ids": retrieved,
            # The deterministic check: an ID in the answer that was never
            # retrieved was invented, whatever the surrounding prose says.
            "invalid_citations": [c for c in cited if c not in retrieved],
            **extra,
        }
        spent += 1
        if spent % 5 == 0:
            write_state(state, {"in_progress": True}, results_path)
            print(f"  {spent} answered and graded", flush=True)
        return spent < budget

    print(f"answerable: {len(answerable)} | unanswerable: {len(unanswerable)}")
    for item in answerable:
        if not record("answerable", item["cve_id"], item["question"],
                      "grounded", {"target_cve": item["cve_id"]}):
            break

    # Judge calibration: corrupt real answers and check the judge notices.
    graded = [r for r in state["answerable"].values() if r.get("answer")]
    for index, source in enumerate(graded[: args.calibration]):
        kind, injected = CORRUPTIONS[index % len(CORRUPTIONS)]
        item_id = f"corrupt-{kind}-{source['id']}"
        if item_id in state["calibration_corrupted"] or spent >= budget:
            continue
        corrupted = source["answer"] + injected
        context = rebuild_context(rag, source["question"])
        verdict = judge(judge_client, args.judge_model, context, corrupted)
        state["calibration_corrupted"][item_id] = {
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

    # The other half of calibration: answers that cannot be unsupported.
    for source in graded[: args.calibration]:
        item_id = f"verbatim-{source['id']}"
        if item_id in state["calibration_verbatim"] or spent >= budget:
            continue
        context = rebuild_context(rag, source["question"])
        quoted = verbatim_answer(context)
        verdict = judge(judge_client, args.judge_model, context, quoted)
        state["calibration_verbatim"][item_id] = {
            "id": item_id,
            "question": source["question"],
            "expected": "grounded",
            "answer": quoted,
            "grade": (verdict or {}).get("grade"),
            "judge_reason": (verdict or {}).get("reason"),
            "judge_usage": (verdict or {}).get("usage"),
            "cited_ids": cited_ids(quoted),
            "retrieved_ids": cited_ids(context),
            "invalid_citations": [],
        }
        spent += 1

    for item in unanswerable:
        if not record("unanswerable", item["id"], item["question"],
                      "declined", {"kind": item["kind"]}):
            break

    # Abstention is judged with its own question, because the three-way
    # groundedness grade cannot express it: an answer that says "not in the
    # context, but here is what is" asserts supported facts and grades as
    # grounded, which would read as a failure to decline when it is the
    # opposite.
    for item in unanswerable:
        rec = state["unanswerable"].get(item["id"])
        if not rec or rec.get("declined") is not None or spent >= budget:
            continue
        context = rebuild_context(rag, rec["question"])
        verdict = judge_decline(judge_client, args.judge_model, rec["question"],
                                context, rec["answer"])
        if verdict:
            rec["declined"] = verdict["declined"]
            rec["fabricated"] = verdict.get("fabricated")
            rec["decline_reason"] = verdict.get("reason")
        spent += 1

    write_state(state, {
        "answer_model": args.model,
        "judge_model": args.judge_model,
        "documents_per_answer": N_RETRIEVED,
        "generation_failures": failures,
        "retrieval": rag.retrieval_mode + (" + direct_id" if rag.direct_id else ""),
        "held_out_from": args.holdout_from or [],
    }, results_path)
    conn.close()
    if failures:
        # Safety-classifier refusals, not answers. They are named rather than
        # counted because the first run recorded them as records - the API
        # returns HTTP 200 with a placeholder string, which a groundedness judge
        # duly grades "abstained", turning a refusal by the provider into an
        # apparent refusal by the system.
        print(f"\n{len(failures)} generation failures, excluded from every rate: "
              f"{', '.join(failures)}")
    report(results_path)


def rejudge(args) -> None:
    """Re-grade every existing answer with the current judge model.

    Grades from two different judges are not comparable, so switching judge
    means re-grading what already exists rather than mixing the two. Only the
    judge is re-run: the answers are reused and retrieval is local, so this
    costs one cheap call per record and changes nothing about what is measured.
    """
    from query import SecurityRAG

    load_dotenv()
    rag = SecurityRAG()
    judge_client = claude_client.build_client()
    results_path = Path(args.results)
    state = load_state(results_path)
    regraded = 0

    wanted = set(args.groups.split(",")) if args.groups else set(state)
    for group, records in state.items():
        if group not in wanted:
            continue
        for item_id, rec in records.items():
            if not rec.get("answer"):
                continue
            context = rebuild_context(rag, rec["question"])
            verdict = judge(judge_client, args.judge_model, context, rec["answer"])
            if verdict:
                rec["grade"] = verdict["grade"]
                rec["judge_reason"] = verdict.get("reason")
                rec["judge_usage"] = verdict.get("usage")
                regraded += 1
        write_state(state, {"judge_model": args.judge_model}, results_path)

    print(f"re-graded {regraded} answers with {args.judge_model}")
    report(results_path)


def compare(baseline_path: Path, current_path: Path) -> None:
    """
    Paired before/after over the questions both runs answered.

    Paired rather than two independent rates, because the same questions appear
    in both and their difficulty is the largest source of variance. The exact
    McNemar test used for retrieval applies unchanged: only the questions whose
    grade changed carry information, and at this sample size there will be very
    few of them.

    Which is the point of reporting it this way. A development set of eighteen
    questions cannot establish that a prompt change worked; it can show which
    specific failures it removed and whether it introduced new ones. The
    per-question movement below is the useful output. The test is there to say
    plainly how little the aggregate proves.
    """
    import significance

    def grades(path: Path) -> Dict[str, Dict[str, Any]]:
        if not path.exists():
            raise SystemExit(f"missing {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        return {g: {r["id"]: r for r in payload.get("records", {}).get(g, [])}
                for g in ("answerable", "unanswerable")}

    before, after = grades(baseline_path), grades(current_path)

    # Each group is scored by the instrument built for it. Grading the
    # unanswerable group on the three-way groundedness rubric reports a
    # catastrophic regression that is not one: an answer saying "the corpus does
    # not carry that, but here is what it does" moves from "abstained" to
    # "grounded" and looks like a failure to decline, when it is a better
    # decline. The decline judge exists precisely because the rubric cannot
    # express this, so it is what the comparison uses.
    def outcome(record: Dict[str, Any], group: str) -> Optional[str]:
        if group == "unanswerable":
            declined = record.get("declined")
            return None if declined is None else ("declined" if declined
                                                  else "answered anyway")
        return record.get("grade")

    print(f"baseline  {baseline_path.name}")
    print(f"current   {current_path.name}")
    for group in ("answerable", "unanswerable"):
        shared = sorted(
            key for key in set(before[group]) & set(after[group])
            if outcome(before[group][key], group) is not None
            and outcome(after[group][key], group) is not None
        )
        if not shared:
            continue
        good = "declined" if group == "unanswerable" else "grounded"
        moved_up, moved_down, changed = [], [], []
        for key in shared:
            b = outcome(before[group][key], group)
            a = outcome(after[group][key], group)
            if b == a:
                continue
            changed.append((key, b, a))
            if a == good and b != good:
                moved_up.append(key)
            elif b == good and a != good:
                moved_down.append(key)

        b_rate = sum(1 for k in shared if outcome(before[group][k], group) == good)
        a_rate = sum(1 for k in shared if outcome(after[group][k], group) == good)
        print()
        print(f"{group} (n={len(shared)} shared questions, target outcome '{good}')")
        print(f"  before {b_rate}/{len(shared)} = {b_rate/len(shared):.3f}")
        print(f"  after  {a_rate}/{len(shared)} = {a_rate/len(shared):.3f}")
        print(f"  fixed {len(moved_up)}, regressed {len(moved_down)}, "
              f"other grade changes {len(changed) - len(moved_up) - len(moved_down)}")
        discordant = len(moved_up) + len(moved_down)
        p = significance.exact_binomial_two_sided(
            min(len(moved_up), len(moved_down)), discordant)
        print(f"  exact McNemar on {discordant} discordant pairs: p={p:.4f}"
              + ("" if discordant >= 6 else
                 "  (below six discordant pairs no split can reach p<0.05, "
                 "so this cannot be significant whatever it shows)"))
        for key, b, a in changed:
            arrow = "fixed    " if a == good else (
                "REGRESSED" if b == good else "changed  ")
            print(f"    {arrow} {key}: {b} -> {a}")


# The threshold that would justify hybrid_rerank's cost: a p50 of 587 ms against
# BM25's 13 ms, plus a cross-encoder to load and serve. Fixed in
# experiments/PREREGISTRATION.md before the run, not chosen from the results.
DECISION_DELTA = 0.10
DECISION_POWER = 0.80


def paired_difference_interval(a_wins: int, b_wins: int, n: int,
                               z: float = 1.96) -> Dict[str, float]:
    """
    95% interval for the difference in grounded rates between two configs on
    the same questions.

    Concordant pairs contribute nothing to the difference but do contribute to
    the denominator, which is why this is not two independent proportions
    subtracted. The variance is the multinomial one:

        Var(p_a - p_b) = [ (b + c) - (b - c)^2 / n ] / n^2
    """
    difference = (a_wins - b_wins) / n
    discordant = a_wins + b_wins
    variance = max(0.0, discordant - (a_wins - b_wins) ** 2 / n) / (n * n)
    half = z * math.sqrt(variance)
    return {
        "difference": round(difference, 4),
        "low": round(difference - half, 4),
        "high": round(difference + half, 4),
        "half_width": round(half, 4),
    }


def decide(a_path: Path, b_path: Path) -> Dict[str, Any]:
    """
    Apply the pre-registered decision rule to a config comparison.

    A is the incumbent and the expensive one (hybrid_rerank, p50 587 ms);
    B is the challenger and the cheap one (bm25, p50 13 ms). The rule is not
    symmetric in them, because the decision is not symmetric: A has to earn its
    latency, and B only has to not be worse.

    The rule exists because a null result and an underpowered result are the
    same output. Without a threshold fixed in advance, "the configs are
    equivalent" and "this run could not tell" are both available after the fact,
    and the choice between them is unfalsifiable.

    Equivalence is decided on the confidence interval rather than on achieved
    power. Post-hoc power is a deterministic function of the p-value and adds
    nothing to it, and gating on it gets the small-discordance case exactly
    backwards: one discordant pair in 157 questions bounds the true difference
    near zero - the strongest equivalence evidence this design can produce - and
    a power gate reports it as inconclusive, because a ten-point difference is
    not merely undetectable at that discordance but arithmetically impossible.
    The interval says so directly. Achieved power is still reported, as a
    diagnostic rather than a criterion.

    See experiments/PREREGISTRATION.md, committed before any held-out question
    was answered.
    """
    import power as power_mod
    import significance

    def grades(path: Path) -> Dict[str, str]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return {r["id"]: r["grade"]
                for r in payload.get("records", {}).get("answerable", [])
                if r.get("grade") and not is_provider_refusal(r)}

    a, b = grades(a_path), grades(b_path)
    shared = sorted(set(a) & set(b))
    if not shared:
        raise SystemExit("the two runs share no graded questions")

    a_wins = sum(1 for k in shared
                 if a[k] == "grounded" and b[k] != "grounded")
    b_wins = sum(1 for k in shared
                 if b[k] == "grounded" and a[k] != "grounded")
    discordant = a_wins + b_wins
    p_value = significance.exact_binomial_two_sided(min(a_wins, b_wins),
                                                    discordant)

    n = len(shared)
    observed_discordance = discordant / n
    interval = paired_difference_interval(a_wins, b_wins, n)

    psi = power_mod.psi_for_delta(DECISION_DELTA, observed_discordance)
    achieved = (None if psi is None
                else round(power_mod.power(n, observed_discordance, psi), 4))

    within = (abs(interval["low"]) < DECISION_DELTA
              and abs(interval["high"]) < DECISION_DELTA)
    if p_value < 0.05 and b_wins > a_wins:
        # The challenger is both faster and better. No tension to resolve.
        verdict = "difference"
        consequence = ("B is better and cheaper; it becomes the default")
    elif p_value < 0.05 and interval["low"] >= DECISION_DELTA:
        verdict = "difference"
        consequence = ("A is better by more than the threshold; it stays the "
                       "default")
    elif p_value < 0.05:
        # Statistically real, practically not worth paying for. Significance is
        # a statement about sampling, not about whether 587 ms per query buys
        # anything a user would notice, and conflating the two is how a slower
        # default survives on a technicality.
        verdict = "difference below the threshold"
        consequence = (f"A is better by {interval['difference']:+.3f} "
                       f"[{interval['low']:+.3f}, {interval['high']:+.3f}], "
                       f"which does not reach {DECISION_DELTA:.0%}: the default "
                       f"flips to bm25 on latency grounds")
    elif within:
        verdict = "equivalence"
        consequence = (f"the whole interval lies inside "
                       f"+/-{DECISION_DELTA:.0%}: the default flips to bm25 on "
                       f"latency grounds")
    else:
        verdict = "inconclusive"
        consequence = (f"the interval admits a difference of "
                       f"{DECISION_DELTA:.0%} or more; the default stands "
                       f"unchanged on the Phase 2 retrieval evidence")

    result = {
        "a": str(a_path), "b": str(b_path),
        "questions": n,
        "a_grounded": sum(1 for k in shared if a[k] == "grounded"),
        "b_grounded": sum(1 for k in shared if b[k] == "grounded"),
        "a_wins": a_wins, "b_wins": b_wins,
        "discordant": discordant,
        "observed_grade_discordance": round(observed_discordance, 4),
        "p_value": round(p_value, 4),
        "difference_interval_95": interval,
        "preregistered_delta": DECISION_DELTA,
        "achieved_power_at_delta": achieved,
        "achieved_power_note": (
            "diagnostic only; the verdict is decided on the interval. None "
            "means a difference that size is arithmetically impossible at the "
            "observed discordance."
        ),
        "verdict": verdict,
        "consequence": consequence,
        "rule": "experiments/PREREGISTRATION.md",
    }

    print(f"{n} shared held-out questions")
    print(f"  A grounded {result['a_grounded']}/{n} = "
          f"{result['a_grounded'] / n:.3f}")
    print(f"  B grounded {result['b_grounded']}/{n} = "
          f"{result['b_grounded'] / n:.3f}")
    print(f"  discordant {discordant} (A {a_wins}, B {b_wins}), "
          f"grade discordance {observed_discordance:.3f}")
    print(f"  difference A - B = {interval['difference']:+.3f}, "
          f"95% interval [{interval['low']:+.3f}, {interval['high']:+.3f}]")
    print(f"  exact McNemar p = {p_value:.4f}")
    print(f"  achieved power for a {DECISION_DELTA:.0%} difference: "
          + ("n/a (impossible at this discordance)" if achieved is None
             else f"{achieved:.2f}") + "   [diagnostic]")
    print()
    print(f"  VERDICT: {verdict.upper()}")
    print(f"  {consequence}")
    return result


def report(results_path: Path) -> None:
    if not Path(results_path).exists():
        raise SystemExit(f"no results at {results_path}; run with --run")
    payload = json.loads(Path(results_path).read_text(encoding="utf-8"))
    summary = payload.get("summary", {})

    print()
    for group in ("answerable", "unanswerable",
                  "calibration_corrupted", "calibration_verbatim"):
        s = summary.get(group)
        if not s:
            continue
        print(f"{group} (n={s['answers']}, graded {s['graded']})")
        print(f"  grounded    {s['grounded_rate']:.3f}")
        print(f"  unsupported {s['unsupported_rate']:.3f}")
        print(f"  abstained   {s['abstained_rate']:.3f}"
              + ("  <- refusals on answerable questions, i.e. failures"
                 if s.get("false_abstentions") else ""))
        if s.get("provider_refusals"):
            print(f"  excluded    {s['provider_refusals']} provider refusals "
                  f"(API declined the request; not an answer, not an abstention)")
        print(f"  answers citing a CVE {s['answers_citing_a_cve']}, "
              f"invented citations {s['answers_with_an_invented_cve']}, "
              f"citation validity {s['citation_validity']:.3f}")
        if s.get("decline_judged"):
            print(f"  declined {s['declined_rate']:.3f}, "
                  f"fabricated {s['fabricated_rate']:.3f} "
                  f"(n={s['decline_judged']}, judged separately from groundedness)")
        print()

    answerable = summary.get("answerable")
    unanswerable = summary.get("unanswerable")
    if answerable and unanswerable:
        # The two halves of the refusal behaviour, reported together because
        # either one alone is gameable. A system tuned to refuse more would
        # push the first number up and the second one up with it.
        print("refusal behaviour (read as a pair)")
        # Measured with the decline judge, not the groundedness rubric. The
        # rubric cannot express this: an answer that says "the corpus does not
        # carry that, but here is what it does carry" asserts supported facts
        # and grades "grounded", which reads as a failure to decline when it is
        # the opposite.
        print(f"  correct decline,    unanswerable questions : "
              f"{unanswerable.get('declined_rate', 0):.3f} "
              f"({round(unanswerable.get('declined_rate', 0) * unanswerable.get('decline_judged', 0))}/"
              f"{unanswerable.get('decline_judged', 0)}, decline judge)")
        print(f"  false abstention,   answerable questions   : "
              f"{answerable.get('false_abstention_rate', 0):.3f} "
              f"({answerable.get('false_abstentions', 0)}/"
              f"{answerable['graded']})")
        print("  a system that refuses indiscriminately scores well on the "
              "first and badly on the second")
        print()

    corrupted = summary.get("calibration_corrupted")
    verbatim = summary.get("calibration_verbatim")
    if corrupted or verbatim:
        print("judge calibration")
    if corrupted:
        print(f"  recall    : caught {corrupted['unsupported_rate']:.1%} of "
              f"deliberately corrupted answers (n={corrupted['answers']})")
        if corrupted["unsupported_rate"] < 0.8:
            print("    WARNING: misses planted errors, so groundedness is an "
                  "upper bound at best")
    if verbatim:
        false_positive = 1 - verbatim["grounded_rate"]
        print(f"  precision : wrongly flagged {false_positive:.1%} of answers "
              f"quoted verbatim from their own context (n={verbatim['answers']})")
        if false_positive > 0.1:
            print("    WARNING: this judge invents faults in grounded answers, "
                  "so the unsupported rate above is inflated and must not be "
                  "quoted as a property of the system")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persist-dir", default=str(PROJECT_ROOT / "chroma_db"))
    parser.add_argument("--collection", default="nvd_cve")
    parser.add_argument("--lexical-db", default=str(LEXICAL_DB))
    parser.add_argument("--model", default=os.getenv("CLAUDE_MODEL", "claude-opus-5"),
                        help="model under test; generates the answers")
    parser.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL,
                        help="model that grades. Cheaper is fine if it passes "
                             "calibration - that is what calibration is for.")
    parser.add_argument("--answerable", type=int, default=N_ANSWERABLE,
                        help="how many answerable questions to reach in total")
    parser.add_argument("--limit", type=int, help="stop after this many API pairs")
    parser.add_argument("--calibration", type=int, default=12,
                        help="how many corrupted answers to grade")
    parser.add_argument("--build", action="store_true",
                        help="build the unanswerable set and exit")
    parser.add_argument("--run", action="store_true", help="generate and grade")
    parser.add_argument("--rejudge", action="store_true",
                        help="re-grade existing answers with --judge-model")
    parser.add_argument("--groups", default=None,
                        help="comma-separated groups to re-grade; default all")
    parser.add_argument("--report", action="store_true",
                        help="summarize existing results")
    parser.add_argument("--results", default=str(RESULTS_PATH),
                        help="where to read and write graded answers. A run "
                             "resumes from whatever is already here, so a "
                             "prompt change needs a new path or it will skip "
                             "every question and compare a prompt to itself.")
    parser.add_argument("--retrieval", default=None,
                        help="retrieval config under test; defaults to the "
                             "shipped default")
    parser.add_argument("--holdout-from", action="append", metavar="RESULTS",
                        help="exclude every question appearing in this results "
                             "file. Repeatable. Defines the held-out set by "
                             "exclusion so it is identical across configs.")
    parser.add_argument("--decide", nargs=2, metavar=("A", "B"),
                        help="apply the pre-registered decision rule to two "
                             "config runs; see experiments/PREREGISTRATION.md")
    parser.add_argument("--compare", metavar="BASELINE",
                        help="paired comparison of --results against an earlier "
                             "results file over the questions both contain")
    args = parser.parse_args()

    if args.decide:
        decide(Path(args.decide[0]), Path(args.decide[1]))
        return

    if args.compare:
        compare(Path(args.compare), Path(args.results))
        return

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
        report(Path(args.results))
        return
    if args.rejudge:
        rejudge(args)
        return
    if args.run:
        run(args)
        return
    parser.error("choose --build, --run or --report")


if __name__ == "__main__":
    main()
