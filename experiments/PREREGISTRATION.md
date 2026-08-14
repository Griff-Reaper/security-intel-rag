# Pre-registration: held-out answer-quality comparison

Written and committed **before** the run. The decision rule below is executable
— `experiments/answer_quality.py --decide` applies it to the results and prints
the verdict — so the interpretation cannot be chosen after seeing the data.

## Why this exists

Every retrieval conclusion in this project rests on Recall@1 proxying answer
quality. Nothing has tested that. This run tests it.

The power analysis (`experiments/power.py`) says n=157 gives between 1.00 and
0.38 power for a 10-point difference, depending on a grade-discordance rate that
cannot be known until the grades exist. That is an honest position and also a
trap: **a null result and an underpowered result look identical in the output**,
and once the data is in, the difference between "the configs are equivalent" and
"this run could not tell" is a sentence anyone can write either way.

This project already made the inverse error once — reading a pooled null as
evidence of no difference, caught only by re-testing per query shape. Writing the
rule down first is what makes that correction structural rather than a thing that
happened to get caught.

## Hypothesis

**H0:** `hybrid_rerank` and `bm25` produce the same rate of grounded answers on
held-out paraphrased questions.

## Design

- **Questions:** the items of `experiments/samples/paraphrased_eval.json` not
  used to develop the prompt fix. The held-out set is defined **by exclusion**
  against the development runs, not by a count and not by resampling, so it is
  identical across configs and cannot drift.

  *Post-hoc note, added after the run began and before any result was read:*
  the exclusion yields **154**, not the 157 stated elsewhere in this document.
  192 minus 38, not 192 minus 35 — the two questions the API refused in the
  baseline were seen and are held out too, and one further question appears in
  the baseline only. The definition is what governs; the count was arithmetic
  and it was three off.
- **Configs:** `hybrid_rerank + direct_id` (current default) and
  `bm25 + direct_id`. Both with `N_RETRIEVED = 5`, the same generation prompt,
  and the same judge (`claude-opus-5`), which passed two-sided calibration.
- **Primary outcome:** the three-way groundedness grade, collapsed to
  grounded vs not-grounded.
- **Test:** exact McNemar on discordant pairs, α = 0.05, two-sided. The same
  function `src/significance.py` uses everywhere else.
- **Calibration:** re-run per config. A judge that drifted between arms would
  produce a difference that is not in the system.

## Decision rule

**A** is `hybrid_rerank` — the incumbent, p50 587 ms, plus a cross-encoder to
load and serve. **B** is `bm25` — the challenger, p50 13 ms. The rule is
deliberately asymmetric in them, because the decision is: A has to earn its
latency, B only has to not be worse.

Let `CI` be the 95% interval on the paired difference in grounded rate, A − B,
and `Δ = 0.10` the difference that would justify A's cost.

| Condition | Verdict | Consequence |
|---|---|---|
| `p < 0.05`, B ahead | **Difference** | B is better *and* cheaper; default flips to `bm25` |
| `p < 0.05`, A ahead, `CI.low >= Δ` | **Difference** | A earns its latency; default unchanged |
| `p < 0.05`, A ahead, `CI.low < Δ` | **Difference below threshold** | Real but not worth 587 ms; default flips to `bm25` |
| `p >= 0.05`, `CI` inside `±Δ` | **Equivalence** | Default flips to `bm25` on latency grounds |
| `p >= 0.05`, `CI` wider than `±Δ` | **Inconclusive** | Interval reported; default stands unchanged on the Phase 2 retrieval evidence |

Two notes on why the rule is shaped this way, both from dry-running it against
synthetic results before the real ones existed:

**Equivalence is decided on the interval, not on achieved power.** Post-hoc power
is a deterministic function of the p-value and adds nothing to it. Worse, gating
on it inverts the small-discordance case: one discordant pair in 157 questions
bounds the true difference near zero — the strongest equivalence evidence this
design can produce — and a power gate calls it *inconclusive*, because at that
discordance a ten-point difference is not merely undetectable but arithmetically
impossible. The interval says so directly. Achieved power is still reported, as
a diagnostic.

**Statistical significance is not the same as being worth paying for.** A
significant three-point win for the slower config is a statement about sampling,
not about whether 587 ms per query buys a user anything. Without the
`CI.low >= Δ` clause, a slower default survives on a technicality.

**An inconclusive result is a reportable outcome, not a failed run.** It will be
published as inconclusive, with the interval stated next to it.

## The sample ceiling is methodological

157 is every held-out question that exists. `paraphrased_eval.json` carries one
question per CVE from a 200-CVE sample pinned in Phase 2 and committed not to be
redrawn; 192 generated successfully and 35 were spent developing the prompt fix.
More money does not buy more questions.

*(The counts in this paragraph are left as originally committed. They are three
off — see the note under **Design**. Correcting them in place would quietly
rewrite a document whose whole purpose is to be unrewritable; the argument is
unaffected, since 154 is no more purchasable than 157.)*

One option would raise n without touching that commitment: generating a **second
question per CVE** from the same 200. It is deliberately not being used here.
Two questions targeting the same CVE are not independent pairs, and McNemar
assumes independence; a correct analysis would need clustered inference, which is
more machinery in exchange for a weaker claim. It is held in reserve for the
**Inconclusive** branch only, and if used it will be reported as a clustered
analysis with the dependence stated, never pooled with these results as though
n had simply doubled.

## Secondary measurements, not tested

Reported for both configs but not subject to the decision rule, because the run
is not powered for them and they are not what it was designed to answer:
citation validity, false abstention, correct decline on unanswerable questions,
and provider refusal rate.

---

## Result

Run 2026-08-14. Verdict computed by `--decide`, artifact at
`experiments/results/config_decision.json`.

| | `hybrid_rerank` (A) | `bm25` (B) |
|---|---:|---:|
| Grounded | 141 / 142 = 0.993 | 142 / 142 = 1.000 |
| Judge recall on planted corruptions | 12 / 12 | 12 / 12 |
| Judge false positives on verbatim answers | 0 / 12 | 0 / 12 |
| Correct decline, unanswerable | 10 / 10 | 20 / 20 |
| Invented CVE IDs | 0 | 0 |

Difference A − B = **−0.007**, 95% interval **[−0.021, +0.007]**, exact McNemar
**p = 1.000** on one discordant pair.

**VERDICT: EQUIVALENCE.** The whole interval lies inside ±10 points. Both judges
passed calibration in both directions, so this is not judge drift.

## Two things the result exposed, recorded rather than quietly fixed

**1. The primary outcome was close to blind to what the comparison was for.**

Groundedness asks whether the answer follows from its context. It does not ask
whether that was the *right* context. An answer faithfully summarising five
documents, none of which concern the CVE the user asked about, is grounded —
correctly — and the user has still been failed.

The gap is large. Grounded rate 0.993; target CVE actually retrieved 0.782. On
roughly 3 questions in 14, the system produced an impeccable answer about the
wrong vulnerabilities. Choosing groundedness as the primary outcome was an error
in this document, not a finding of the run.

A post-hoc deterministic check, added after seeing that and labelled as such,
asks the second question: was the target CVE among the five documents retrieved?
**A 111/142 = 0.782, B 108/142 = 0.761**, difference +0.021, interval
[−0.036, +0.078], p = 0.629. It agrees with the pre-registered verdict, which is
the only reason the verdict survives contact with this limitation.

**2. The stated consequence was broader than the experiment.**

The rule says equivalence flips the shipped default to `bm25`. That was written
without noticing that this experiment covers **one query shape of four**.
`hybrid_rerank` was made the default on Phase 2 per-shape evidence, and on the
one shape where the two configs measurably differ it still wins:

| Query shape | `hybrid_rerank` R@1 | `bm25` R@1 | Paired test |
|---|---:|---:|---|
| Product + version | **0.306** | 0.235 | p = 0.0125, significant |
| Bare CVE ID | — | — | p = 0.070, and routed by keyed lookup anyway |
| Description sentence | — | — | p = 0.791 |
| Paraphrased analyst question | 0.625 | 0.609 | p = 0.775 |

The latency premise was also weaker than stated. This document justifies Δ = 0.10
with "587 ms against 13 ms", as though retrieval were the query. Measured from
ledger timestamps, generation p50 is **4.0 s**, so the retrieval premium is
**12.5% of end-to-end**, not 45×.

So the honest position is that the verdict stands and its stated consequence does
not follow from it. Flipping the default would trade a measured, significant
7-point R@1 loss on product+version queries for 12.5% latency, on the strength of
an experiment that did not test that shape. **The default is left unchanged and
this paragraph is the record of the rule not being executed as written** — which
is worse than the rule having been right, and better than either silently
skipping it or following it off a cliff.

The pre-registration did its job. It stopped "equivalent" being written where
"the metric could not see it" belonged, and it made the overreach visible instead
of letting a convenient reading pass. Routing by query shape is the correct fix
and is on the roadmap.

---

*Committed before any held-out question was answered. Verify with
`git log --diff-filter=A -- experiments/PREREGISTRATION.md` against the
`generated_at` timestamps in `experiments/results/answer_quality_holdout_*.json`.
Everything above the Result heading is as first committed, apart from the dated
note under Design.*
