"""
Tests for the answer-quality harness itself.

The harness has now produced five faults that would have shipped as findings
about the system, so it is treated as the thing under test rather than the thing
doing the testing. Each class below pins one of them.

The results-path tests exist because of the most recent: `--results` was added so
a prompt change could be measured against its predecessor, one of the four write
sites kept its default, and the run silently overwrote the baseline it was being
compared against. The parameter is now required, which turns that mistake into a
TypeError, and the call sites are checked here so it stays that way.
"""

import ast
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "experiments"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "config"))

import answer_quality as aq  # noqa: E402


def graded(grade, **extra):
    return {"id": extra.pop("id", "CVE-2000-0001"), "grade": grade,
            "answer": extra.pop("answer", "An answer."), **extra}


class TestProviderRefusals:
    """The API declining a request is not the system declining to answer."""

    def test_the_placeholder_is_recognised(self):
        assert aq.is_provider_refusal({"answer": aq.REFUSAL_PLACEHOLDER})

    def test_the_error_field_is_recognised(self):
        assert aq.is_provider_refusal({"error": "refusal", "answer": ""})

    def test_a_real_abstention_is_not_a_refusal(self):
        answer = "The indexed data does not cover this vulnerability."
        assert not aq.is_provider_refusal({"answer": answer})

    def test_the_placeholder_matches_what_query_py_emits(self):
        """A copy of a string in two files drifts. This is the string the
        production path substitutes on stop_reason 'refusal'."""
        source = (ROOT / "src" / "query.py").read_text(encoding="utf-8")
        assert aq.REFUSAL_PLACEHOLDER in source

    def test_refusals_are_excluded_from_every_rate(self):
        records = [graded("grounded", id="a"), graded("unsupported", id="b"),
                   graded("abstained", id="c", answer=aq.REFUSAL_PLACEHOLDER)]
        block = aq.summarize(records, "answerable")
        assert block["answers"] == 2
        assert block["grounded_rate"] == 0.5
        assert block["abstained_rate"] == 0.0
        assert block["provider_refusals"] == 1
        assert block["provider_refusal_ids"] == ["c"]

    def test_this_is_the_baseline_correction(self):
        """Two of eighteen baseline records were the placeholder, graded
        'abstained' because that is what the text says. Reported as a false
        abstention rate of 0.111, the system looked like it was refusing
        answerable questions; it had never been asked them."""
        records = ([graded("grounded", id=f"g{i}") for i in range(11)]
                   + [graded("unsupported", id=f"u{i}") for i in range(5)]
                   + [graded("abstained", id=f"r{i}",
                             answer=aq.REFUSAL_PLACEHOLDER) for i in range(2)])
        block = aq.summarize(records, "answerable")
        assert block["answers"] == 16
        assert block["grounded_rate"] == pytest.approx(0.6875)
        assert block["false_abstention_rate"] == 0.0
        assert block["provider_refusals"] == 2

    def test_no_refusals_leaves_the_block_clean(self):
        block = aq.summarize([graded("grounded")], "answerable")
        assert "provider_refusals" not in block


class TestFalseAbstention:
    def test_answerable_abstention_is_labelled_as_failure(self):
        block = aq.summarize([graded("grounded"), graded("abstained", id="x")],
                             "answerable")
        assert block["false_abstention_rate"] == 0.5
        assert block["false_abstentions"] == 1

    def test_unanswerable_abstention_is_not(self):
        """Same grade, opposite meaning. Folding both into one rate lets a
        system that refuses indiscriminately look good on one set for the wrong
        reason."""
        block = aq.summarize([graded("abstained"), graded("abstained", id="y")],
                             "unanswerable")
        assert block["abstained_rate"] == 1.0
        assert "false_abstention_rate" not in block

    def test_the_group_must_be_passed_to_be_classified(self):
        assert "false_abstention_rate" not in aq.summarize([graded("abstained")])


class TestComparisonUsesTheRightInstrument:
    """
    Each group is scored by the instrument built for it.

    Grading the unanswerable group on the three-way groundedness rubric reported
    eight regressions from a prompt change that caused none. The answers had
    moved from a bare refusal to "the corpus does not carry that, but here is
    what it does" - a better decline, which the rubric scores as "grounded"
    because it asserts supported facts. The decline judge, which exists for
    exactly this, showed 100% before and after.
    """

    def _compare(self, capsys, before, after, tmp_path):
        def write(name, records):
            path = tmp_path / name
            path.write_text(json.dumps({"records": records}), encoding="utf-8")
            return path
        aq.compare(write("before.json", before), write("after.json", after))
        return capsys.readouterr().out

    def test_a_better_decline_is_not_a_regression(self, capsys, tmp_path):
        item = {"id": "x", "question": "q", "answer": "a", "declined": True}
        out = self._compare(
            capsys,
            {"unanswerable": [{**item, "grade": "abstained"}]},
            {"unanswerable": [{**item, "grade": "grounded"}]},
            tmp_path,
        )
        assert "regressed 0" in out
        assert "1/1 = 1.000" in out

    def test_actually_answering_an_unanswerable_question_is_a_regression(
            self, capsys, tmp_path):
        item = {"id": "x", "question": "q", "answer": "a", "grade": "grounded"}
        out = self._compare(
            capsys,
            {"unanswerable": [{**item, "declined": True}]},
            {"unanswerable": [{**item, "declined": False}]},
            tmp_path,
        )
        assert "regressed 1" in out

    def test_unjudged_records_are_dropped_rather_than_scored(self, capsys,
                                                             tmp_path):
        """A record the decline judge never reached has `declined` unset.
        Counting it as 'did not decline' would invent a failure."""
        item = {"id": "x", "question": "q", "answer": "a", "grade": "grounded"}
        out = self._compare(
            capsys,
            {"unanswerable": [{**item, "declined": True}]},
            {"unanswerable": [item]},
            tmp_path,
        )
        assert "unanswerable" not in out

    def test_answerable_still_uses_the_groundedness_grade(self, capsys, tmp_path):
        out = self._compare(
            capsys,
            {"answerable": [{"id": "c", "grade": "unsupported", "answer": "a"}]},
            {"answerable": [{"id": "c", "grade": "grounded", "answer": "a"}]},
            tmp_path,
        )
        assert "fixed 1" in out


class TestPreregisteredDecisionRule:
    """
    Every branch of the rule in experiments/PREREGISTRATION.md, exercised on
    synthetic results so the rule is known to behave before it is pointed at
    data nobody can un-see.

    Two of these encode corrections found by doing exactly that. Gating
    equivalence on achieved power called one discordant pair in 157 questions
    "inconclusive" when it is the strongest equivalence evidence the design can
    produce. And keying the verdict on significance alone would flip the default
    to the slower config on a three-point win, which is a statement about
    sampling rather than about whether 587 ms buys anything.
    """

    def _decide(self, capsys, a_grades, b_grades, tmp_path):
        def write(name, grades):
            path = tmp_path / name
            path.write_text(json.dumps({"records": {"answerable": [
                {"id": f"CVE-2000-{i:04d}", "grade": g, "answer": "a"}
                for i, g in enumerate(grades)]}}), encoding="utf-8")
            return path
        result = aq.decide(write("a.json", a_grades), write("b.json", b_grades),
                           tmp_path / "decision.json")
        capsys.readouterr()
        return result

    def _split(self, grounded, n=157):
        return ["grounded"] * grounded + ["unsupported"] * (n - grounded)

    def test_challenger_wins_outright(self, capsys, tmp_path):
        r = self._decide(capsys, self._split(100), self._split(140), tmp_path)
        assert r["verdict"] == "difference"
        assert "cheaper" in r["consequence"]

    def test_incumbent_wins_by_more_than_the_threshold(self, capsys, tmp_path):
        r = self._decide(capsys, self._split(140), self._split(100), tmp_path)
        assert r["verdict"] == "difference"
        assert r["difference_interval_95"]["low"] >= aq.DECISION_DELTA
        assert "stays the default" in r["consequence"]

    def test_a_significant_but_small_win_does_not_buy_the_latency(
            self, capsys, tmp_path):
        """5 points, p < 0.05, and still not worth 587 ms per query."""
        r = self._decide(capsys, self._split(130), self._split(122), tmp_path)
        assert r["p_value"] < 0.05
        assert r["verdict"] == "difference below the threshold"
        assert "flips to bm25" in r["consequence"]

    def test_one_discordant_pair_is_equivalence_not_ignorance(
            self, capsys, tmp_path):
        a = ["grounded"] * 140 + ["unsupported"] * 17
        b = ["grounded"] * 139 + ["unsupported"] * 18
        r = self._decide(capsys, a, b, tmp_path)
        assert r["verdict"] == "equivalence"
        # A ten-point difference is not undetectable here, it is impossible.
        assert r["achieved_power_at_delta"] is None

    def test_a_noisy_null_is_inconclusive(self, capsys, tmp_path):
        a = ["grounded"] * 100 + ["unsupported"] * 57
        b = ["unsupported"] * 57 + ["grounded"] * 100
        r = self._decide(capsys, a, b, tmp_path)
        assert r["p_value"] >= 0.05
        assert r["verdict"] == "inconclusive"
        assert r["difference_interval_95"]["high"] > aq.DECISION_DELTA

    def test_provider_refusals_are_not_scored_as_failures(self, capsys,
                                                          tmp_path):
        def write(name, records):
            path = tmp_path / name
            path.write_text(json.dumps({"records": {"answerable": records}}),
                            encoding="utf-8")
            return path
        common = [{"id": "CVE-2000-0001", "grade": "grounded", "answer": "a"}]
        refused = [{"id": "CVE-2000-0002", "grade": "abstained",
                    "answer": aq.REFUSAL_PLACEHOLDER}]
        result = aq.decide(write("a.json", common + refused),
                           write("b.json", common + refused),
                           tmp_path / "decision.json")
        capsys.readouterr()
        assert result["questions"] == 1

    def test_the_threshold_matches_the_committed_rule(self):
        text = (ROOT / "experiments" / "PREREGISTRATION.md").read_text(
            encoding="utf-8")
        assert f"`Δ = {aq.DECISION_DELTA:.2f}`" in text, (
            "the code threshold and the pre-registered one have drifted"
        )


class TestPairedDifferenceInterval:
    def test_no_discordant_pairs_is_a_point(self):
        block = aq.paired_difference_interval(0, 0, 157)
        assert block["difference"] == 0.0
        assert block["half_width"] == 0.0

    def test_concordant_pairs_shrink_the_interval(self):
        """The difference is not two independent proportions subtracted:
        questions both configs get right contribute to the denominator and not
        to the variance."""
        narrow = aq.paired_difference_interval(10, 0, 500)["half_width"]
        wide = aq.paired_difference_interval(10, 0, 50)["half_width"]
        assert narrow < wide

    def test_symmetric_under_swapping_the_configs(self):
        a = aq.paired_difference_interval(12, 5, 157)
        b = aq.paired_difference_interval(5, 12, 157)
        assert a["difference"] == pytest.approx(-b["difference"])
        assert a["half_width"] == pytest.approx(b["half_width"])

    def test_variance_never_goes_negative(self):
        """(b - c)^2 / n can exceed b + c when every pair is discordant and
        one-sided; the formula has to be clamped or it takes a square root of a
        negative number."""
        block = aq.paired_difference_interval(157, 0, 157)
        assert block["half_width"] == 0.0
        assert block["difference"] == 1.0


class TestResultsPathIsAlwaysExplicit:
    def _tree(self):
        return ast.parse((ROOT / "experiments" / "answer_quality.py")
                         .read_text(encoding="utf-8"))

    @pytest.mark.parametrize("name", ["load_state", "write_state", "report"])
    def test_the_path_parameter_has_no_default(self, name):
        """A default here is what let a run write its results over the file it
        was being compared against, while reporting success."""
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                args = node.args
                index = [a.arg for a in args.args].index("results_path")
                # Defaults align to the tail of the positional list.
                first_defaulted = len(args.args) - len(args.defaults)
                assert index < first_defaulted, (
                    f"{name}(results_path=...) has a default; omitting it at a "
                    "call site would silently write to the wrong file"
                )
                return
        pytest.fail(f"{name} not found")

    def test_every_call_site_passes_it(self):
        required = {"load_state": 1, "report": 1, "write_state": 3}
        missing = []
        for node in ast.walk(self._tree()):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in required):
                supplied = len(node.args) + len(node.keywords)
                if supplied < required[node.func.id]:
                    missing.append(f"{node.func.id} at line {node.lineno}")
        assert not missing, f"calls without an explicit results path: {missing}"

    def test_the_module_default_is_only_a_cli_default(self):
        """RESULTS_PATH should survive only as the argparse default, where an
        explicit value always reaches the functions."""
        source = (ROOT / "experiments" / "answer_quality.py").read_text(
            encoding="utf-8")
        uses = [line.strip() for line in source.splitlines()
                if "RESULTS_PATH" in line and not line.strip().startswith("#")]
        assert len(uses) == 2, uses           # the definition and the CLI default
        assert any("default=str(RESULTS_PATH)" in u for u in uses)


class TestRefusalAggregation:
    """
    Denominators. Both of the ones this file started with were wrong, in
    opposite directions: the per-run rate counted calibration records, which
    involve no generation call at all, and the ledger rate counted every call
    ever made against refusals only observable since `stop_reason` was recorded.
    """

    def _module(self):
        import refusals
        return refusals

    def test_calibration_records_are_not_generation_attempts(self, tmp_path,
                                                             monkeypatch):
        refusals = self._module()
        (tmp_path / "answer_quality_x.json").write_text(json.dumps({
            "records": {
                "answerable": [{"id": "a", "answer": "real"},
                               {"id": "b", "answer": aq.REFUSAL_PLACEHOLDER}],
                "unanswerable": [{"id": "c", "answer": "real"}],
                "calibration_corrupted": [{"id": f"k{i}", "answer": "x"}
                                          for i in range(20)],
            }}), encoding="utf-8")
        monkeypatch.setattr(refusals, "RESULTS_DIR", tmp_path)
        run = refusals.from_answer_runs()[0]
        assert run["attempted"] == 3      # not 23
        assert run["refused"] == 1

    def test_a_copied_results_file_is_not_a_second_observation(self, tmp_path,
                                                               monkeypatch):
        refusals = self._module()
        payload = json.dumps({"records": {"answerable": [
            {"id": "a", "answer": aq.REFUSAL_PLACEHOLDER}]}})
        for name in ("answer_quality.json", "answer_quality_prompt_v1.json"):
            (tmp_path / name).write_text(payload, encoding="utf-8")
        monkeypatch.setattr(refusals, "RESULTS_DIR", tmp_path)
        assert len(refusals.from_answer_runs()) == 1

    def test_named_and_embedded_refusals_are_not_double_counted(self, tmp_path,
                                                                monkeypatch):
        """The harness names refusals in generation_failures now and used to
        persist them as records. A file holding both must not count twice."""
        refusals = self._module()
        (tmp_path / "answer_quality_y.json").write_text(json.dumps({
            "generation_failures": ["b"],
            "records": {"answerable": [
                {"id": "a", "answer": "real"},
                {"id": "b", "answer": aq.REFUSAL_PLACEHOLDER}]},
        }), encoding="utf-8")
        monkeypatch.setattr(refusals, "RESULTS_DIR", tmp_path)
        run = refusals.from_answer_runs()[0]
        assert run["refused"] == 1
        assert run["attempted"] == 2

    def test_ledger_rate_is_over_calls_that_recorded_a_stop_reason(self,
                                                                   tmp_path):
        import api_ledger
        path = tmp_path / "ledger.jsonl"
        rows = ([{"model": "m", "purpose": "p"}] * 10          # before the field
                + [{"model": "m", "purpose": "p", "stop_reason": "end_turn"}] * 9
                + [{"model": "m", "purpose": "p", "stop_reason": "refusal"}])
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        totals = api_ledger.summarize(path)["totals"]
        assert totals["calls"] == 20
        assert totals["calls_with_stop_reason"] == 10
        assert totals["refusals"] == 1      # 1 in 10, not 1 in 20


class TestNothingWritesIntoCommittedResults:
    """
    A test suite that writes into experiments/results/ can destroy a
    measurement that cost real money, and does it silently, because the console
    output of the real run was correct at the time.

    That is not hypothetical either. `decide()` wrote to a module constant, the
    tests below exercised all five branches of the rule on synthetic data, and
    the last one to run left a one-question verdict in config_decision.json
    where a 142-question one had been. It was caught by reading the artifact
    instead of trusting the terminal.

    Both fixes are structural: the output path is a required argument, and this
    test fails if any experiment function grows a default that points inside the
    results directory.
    """

    def _experiment_sources(self):
        for path in sorted((ROOT / "experiments").glob("*.py")):
            yield path, ast.parse(path.read_text(encoding="utf-8"))

    def test_no_writing_function_defaults_to_the_results_directory(self):
        """A default output path is what turns a test run into data loss."""
        offenders = []
        for path, tree in self._experiment_sources():
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef):
                    continue
                names = [a.arg for a in node.args.args]
                defaults = node.args.defaults
                first_defaulted = len(names) - len(defaults)
                for index, name in enumerate(names):
                    if index < first_defaulted:
                        continue
                    if not any(k in name for k in ("out", "path", "dest")):
                        continue
                    default = defaults[index - first_defaulted]
                    rendered = ast.dump(default)
                    if "RESULTS_DIR" in rendered or "RESULTS_PATH" in rendered:
                        offenders.append(
                            f"{path.name}:{node.lineno} {node.name}({name}=...)")
        assert not offenders, (
            "these default to a committed results path, so calling them from a "
            f"test overwrites a real measurement: {offenders}"
        )

    def test_the_results_directory_is_untouched_by_this_suite(self, tmp_path):
        """End-to-end: run the rule and confirm the real artifact is unchanged."""
        real = ROOT / "experiments" / "results" / "config_decision.json"
        before = real.read_text(encoding="utf-8") if real.exists() else None

        def write(name, grades):
            path = tmp_path / name
            path.write_text(json.dumps({"records": {"answerable": [
                {"id": f"CVE-2000-{i:04d}", "grade": g, "answer": "a"}
                for i, g in enumerate(grades)]}}), encoding="utf-8")
            return path
        aq.decide(write("a.json", ["grounded"] * 3),
                  write("b.json", ["grounded"] * 3),
                  tmp_path / "decision.json")

        after = real.read_text(encoding="utf-8") if real.exists() else None
        assert after == before, "the test suite just overwrote a real result"

    def test_decide_requires_an_explicit_destination(self):
        for path, tree in self._experiment_sources():
            if path.name != "answer_quality.py":
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "decide":
                    names = [a.arg for a in node.args.args]
                    first_defaulted = len(names) - len(node.args.defaults)
                    assert names.index("out_path") < first_defaulted
                    return
        pytest.fail("decide() not found")


class TestCommittedArtifactsAgree:
    """The published numbers must be what summarize() produces today."""

    @pytest.mark.parametrize("name", [
        "answer_quality.json",
        "answer_quality_prompt_v1.json",
        "answer_quality_prompt_v2.json",
    ])
    def test_stored_summary_matches_a_fresh_one(self, name):
        path = ROOT / "experiments" / "results" / name
        if not path.exists():
            pytest.skip(f"{name} not present")
        payload = json.loads(path.read_text(encoding="utf-8"))
        fresh = {g: aq.summarize(v, g)
                 for g, v in payload["records"].items() if v}
        assert payload.get("summary") == fresh, (
            f"{name} carries a stale summary; re-run --report or rebuild it"
        )

    def test_the_baseline_excludes_its_two_refusals(self):
        path = ROOT / "experiments" / "results" / "answer_quality.json"
        block = json.loads(path.read_text(encoding="utf-8"))["summary"]["answerable"]
        assert block["provider_refusals"] == 2
        assert block["answers"] == 16
        assert block["false_abstention_rate"] == 0.0
