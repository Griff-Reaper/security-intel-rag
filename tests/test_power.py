"""
Tests for the sample-size arithmetic.

This module decides how much money the answer-quality runs cost and what the
resulting nulls are allowed to claim, so it gets the same treatment as the
retrieval code: the fast path is checked against the slow definition, the
rejection rule is checked against the test that actually runs, and the boundary
cases are pinned by hand-computable values rather than by whatever the code
happened to return the first time.
"""

import math
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "experiments"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import power as P  # noqa: E402
import significance  # noqa: E402


class TestBinomialPmf:
    def test_sums_to_one(self):
        for n, p in ((10, 0.5), (37, 0.109), (200, 0.8)):
            total = sum(P._binom_pmf(k, n, p) for k in range(n + 1))
            assert total == pytest.approx(1.0, abs=1e-9)

    def test_known_value(self):
        # Three heads in five fair flips: C(5,3)/32 = 10/32
        assert P._binom_pmf(3, 5, 0.5) == pytest.approx(10 / 32)

    def test_survives_large_n(self):
        """math.comb is exact but overflows float conversion here; log space
        was adopted after exactly this input raised OverflowError."""
        assert P._binom_pmf(500, 2000, 0.25) > 0

    @pytest.mark.parametrize("p,k,expected", [(0.0, 0, 1.0), (0.0, 3, 0.0),
                                             (1.0, 5, 1.0), (1.0, 2, 0.0)])
    def test_degenerate_probabilities(self, p, k, expected):
        assert P._binom_pmf(k, 5, p) == expected


class TestExactPValue:
    def test_matches_the_test_that_actually_runs(self):
        """The power calculation must reject on src/significance.py's rule, not
        on its own. Any drift here silently misprices every run."""
        for discordant in range(0, 40):
            for wins_a in range(discordant + 1):
                mine = P.two_sided_exact_p(wins_a, discordant)
                theirs = significance.exact_binomial_two_sided(
                    min(wins_a, discordant - wins_a), discordant)
                assert mine == pytest.approx(theirs, abs=1e-12), (
                    f"disagreement at {wins_a}/{discordant}")

    def test_no_discordant_pairs_is_not_evidence(self):
        assert P.two_sided_exact_p(0, 0) == 1.0

    def test_symmetric(self):
        for discordant in range(1, 25):
            for wins_a in range(discordant + 1):
                assert P.two_sided_exact_p(wins_a, discordant) == pytest.approx(
                    P.two_sided_exact_p(discordant - wins_a, discordant))


class TestCriticalRegion:
    def test_threshold_form_matches_brute_force(self):
        """The fast two-tail threshold must select exactly the splits whose
        p-value rejects."""
        for discordant in range(0, 60):
            fast = set(P.critical_region(discordant))
            slow = {b for b in range(discordant + 1)
                    if P.rejects(b, discordant)}
            assert fast == slow, f"mismatch at m={discordant}"

    @pytest.mark.parametrize("discordant", [0, 1, 2, 3, 4, 5])
    def test_below_six_pairs_the_test_cannot_fire(self, discordant):
        """A clean sweep of five pairs gives p = 2/32 = 0.0625. No split
        rejects, so a comparison resting on five discordant pairs reports
        'not significant' regardless of what it saw."""
        assert P.critical_region(discordant) == []
        assert P.critical_threshold(discordant) == -1

    def test_six_pairs_rejects_only_on_a_sweep(self):
        # 2 * (1/64) = 0.03125 < 0.05; one dissenter gives 2 * (7/64) = 0.219
        assert P.critical_region(6) == [0, 6]

    def test_power_is_zero_when_nothing_can_reject(self):
        assert P.power_given_discordant(5, psi=1.0) == 0.0

    def test_a_sweep_of_six_is_detected_when_the_effect_is_total(self):
        assert P.power_given_discordant(6, psi=1.0) == pytest.approx(1.0)


class TestPsiForDelta:
    def test_no_difference_means_an_even_split(self):
        assert P.psi_for_delta(0.0, 0.109) == pytest.approx(0.5)

    def test_a_difference_equal_to_the_discordance_is_a_clean_sweep(self):
        assert P.psi_for_delta(0.109, 0.109) == pytest.approx(1.0)

    def test_a_difference_larger_than_the_discordance_is_impossible(self):
        """Agreeing pairs contribute nothing to the marginal difference, so the
        difference cannot exceed the share of pairs that disagree. This is the
        ceiling the config comparison runs into."""
        assert P.psi_for_delta(0.15, 0.109) is None

    def test_zero_discordance_admits_no_difference(self):
        assert P.psi_for_delta(0.01, 0.0) is None

    def test_round_trips_to_the_marginal_difference(self):
        for delta in (0.01, 0.05, 0.1):
            psi = P.psi_for_delta(delta, 0.2)
            assert 0.2 * (2 * psi - 1) == pytest.approx(delta)


class TestPower:
    def test_rises_with_sample_size(self):
        psi = P.psi_for_delta(0.05, 0.109)
        values = [P.power(n, 0.109, psi) for n in (50, 100, 200, 400)]
        assert values == sorted(values)
        assert values[0] < values[-1]

    def test_rises_with_effect_size(self):
        values = [P.power(200, 0.109, P.psi_for_delta(d, 0.109))
                  for d in (0.02, 0.05, 0.08)]
        assert values == sorted(values)

    def test_a_true_null_rejects_at_about_the_nominal_rate(self):
        """Under psi = 0.5 the rejection rate is the type I error. The exact
        test is conservative on discrete data, so this sits at or below alpha
        and never above it."""
        rate = P.power(200, 0.109, 0.5)
        assert 0.0 < rate <= P.ALPHA

    def test_lower_discordance_helps_at_a_fixed_difference(self):
        """The counterintuitive half of this calculation, and the reason the
        planned run is better powered than a first look suggests: fewer
        discordant pairs means any given marginal difference must be more
        lopsided among them, which is easier to detect, not harder."""
        tight = P.power(200, 0.10, P.psi_for_delta(0.05, 0.10))
        loose = P.power(200, 0.30, P.psi_for_delta(0.05, 0.30))
        assert tight > loose

    def test_bounded(self):
        for psi in (0.5, 0.75, 1.0):
            assert 0.0 <= P.power(150, 0.109, psi) <= 1.0

    def test_the_window_does_not_change_the_answer(self):
        """power() sums over a ten-sigma window instead of every possible
        discordant count. The truncation must be invisible at the precision
        anything is reported to."""
        n, d, psi = 120, 0.109, 0.9
        windowed = P.power(n, d, psi)
        exhaustive = sum(P._binom_pmf(m, n, d) * P.power_given_discordant(m, psi)
                         for m in range(n + 1))
        assert windowed == pytest.approx(exhaustive, abs=1e-9)


class TestRequiredN:
    def test_is_the_smallest_sufficient_sample(self):
        d, delta = 0.109, 0.075
        n = P.required_n(delta, d)
        psi = P.psi_for_delta(delta, d)
        assert P.power(n, d, psi) >= P.TARGET_POWER
        assert P.power(n - 1, d, psi) < P.TARGET_POWER

    def test_smaller_differences_need_larger_samples(self):
        sizes = [P.required_n(d, 0.109) for d in (0.10, 0.075, 0.05)]
        assert sizes == sorted(sizes)

    def test_impossible_differences_have_no_answer(self):
        assert P.required_n(0.20, 0.109) is None

    def test_unreachable_within_the_cap_returns_none(self):
        assert P.required_n(0.0001, 0.109, cap=500) is None


class TestIntervals:
    def test_wald_matches_the_hand_calculation(self):
        """The figure the README quoted: 11 of 18 grounded."""
        block = P.wald(11, 18)
        assert block["point"] == pytest.approx(0.611, abs=5e-4)
        assert block["standard_error"] == pytest.approx(0.115, abs=5e-4)
        assert block["half_width_95"] == pytest.approx(0.225, abs=5e-4)

    def test_wilson_is_inside_zero_and_one_where_wald_is_not(self):
        """2 of 18: the normal approximation runs off the bottom of the scale
        and has to be clamped, which is why Wilson is what gets quoted."""
        assert P.wald(2, 18)["low"] == 0.0          # clamped from negative
        assert P.wilson(2, 18)["low"] > 0.0

    def test_wilson_never_leaves_the_unit_interval(self):
        for n in (5, 18, 132, 264):
            for k in range(n + 1):
                block = P.wilson(k, n)
                assert 0.0 <= block["low"] <= block["high"] <= 1.0

    def test_intervals_narrow_as_the_sample_grows(self):
        widths = [P.wilson(round(0.611 * n), n)["width"]
                  for n in (18, 132, 264, 528)]
        assert widths == sorted(widths, reverse=True)

    def test_the_unsupported_interval_is_nearly_uninformative(self):
        """5 of 18 unsupported spans roughly one in eight to one in two. The
        README gloss has to survive this bracket, not the point estimate."""
        block = P.wilson(5, 18)
        assert block["low"] == pytest.approx(0.125, abs=0.005)
        assert block["high"] == pytest.approx(0.509, abs=0.005)


class TestReportedFiguresAreReproducible:
    """Whatever the README says about power must come from running this file."""

    def test_the_generation_depth_matches_the_answer_harness(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                        "experiments"))
        import answer_quality
        assert P.GENERATION_DEPTH == answer_quality.N_RETRIEVED, (
            "the power calculation assumes a retrieval depth the answer "
            "harness does not use"
        )
