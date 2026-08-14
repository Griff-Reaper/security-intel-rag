"""
Tests for what the answer model is shown and what it is permitted to add.

Both halves of this were measured defects rather than hypotheticals. The index
carried a CVSS vector, a KEV listing and an EPSS score that the prompt never
included, and the system prompt asked for actionable recommendations grounded in
records that did not contain any. Five of eighteen answers were graded
unsupported, all of them the same way.

The judge-parity test is the important one here. The last time context building
drifted between the model's call site and the judge's, the judge was shown less
than the model and reported hallucinated publication dates that had been in the
prompt the whole time. `enrichment` is a keyword argument with a default, which
makes exactly that drift silent again, so it is asserted rather than assumed.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "config"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import prompts  # noqa: E402
import provenance  # noqa: E402

SNAPSHOT = {"kev_catalog": "2026.08.11", "epss_date": "2026-08-13"}

BASE_META = {
    "type": "cve",
    "cve_id": "CVE-2009-2073",
    "severity": "MEDIUM",
    "cvss_base_score": 6.8,
    "cvss_version": "2.0",
    "cvss_vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
    "published": "2009-06-16T16:30:00.000",
    "cwe_ids": "CWE-352",
}


def render(meta, doc="A vulnerability.", enrichment=SNAPSHOT):
    return prompts.format_context_documents([doc], [meta], enrichment=enrichment)


class TestCvssVector:
    def test_the_vector_reaches_the_model(self):
        """Three of the five unsupported answers reasoned about attack
        complexity and user interaction from the base score alone, because the
        vector stating them was indexed and withheld."""
        assert "AV:N/AC:M/Au:N/C:P/I:P/A:P" in render(BASE_META)

    def test_the_score_is_still_shown(self):
        assert "6.8" in render(BASE_META)

    def test_absent_vector_renders_nothing(self):
        meta = {k: v for k, v in BASE_META.items() if k != "cvss_vector"}
        assert "CVSS vector" not in render(meta)

    def test_an_unscored_cve_does_not_claim_a_score(self):
        meta = {"type": "cve", "cve_id": "CVE-2020-0001"}
        out = render(meta)
        assert "not scored" in out
        assert "CVSS vector" not in out


class TestExploitationStatus:
    def test_listed_is_stated_with_the_catalog_version(self):
        out = render({**BASE_META, "kev": True})
        assert "Known Exploited" in out
        assert "2026.08.11" in out

    def test_ransomware_use_is_only_claimed_when_recorded(self):
        assert "ransomware" in render({**BASE_META, "kev": True,
                                       "kev_ransomware": True})
        assert "ransomware" not in render({**BASE_META, "kev": True,
                                           "kev_ransomware": False})

    def test_a_checked_negative_is_stated(self):
        out = render({**BASE_META, "kev": False})
        assert "not listed" in out

    def test_an_unenriched_record_says_nothing_either_way(self):
        """False and missing are different findings. A record never checked
        against the catalog must not render as 'not listed', which would be a
        claim the data does not support."""
        out = render(BASE_META)
        assert "Known Exploited" not in out
        assert "not listed" not in out

    def test_epss_is_labelled_as_a_prediction(self):
        out = render({**BASE_META, "epss_score": 0.0421, "epss_percentile": 0.912})
        assert "0.0421" in out
        assert "0.912" in out
        assert "predicted" in out.lower()
        assert "2026-08-13" in out

    def test_epss_of_zero_is_still_reported(self):
        """A falsy score is a measurement, not a missing field."""
        assert "EPSS" in render({**BASE_META, "epss_score": 0.0})

    def test_snapshot_qualifiers_are_omitted_when_unknown(self):
        out = render({**BASE_META, "kev": True, "epss_score": 0.5},
                     enrichment=None)
        assert "Known Exploited" in out
        assert "version" not in out
        assert "scored" not in out


class TestEnrichmentSnapshot:
    def test_reads_the_manifest(self):
        snapshot = provenance.enrichment_snapshot()
        assert "kev_catalog" in snapshot
        assert "epss_date" in snapshot
        assert len(snapshot["epss_date"]) == 10, "date, not a full timestamp"

    def test_a_missing_manifest_is_not_an_error(self, tmp_path):
        assert provenance.enrichment_snapshot(tmp_path / "nope.json") == {}

    def test_partial_enrichment_yields_partial_qualifiers(self, tmp_path):
        import json
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps({"exploitation": {"epss": {
            "score_date": "2026-08-13T12:03:51Z"}}}), encoding="utf-8")
        snapshot = provenance.enrichment_snapshot(path)
        assert snapshot == {"epss_date": "2026-08-13"}


class TestSystemPrompt:
    def test_no_longer_asks_for_actionable_recommendations(self):
        """The instruction that produced invented exploitation mechanics."""
        assert "actionable recommendations" not in \
            prompts.SECURITY_ANALYST_SYSTEM_PROMPT.lower()

    def test_forbids_expanding_cwe_identifiers(self):
        text = prompts.SECURITY_ANALYST_SYSTEM_PROMPT.lower()
        assert "cwe" in text
        assert "identifiers are not definitions" in text

    def test_permits_reading_a_vector_but_not_inferring_from_a_score(self):
        text = prompts.SECURITY_ANALYST_SYSTEM_PROMPT
        assert "vector string" in text
        assert "from a score alone" in text

    def test_restraint_is_not_a_licence_to_refuse(self):
        """The over-correction guard. Tightening the prompt against elaboration
        risks buying groundedness with false abstentions, which the harness now
        reports as its own number."""
        assert "answer the question, answer it" in \
            prompts.SECURITY_ANALYST_SYSTEM_PROMPT


class TestCveTemplate:
    def test_no_longer_claims_the_corpus_lacks_exploitation_status(self):
        """It has carried KEV and EPSS since Phase 3. Telling the model
        otherwise is an instruction to refuse an answerable question."""
        text = prompts.CVE_ANALYSIS_TEMPLATE
        assert "does not include exploitation" not in text
        assert "KEV" in text or "Known exploited" in text

    def test_still_refuses_attack_mappings_and_patch_advice(self):
        text = prompts.CVE_ANALYSIS_TEMPLATE
        assert "ATT&CK" in text
        assert "patch instructions" in text

    def test_distinguishes_observed_from_predicted_exploitation(self):
        text = prompts.CVE_ANALYSIS_TEMPLATE
        assert "observed" in text
        assert "predicted probability" in text

    def test_says_an_absent_field_is_not_a_negative_finding(self):
        assert "not the same as a negative finding" in prompts.CVE_ANALYSIS_TEMPLATE

    def test_formats_without_error(self):
        out = prompts.CVE_ANALYSIS_TEMPLATE.format(context="CTX", query="Q")
        assert "CTX" in out and "Q" in out


class TestJudgeSeesWhatTheModelSees:
    """The structural guard against the instrument bug, not a behaviour test."""

    def _sources(self):
        import inspect
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent
        return {
            "model": (root / "src" / "query.py").read_text(encoding="utf-8"),
            "judge": (root / "experiments" / "answer_quality.py").read_text(
                encoding="utf-8"),
        }

    def test_both_call_sites_pass_the_enrichment_snapshot(self):
        import re
        for name, text in self._sources().items():
            calls = re.findall(r"format_context_documents\((?:[^()]|\([^()]*\))*\)",
                               text, re.DOTALL)
            # Prose mentions the function by name with empty parentheses; a real
            # call passes documents and metadatas, so it has a comma in it.
            calls = [c for c in calls if "," in c]
            assert calls, f"no formatting call found in {name}"
            for call in calls:
                assert "enrichment" in call, (
                    f"{name} builds context without the enrichment snapshot; the "
                    "judge and the model would see different prompts"
                )

    def test_the_default_would_silently_drop_it(self):
        """Documents why the test above exists: omitting the argument is legal
        and produces a subtly different prompt rather than an error."""
        meta = {**BASE_META, "kev": True}
        assert prompts.format_context_documents(["d"], [meta]) != \
            prompts.format_context_documents(["d"], [meta], enrichment=SNAPSHOT)
