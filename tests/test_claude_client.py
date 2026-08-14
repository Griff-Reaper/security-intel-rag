"""
Tests for the Anthropic SDK version guard.

The bug this guards against was silent in the worst way: requirements.txt asked
for >= 0.121.0, the environment had 0.34.0, and nothing complained until a model
returned a thinking block and the SDK raised an AttributeError from inside
response parsing. The pin did not fail - it had simply never been applied.

So the guard is tested for the property that matters: it must fire on an old
version, stay quiet on a current one, and never refuse to start over a version
string it merely cannot parse.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import claude_client as cc


class TestVersionParsing:
    @pytest.mark.parametrize("text,expected", [
        ("0.34.0", (0, 34, 0)),
        ("0.122.0", (0, 122, 0)),
        ("1.2.3", (1, 2, 3)),
        ("0.121.0b1", (0, 121, 1)),
        ("2.0", (2, 0)),
    ])
    def test_parses_release_components(self, text, expected):
        assert cc._parse(text) == expected

    @pytest.mark.parametrize("text", ["", "unknown", "not.a.version"])
    def test_unparseable_returns_none(self, text):
        assert cc._parse(text) is None

    def test_ordering_is_numeric_not_lexicographic(self):
        """0.34.0 must sort below 0.122.0; as strings it would not."""
        assert cc._parse("0.34.0") < cc._parse("0.122.0")


class TestGuard:
    def test_the_installed_sdk_passes(self):
        assert cc.require_supported_sdk()

    def test_an_old_version_raises_with_the_fix(self, monkeypatch):
        monkeypatch.setattr(cc, "installed_version", lambda: "0.34.0")
        with pytest.raises(cc.UnsupportedSDKError) as exc:
            cc.require_supported_sdk()
        message = str(exc.value)
        assert "0.34.0" in message
        assert "0.121.0" in message
        assert "pip install -r requirements.txt" in message
        # The message must name the real symptom, or the next person greps for
        # the AttributeError and finds nothing.
        assert "thinking blocks" in message

    def test_the_exact_minimum_passes(self, monkeypatch):
        monkeypatch.setattr(cc, "installed_version", lambda: "0.121.0")
        assert cc.require_supported_sdk() == "0.121.0"

    def test_one_release_below_the_minimum_fails(self, monkeypatch):
        monkeypatch.setattr(cc, "installed_version", lambda: "0.120.9")
        with pytest.raises(cc.UnsupportedSDKError):
            cc.require_supported_sdk()

    def test_an_unparseable_version_does_not_block_startup(self, monkeypatch):
        """Refusing to run over a version string would be worse than the bug."""
        monkeypatch.setattr(cc, "installed_version", lambda: "custom-build")
        assert cc.require_supported_sdk() == "custom-build"


class TestBuildClient:
    def test_missing_api_key_is_a_clear_error(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            cc.build_client()

    def test_the_version_check_runs_before_the_key_check(self, monkeypatch):
        """An old SDK is the more actionable failure, so it should surface first."""
        monkeypatch.setattr(cc, "installed_version", lambda: "0.34.0")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(cc.UnsupportedSDKError):
            cc.build_client()

    def test_explicit_key_is_accepted(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert cc.build_client(api_key="sk-test-not-a-real-key") is not None


class TestCallSitesAreGuarded:
    """Every module that talks to Claude must go through the factory."""

    def test_no_direct_client_construction_outside_the_factory(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parent.parent
        offenders = []
        for path in list((root / "src").rglob("*.py")) + \
                    list((root / "experiments").rglob("*.py")):
            if path.name == "claude_client.py":
                continue
            text = path.read_text(encoding="utf-8")
            if re.search(r"\bAnthropic\s*\(", text):
                offenders.append(str(path.relative_to(root)))
        assert not offenders, (
            f"these construct an unchecked Anthropic client: {offenders}. "
            "Use claude_client.build_client()."
        )
