"""
One place that knows how to construct the Anthropic client.

This exists because of a failure that took a while to diagnose. The environment
had `anthropic` 0.34.0 installed while requirements.txt asked for >= 0.121.0 -
the pin had simply never been enforced there. Version 0.34.0 predates thinking
blocks, so when Opus returned a response containing one, the SDK raised

    AttributeError: 'typing.Union' object has no attribute '__discriminator__'

deep inside response parsing. That reads like an API problem or a bug in this
project. It was neither, and nothing about the message points at the real cause.

A version pin cannot catch this on its own: an unenforced pin fails silently by
definition. A runtime assertion can, so the check runs at client construction
and names the installed version, the required version, and the fix.

Both callers - src/query.py and experiments/build_eval_set.py - go through
build_client(), so neither can acquire an unchecked client.
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from anthropic import Anthropic

# The first release that parses thinking blocks. Below this, any response from a
# reasoning model fails to deserialize.
MIN_ANTHROPIC_VERSION = (0, 121, 0)


class UnsupportedSDKError(RuntimeError):
    """Raised when the installed anthropic SDK is too old to parse responses."""


def installed_version() -> str:
    try:
        import importlib.metadata as metadata

        return metadata.version("anthropic")
    except Exception:  # noqa: BLE001 - fall back to the module attribute
        import anthropic

        return getattr(anthropic, "__version__", "unknown")


def _parse(version: str) -> Optional[Tuple[int, ...]]:
    """Numeric release components, or None if the string is not parseable."""
    parts = []
    for chunk in version.split(".")[:3]:
        digits = "".join(c for c in chunk if c.isdigit())
        if not digits:
            return None
        parts.append(int(digits))
    return tuple(parts) if parts else None


def require_supported_sdk() -> str:
    """
    Fail loudly if the installed SDK cannot parse modern responses.

    Raises:
        UnsupportedSDKError: The installed version is below MIN_ANTHROPIC_VERSION.
    """
    version = installed_version()
    parsed = _parse(version)
    minimum = ".".join(str(p) for p in MIN_ANTHROPIC_VERSION)
    if parsed is None:
        # Unparseable is not a failure: pre-release and vendored builds exist,
        # and refusing to start over a version string would be worse than the
        # bug this guards against.
        return version
    if parsed < MIN_ANTHROPIC_VERSION:
        raise UnsupportedSDKError(
            f"anthropic {version} is installed but >= {minimum} is required.\n"
            f"Releases before {minimum} cannot parse the thinking blocks that "
            f"current models return, and fail with an AttributeError inside "
            f"response parsing rather than a clear error.\n"
            f"Fix: pip install -r requirements.txt"
        )
    return version


def build_client(api_key: Optional[str] = None) -> Anthropic:
    """Construct a checked Anthropic client.

    Raises:
        UnsupportedSDKError: The SDK is too old.
        ValueError: No API key available.
    """
    require_supported_sdk()
    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment!")
    return Anthropic(api_key=key)
