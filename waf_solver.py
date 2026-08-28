"""AWS WAF challenge response parsing and solver integration.

The challenge algorithm itself is supplied by the optional ``awswaf`` package.
Keeping the integration in this small module makes challenge-page format errors
distinguishable from backend/runtime errors and makes the code testable without
performing a network request.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse


class WafSolverError(RuntimeError):
    """Base error raised by the AWS WAF solver integration."""


class InvalidChallengeError(WafSolverError):
    """Raised when a response is not a supported AWS WAF challenge page."""


class SolverUnavailableError(WafSolverError):
    """Raised when the optional solver backend is not installed."""


class SolverExecutionError(WafSolverError):
    """Raised when the backend cannot produce a valid token."""


class SolverBackend(Protocol):
    def __call__(self) -> str: ...


SolverFactory = Callable[..., SolverBackend]


@dataclass(frozen=True)
class WafChallenge:
    """Values embedded in an AWS WAF challenge page."""

    goku_props: Mapping[str, Any]
    endpoint: str


_GOKU_PROPS_START = re.compile(r"(?:window\s*\.\s*)?gokuProps\s*=\s*")
_CHALLENGE_SCRIPT = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*(['\"])(https://[^'\"]+/challenge\.js(?:\?[^'\"]*)?)\1",
    re.IGNORECASE,
)


def parse_aws_waf_challenge(html_response: str) -> WafChallenge:
    """Extract and validate solver inputs from an AWS WAF challenge page."""
    if not isinstance(html_response, str) or not html_response.strip():
        raise InvalidChallengeError("AWS WAF challenge response is empty")

    props_match = _GOKU_PROPS_START.search(html_response)
    if props_match is None:
        raise InvalidChallengeError("AWS WAF gokuProps was not found")

    try:
        goku_props, _ = json.JSONDecoder().raw_decode(
            html_response, props_match.end()
        )
    except json.JSONDecodeError as exc:
        raise InvalidChallengeError("AWS WAF gokuProps is not valid JSON") from exc
    if not isinstance(goku_props, dict):
        raise InvalidChallengeError("AWS WAF gokuProps must be a JSON object")

    script_match = _CHALLENGE_SCRIPT.search(html_response)
    if script_match is None:
        raise InvalidChallengeError("AWS WAF challenge.js URL was not found")

    script_url = script_match.group(2)
    parsed_url = urlparse(script_url)
    if parsed_url.scheme != "https" or not parsed_url.hostname:
        raise InvalidChallengeError("AWS WAF challenge.js URL is invalid")

    return WafChallenge(goku_props=goku_props, endpoint=parsed_url.netloc)


def _default_solver_factory() -> SolverFactory:
    try:
        from awswaf.aws import AwsWaf
    except ImportError as exc:
        raise SolverUnavailableError(
            "AWS WAF solver backend is unavailable; install a compatible "
            "'awswaf' package"
        ) from exc
    return AwsWaf


def solve_aws_waf_challenge(
    html_response: str,
    user_agent: str,
    *,
    domain: str = "www.paypay.ne.jp",
    solver_factory: SolverFactory | None = None,
) -> str:
    """Parse a challenge, invoke the configured backend, and return its token."""
    if not isinstance(user_agent, str) or not user_agent.strip():
        raise ValueError("user_agent must be a non-empty string")
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")

    challenge = parse_aws_waf_challenge(html_response)
    factory = solver_factory or _default_solver_factory()

    try:
        solver = factory(
            goku_props=dict(challenge.goku_props),
            endpoint=challenge.endpoint,
            domain=domain,
            user_agent=user_agent,
        )
        token = solver()
    except WafSolverError:
        raise
    except Exception as exc:
        raise SolverExecutionError("AWS WAF solver backend failed") from exc

    if not isinstance(token, str) or not token.strip():
        raise SolverExecutionError("AWS WAF solver backend returned an empty token")
    return token.strip()
