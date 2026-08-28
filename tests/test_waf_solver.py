import unittest

from waf_solver import (
    InvalidChallengeError,
    SolverExecutionError,
    WafChallenge,
    parse_aws_waf_challenge,
    solve_aws_waf_challenge,
)


HTML = """
<html><script>window.gokuProps = {"key":"value", "nested": {"number": 1}};</script>
<script defer src='https://abc.example.test/challenge.js?cache=1'></script></html>
"""


class WafSolverTests(unittest.TestCase):
    def test_parse_challenge(self):
        self.assertEqual(
            parse_aws_waf_challenge(HTML),
            WafChallenge(
                goku_props={"key": "value", "nested": {"number": 1}},
                endpoint="abc.example.test",
            ),
        )

    def test_rejects_missing_or_malformed_values(self):
        invalid_pages = (
            "",
            '<script src="https://example.test/challenge.js"></script>',
            'window.gokuProps = {bad}; <script src="https://x/challenge.js"></script>',
            'window.gokuProps = {}; <script src="http://x/challenge.js"></script>',
        )
        for page in invalid_pages:
            with self.subTest(page=page), self.assertRaises(InvalidChallengeError):
                parse_aws_waf_challenge(page)

    def test_passes_challenge_to_backend(self):
        received = {}

        def factory(**kwargs):
            received.update(kwargs)
            return lambda: " token-value "

        token = solve_aws_waf_challenge(
            HTML, "test-agent", domain="app.example.test", solver_factory=factory
        )

        self.assertEqual(token, "token-value")
        self.assertEqual(
            received["goku_props"], {"key": "value", "nested": {"number": 1}}
        )
        self.assertEqual(received["endpoint"], "abc.example.test")
        self.assertEqual(received["domain"], "app.example.test")
        self.assertEqual(received["user_agent"], "test-agent")

    def test_wraps_backend_errors(self):
        def factory(**_kwargs):
            def fail():
                raise RuntimeError("sensitive backend detail")

            return fail

        with self.assertRaises(SolverExecutionError) as raised:
            solve_aws_waf_challenge(HTML, "test-agent", solver_factory=factory)
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)

    def test_rejects_empty_backend_token(self):
        with self.assertRaises(SolverExecutionError):
            solve_aws_waf_challenge(
                HTML, "test-agent", solver_factory=lambda **_kwargs: lambda: "  "
            )

    def test_requires_user_agent(self):
        with self.assertRaises(ValueError):
            solve_aws_waf_challenge(HTML, "")


if __name__ == "__main__":
    unittest.main()
