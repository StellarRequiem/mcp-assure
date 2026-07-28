"""Control-plane v1: packs, purple, integrations, verity soft hook."""

from __future__ import annotations

import unittest
from unittest import mock

from mcp_assure import AssureEngine, AssuredRunner, ToolCall
from mcp_assure.integrations import AssuredToolDispatcher, assure_callable
from mcp_assure.packs import list_packs, load_pack
from mcp_assure.purple import list_fixtures, run_all, run_fixture
from mcp_assure.verity_hook import check_claim, maybe_verify_tool_result, verity_available


class PacksTests(unittest.TestCase):
    def test_packs_load(self) -> None:
        names = list_packs()
        self.assertIn("baseline", names)
        self.assertIn("mcp_authz_boundaries", names)
        self.assertIn("strict_local", names)
        reg = load_pack("baseline")
        self.assertIn("echo", reg)
        eng = AssureEngine(reg)
        self.assertTrue(
            eng.evaluate(ToolCall(tool="echo", arguments={"text": "hi"})).allowed
        )


class PurpleTests(unittest.TestCase):
    def test_all_purple_fixtures_pass(self) -> None:
        self.assertGreaterEqual(len(list_fixtures()), 3)
        fails = []
        for rep in run_all():
            if not rep.passed:
                fails.append(rep.as_dict())
        self.assertEqual(fails, [], msg=str(fails))

    def test_velocity_fixture(self) -> None:
        rep = run_fixture("velocity_flood")
        self.assertTrue(rep.passed, rep.as_dict())


class IntegrationTests(unittest.TestCase):
    def test_dispatcher(self) -> None:
        eng = AssureEngine(load_pack("baseline"))
        d = AssuredToolDispatcher(
            eng, {"echo": lambda a: {"echo": a["text"]}}
        )
        out = d.call_tool({"name": "echo", "arguments": {"text": "z"}})
        self.assertTrue(out["executed"])
        denied = d.call_tool({"name": "nope", "arguments": {}})
        self.assertFalse(denied["executed"])

    def test_decorator(self) -> None:
        eng = AssureEngine(load_pack("baseline"))

        @assure_callable(eng, name="echo")
        def echo(text: str) -> str:
            return text.upper()

        self.assertEqual(echo(text="ab"), "AB")
        with self.assertRaises(Exception):
            echo(text="x", token="nope")  # type: ignore[call-arg]


class VerityHookTests(unittest.TestCase):
    def test_unavailable_soft(self) -> None:
        # May or may not be installed; must not raise
        _ = verity_available()
        r = check_claim({"name": "x", "accuracy": 0.99, "sample_size": 3})
        self.assertIsInstance(r.status, str)
        self.assertTrue(len(r.status) > 0)
        self.assertIsInstance(r.available, bool)

    def test_maybe_verify_skips_non_claims(self) -> None:
        self.assertIsNone(maybe_verify_tool_result({"echo": "hi"}))
        self.assertIsNone(maybe_verify_tool_result("plain"))

    def test_maybe_verify_with_mock(self) -> None:
        with mock.patch(
            "mcp_assure.verity_hook.check_claim",
            return_value=type("R", (), {"as_dict": lambda self: {}, "status": "REFUSE", "available": True})(),
        ):
            r = maybe_verify_tool_result(
                {"name": "m", "accuracy": 0.9, "sample_size": 10, "out_of_sample": False}
            )
            self.assertIsNotNone(r)


if __name__ == "__main__":
    unittest.main()
