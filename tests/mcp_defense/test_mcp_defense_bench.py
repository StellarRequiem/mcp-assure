"""Regression test: mcp-assure's FastMCP middleware on the mcp-defense-bench corpus.

Runs only where the pinned scorer is installed (CI job ``mcp-defense``:
``pip install -e ".[dev]" -r tests/mcp_defense/requirements.txt``); elsewhere it skips, so the
main matrix and the zero-dependency core are unaffected. Dev and benign corpora only.

The test never writes ``baseline.json``. To accept a change on purpose, run
``python tests/mcp_defense/update_baseline.py --write`` and commit the diff (see README.md).
"""

from __future__ import annotations

import asyncio
import json
import unittest

try:
    import harness
    import mcp_defense_bench  # noqa: F401
    from fastmcp import Client, FastMCP
    from fastmcp.exceptions import ToolError
    from fastmcp.tools.base import Tool, ToolResult
    from mcp.types import TextContent
    from operator_pack import operator_pack
except ImportError:  # the pinned scorer is not installed: this module is skipped
    harness = None

SMUGGLING_CASE = "out-of-scope-params/001-argument-smuggling"


@unittest.skipIf(harness is None, "needs tests/mcp_defense/requirements.txt")
class PinTests(unittest.TestCase):
    def test_scorer_corpus_and_fastmcp_are_the_pinned_versions(self) -> None:
        self.assertEqual(harness.pin_problems(), [])

    def test_baseline_was_recorded_with_the_same_pins(self) -> None:
        base = json.loads(harness.BASELINE.read_text("utf8"))
        recorded = {k: v for k, v in base["pins"].items() if k != "scorerSource"}
        current = {k: v for k, v in harness.pins().items() if k != "scorerSource"}
        self.assertEqual(recorded, current)


@unittest.skipIf(harness is None, "needs tests/mcp_defense/requirements.txt")
class SmugglingDeniedBeforeHandlerTests(unittest.TestCase):
    """The bench's argument-smuggling fixture, served by a real FastMCP server with a handler
    that records every invocation: the smuggled call must be denied and the handler never run."""

    def setUp(self) -> None:
        bench = harness.Bench.vendored_snapshot()
        self.case = next(c for c in bench.load_cases("dev") if c["id"] == SMUGGLING_CASE)
        self.invocations: list[dict] = []

    def _server(self, fixture: dict) -> FastMCP:
        invocations = self.invocations

        class RecordingTool(Tool):
            async def run(self, arguments: dict) -> ToolResult:
                invocations.append(dict(arguments))
                return ToolResult(content=[TextContent(type="text", text="ok")])

        defn = fixture["tool"]
        server = FastMCP("mcp-assure-smuggling")
        server.add_tool(
            RecordingTool(
                name=defn["name"], description=defn["description"], parameters=defn["inputSchema"]
            )
        )
        server.add_middleware(operator_pack())
        return server

    def _call(self, fixture: dict) -> tuple[bool, str]:
        async def go() -> tuple[bool, str]:
            async with Client(self._server(fixture)) as client:
                call = fixture["call"]
                try:
                    r = await client.call_tool(call["name"], call["arguments"])
                except ToolError as e:
                    return True, str(e)
                return bool(r.is_error), " ".join(getattr(b, "text", "") for b in r.content)

        return asyncio.run(go())

    def test_smuggled_argument_is_denied_and_handler_never_runs(self) -> None:
        self.assertIn("__exec", self.case["fixture"]["call"]["arguments"])
        denied, detail = self._call(self.case["fixture"])
        self.assertTrue(denied)
        self.assertIn("mcp-assure DENY ARG_POLICY", detail)
        self.assertIn("__exec", detail)
        self.assertEqual(self.invocations, [])

    def test_matched_control_reaches_the_handler_once(self) -> None:
        control = self.case["benignControl"]
        denied, _ = self._call(control)
        self.assertFalse(denied)
        self.assertEqual(self.invocations, [control["call"]["arguments"]])


@unittest.skipIf(harness is None, "needs tests/mcp_defense/requirements.txt")
class BaselineRegressionTests(unittest.TestCase):
    """Fails on a lost attack denial, a new benign denial (matched control or benign corpus),
    any scorer error, or a change in which fixtures are scored or skipped."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.base = json.loads(harness.BASELINE.read_text("utf8"))
        cls.cur = harness.run()

    def test_no_regressions_against_baseline(self) -> None:
        bad, good = harness.compare(self.base, self.cur)
        if good:
            print("\nimproved vs baseline (run update_baseline.py --write to record):")
            print("\n".join(f"  {g}" for g in good))
        self.assertEqual(bad, [], "\n".join(bad))

    def test_no_scorer_errors(self) -> None:
        self.assertEqual(self.cur["errors"], [])

    def test_counts_match_baseline(self) -> None:
        for corpus in ("dev", "benign"):
            for key in ("scored", "skipped", "errors"):
                self.assertEqual(
                    self.cur[corpus]["summary"][key],
                    self.base[corpus]["summary"][key],
                    f"{corpus} {key}",
                )


if __name__ == "__main__":
    unittest.main()
