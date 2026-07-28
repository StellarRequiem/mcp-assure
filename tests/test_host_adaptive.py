"""Cannot-bypass host dispatcher with AdaptiveGate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_assure import AssureEngine
from mcp_assure.integrations import AssuredToolDispatcher
from mcp_assure.packs import load_pack
from mcp_assure.policy import Decision


class AdaptiveHostTests(unittest.TestCase):
    def test_allow_echo(self) -> None:
        eng = AssureEngine(load_pack("baseline"))
        hits: list[str] = []

        def echo(a: dict) -> dict:
            hits.append("echo")
            return {"echo": a.get("text")}

        host = AssuredToolDispatcher(
            eng, {"echo": echo}, adaptive=True, auto_freeze=False
        )
        out = host.call_tool({"name": "echo", "arguments": {"text": "z"}})
        self.assertTrue(out["executed"])
        self.assertEqual(hits, ["echo"])
        self.assertIn("campaign", out)

    def test_unknown_never_executes(self) -> None:
        eng = AssureEngine(load_pack("baseline"))
        hits: list[str] = []

        def echo(a: dict) -> dict:
            hits.append("echo")
            return a

        host = AssuredToolDispatcher(
            eng, {"echo": echo}, adaptive=True, auto_freeze=False
        )
        out = host.call_tool({"name": "shell_exec", "arguments": {"cmd": "id"}})
        self.assertFalse(out["executed"])
        self.assertEqual(hits, [])
        self.assertEqual(out["verdict"]["decision"], Decision.DENY.value)

    def test_path_smell_never_executes(self) -> None:
        eng = AssureEngine(load_pack("baseline"))
        hits: list[str] = []

        def read_file(a: dict) -> dict:
            hits.append("read")
            return a

        host = AssuredToolDispatcher(
            eng, {"read_file": read_file}, adaptive=True, auto_freeze=False
        )
        out = host.call_tool(
            {"name": "read_file", "arguments": {"path": "/proc/self/environ"}}
        )
        self.assertFalse(out["executed"])
        self.assertEqual(hits, [])
        self.assertEqual(out["verdict"]["code"], "PROACTIVE_ARG_BLOCK")

    def test_grok_host_wire_script(self) -> None:
        import runpy
        from pathlib import Path

        p = Path(__file__).resolve().parents[1] / "examples" / "grok_host_wire.py"
        ns = runpy.run_path(str(p))
        self.assertEqual(ns["main"](), 0)


if __name__ == "__main__":
    unittest.main()
