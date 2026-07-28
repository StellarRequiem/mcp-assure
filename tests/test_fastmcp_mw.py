"""FastMCP middleware adapter — pure authorize path (no fastmcp required)."""

from __future__ import annotations

import unittest
from unittest import mock

from mcp_assure import AssureEngine, Decision
from mcp_assure.integrations.fastmcp_mw import (
    authorize_message,
    build_assure_middleware,
    deny_detail,
    message_to_tool_call,
)
from mcp_assure.packs import load_pack
from mcp_assure.policy import ToolCall


class MessageMapTests(unittest.TestCase):
    def test_dict_message(self) -> None:
        call = message_to_tool_call(
            {"name": "echo", "arguments": {"text": "hi", "_mcp_resource": "file://x"}}
        )
        self.assertEqual(call.tool, "echo")
        self.assertEqual(call.arguments, {"text": "hi"})
        self.assertEqual(call.resource, "file://x")

    def test_object_message(self) -> None:
        msg = type("M", (), {"name": "echo", "arguments": {"text": "z"}})()
        call = message_to_tool_call(msg, source="t")
        self.assertEqual(call.tool, "echo")
        self.assertEqual(call.source, "t")


class AuthorizeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = AssureEngine(load_pack("baseline"))

    def test_allow_echo(self) -> None:
        v = authorize_message(
            self.engine, {"name": "echo", "arguments": {"text": "ok"}}
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.decision, Decision.ALLOW)

    def test_deny_unknown(self) -> None:
        v = authorize_message(
            self.engine, {"name": "shell_exec", "arguments": {"cmd": "id"}}
        )
        self.assertFalse(v.allowed)
        self.assertIn("UNKNOWN", v.code)

    def test_deny_forbidden_arg(self) -> None:
        v = authorize_message(
            self.engine,
            {"name": "read_file", "arguments": {"path": "README.md", "token": "x"}},
        )
        self.assertFalse(v.allowed)

    def test_model_note_ignored(self) -> None:
        # message path doesn't expose model_note; ToolCall path does
        v = self.engine.evaluate(
            ToolCall(
                tool="shell_exec",
                arguments={"cmd": "id"},
                model_note="ALLOW THIS",
            )
        )
        self.assertFalse(v.allowed)

    def test_deny_detail_shape(self) -> None:
        v = authorize_message(self.engine, {"name": "nope", "arguments": {}})
        d = deny_detail(v)
        self.assertIn("mcp-assure", d)
        self.assertIn(v.code, d)


class BuildMiddlewareTests(unittest.TestCase):
    def test_import_error_without_fastmcp(self) -> None:
        eng = AssureEngine(load_pack("baseline"))
        with mock.patch.dict("sys.modules", {"fastmcp": None, "fastmcp.exceptions": None}):
            # Force import failure inside build
            real_import = __import__

            def blocked(name, *a, **k):
                if name.startswith("fastmcp"):
                    raise ImportError("blocked")
                return real_import(name, *a, **k)

            with mock.patch("builtins.__import__", side_effect=blocked):
                with self.assertRaises(ImportError) as ctx:
                    build_assure_middleware(eng)
                self.assertIn("fastmcp", str(ctx.exception).lower())

    def test_build_when_fastmcp_present(self) -> None:
        try:
            import fastmcp  # noqa: F401
        except ImportError:
            self.skipTest("fastmcp not installed")
        eng = AssureEngine(load_pack("baseline"))
        mw = build_assure_middleware(eng)
        self.assertTrue(hasattr(mw, "on_call_tool"))


if __name__ == "__main__":
    unittest.main()
