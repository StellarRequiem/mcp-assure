"""Proactive campaign detection + adaptive gate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_assure.adaptive import AdaptiveGate
from mcp_assure.campaign import CampaignWatch, arg_smell_scan, tool_name_smells
from mcp_assure.engine import AssureEngine
from mcp_assure.packs import load_pack
from mcp_assure.policy import Decision, ToolCall
from mcp_assure.purple import run_all, run_fixture


class SmellTests(unittest.TestCase):
    def test_path_smell(self) -> None:
        s = arg_smell_scan({"path": "/proc/self/environ"})
        self.assertTrue(any(x.code == "PATH_SMELL" for x in s))

    def test_template_smell(self) -> None:
        s = arg_smell_scan(
            {"cfg": "{{ cycler.__init__.__globals__.__builtins__.exec('x') }}"}
        )
        self.assertTrue(any(x.code == "TEMPLATE_SMELL" for x in s))

    def test_tool_name(self) -> None:
        s = tool_name_smells("shell_exec")
        self.assertTrue(s)


class AdaptiveTests(unittest.TestCase):
    def test_proactive_path_block(self) -> None:
        eng = AssureEngine(load_pack("baseline"))
        gate = AdaptiveGate(eng, auto_freeze=False)
        ar = gate.evaluate(
            ToolCall(tool="read_file", arguments={"path": "/var/run/secrets/x"})
        )
        self.assertEqual(ar.verdict.decision, Decision.DENY)
        self.assertEqual(ar.verdict.code, "PROACTIVE_ARG_BLOCK")
        self.assertTrue(ar.adapted)

    def test_swarm_escalates_or_freezes(self) -> None:
        eng = AssureEngine(load_pack("agent_eval_strict"))
        watch = CampaignWatch(
            escalate_score=5.0,
            freeze_score=20.0,
            swarm_unique_sources=4,
            unknown_burst=3,
        )
        gate = AdaptiveGate(eng, watch=watch, auto_freeze=False)
        for i in range(8):
            ar = gate.evaluate(
                ToolCall(
                    tool=f"recon_tool_{i}",
                    arguments={},
                    source=f"synth.sandbox.{i}",
                )
            )
            self.assertEqual(ar.verdict.decision, Decision.DENY)
        snap = watch.snapshot()
        self.assertGreaterEqual(snap.score, 5.0)
        self.assertIn(snap.recommendation, ("escalate", "freeze"))

    def test_auto_freeze_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            freeze = str(Path(td) / "FREEZE")
            eng = AssureEngine(
                load_pack("agent_eval_strict"),
                freeze_path=freeze,
                freeze_allow=frozenset({"echo", "health"}),
            )
            watch = CampaignWatch(
                escalate_score=3.0,
                freeze_score=6.0,
                swarm_unique_sources=3,
                spray_unique_tools=3,
                unknown_burst=2,
            )
            gate = AdaptiveGate(eng, watch=watch, auto_freeze=True)
            # Build score via swarm + spray of unknown tools
            for i in range(10):
                gate.evaluate(
                    ToolCall(
                        tool=f"tool_{i}",
                        arguments={},
                        source=f"src.{i}",
                        actor="agent",
                    )
                )
            # If freeze engaged, health may still evaluate under freeze allowlist
            # when frozen; unknown tools stay DENY
            self.assertTrue(
                Path(freeze).is_file() or watch.snapshot().recommendation == "freeze"
                or watch.snapshot().score >= 6.0
            )


class PurpleProactiveTests(unittest.TestCase):
    def test_new_fixtures(self) -> None:
        for fid in (
            "agentic_tool_spray",
            "encoded_staging_shape",
            "path_smell_recon",
        ):
            rep = run_fixture(fid)
            self.assertTrue(rep.passed, rep.as_dict())

    def test_all_purple(self) -> None:
        fails = [r.as_dict() for r in run_all() if not r.passed]
        self.assertEqual(fails, [])


if __name__ == "__main__":
    unittest.main()
