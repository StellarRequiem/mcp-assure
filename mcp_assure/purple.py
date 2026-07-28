"""Purple stress suite — synthetic adversarial call sequences against the gate.

No live network. No host mutation. Re-runnable scorecard for control-plane health.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from mcp_assure.engine import AssureEngine
from mcp_assure.middleware import AssuredRunner
from mcp_assure.packs import load_pack
from mcp_assure.policy import ToolCall
from mcp_assure.velocity import VelocityLimit, VelocityTracker

_FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "purple_fixtures")


@dataclass
class CheckResult:
    id: str
    passed: bool
    detail: str


@dataclass
class PurpleReport:
    fixture_id: str
    passed: bool
    checks: list[CheckResult] = field(default_factory=list)
    steps: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "passed": self.passed,
            "steps": self.steps,
            "checks": [
                {"id": c.id, "passed": c.passed, "detail": c.detail} for c in self.checks
            ],
            "summary": "; ".join(
                f"{c.id}={'PASS' if c.passed else 'FAIL'}" for c in self.checks
            ),
        }


def list_fixtures() -> list[str]:
    if not os.path.isdir(_FIXTURE_DIR):
        return []
    return sorted(
        n[: -len(".json")]
        for n in os.listdir(_FIXTURE_DIR)
        if n.endswith(".json")
    )


def load_fixture(fixture_id: str) -> dict[str, Any]:
    path = os.path.join(_FIXTURE_DIR, f"{fixture_id}.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("id", fixture_id)
    return data


def run_fixture(fixture_id: str) -> PurpleReport:
    fix = load_fixture(fixture_id)
    pack_name = fix.get("pack", "baseline")
    registry = load_pack(pack_name)

    tight = bool(fix.get("tight_velocity"))
    if tight:
        vel = VelocityTracker(
            {
                "per_identity": VelocityLimit(3, 60.0),
                "per_actor": VelocityLimit(20, 60.0),
                "global": VelocityLimit(50, 60.0),
            }
        )
    else:
        vel = VelocityTracker()

    eng = AssureEngine(registry, velocity=vel)
    executed = {"n": 0}

    def _handler(_args: dict[str, Any]) -> str:
        executed["n"] += 1
        return "executed"

    # Register handlers for all pack tools so ALLOW would execute if we used runner
    handlers = {name: _handler for name in registry.names()}
    runner = AssuredRunner(eng, handlers)

    transcript: list[dict[str, Any]] = []
    for step in fix.get("steps") or []:
        call = ToolCall(
            tool=str(step.get("tool") or ""),
            arguments=dict(step.get("arguments") or {}),
            actor=str(step.get("actor") or "agent"),
            source=str(step.get("source") or "purple"),
            lab_mode=bool(step.get("lab_mode", False)),
            blast_units=int(step.get("blast_units") or 1),
            resource=step.get("resource"),
            audience=step.get("audience"),
            model_note=step.get("model_note"),
        )
        if step.get("use_runner", True):
            out = runner.invoke(call)
            row = {
                "tool": call.tool,
                "decision": out["verdict"]["decision"],
                "code": out["verdict"]["code"],
                "executed": out["executed"],
            }
        else:
            v = eng.evaluate(call)
            row = {
                "tool": call.tool,
                "decision": v.decision.value,
                "code": v.code,
                "executed": False,
            }
        transcript.append(row)

    expect = fix.get("expect") or {}
    checks: list[CheckResult] = []

    if "codes_include" in expect:
        want = set(expect["codes_include"])
        have = {r["code"] for r in transcript}
        checks.append(
            CheckResult(
                "codes_include",
                want.issubset(have),
                f"want {sorted(want)} have {sorted(have)}",
            )
        )

    if expect.get("no_execution"):
        checks.append(
            CheckResult(
                "no_execution",
                executed["n"] == 0 and not any(r["executed"] for r in transcript),
                f"handler_calls={executed['n']}",
            )
        )

    if expect.get("some_execution"):
        checks.append(
            CheckResult(
                "some_execution",
                executed["n"] > 0,
                f"handler_calls={executed['n']}",
            )
        )

    if "min_denies" in expect:
        denies = sum(1 for r in transcript if r["decision"] == "DENY")
        need = int(expect["min_denies"])
        checks.append(
            CheckResult("min_denies", denies >= need, f"denies={denies} need>={need}")
        )

    if expect.get("model_note_ineffective"):
        # any step with model_note that targeted unknown tool must still DENY
        bad = [
            r
            for r, s in zip(transcript, fix.get("steps") or [])
            if s.get("model_note") and r["decision"] == "ALLOW" and s.get("tool") not in registry
        ]
        checks.append(
            CheckResult(
                "model_note_ineffective",
                len(bad) == 0,
                "model_note must not authorize unknown tools",
            )
        )

    passed = all(c.passed for c in checks) if checks else False
    return PurpleReport(
        fixture_id=fix.get("id", fixture_id),
        passed=passed,
        checks=checks,
        steps=len(transcript),
    )


def run_all() -> list[PurpleReport]:
    return [run_fixture(fid) for fid in list_fixtures()]
