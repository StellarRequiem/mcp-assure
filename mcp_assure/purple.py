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
    mode = str(fix.get("mode") or "static")

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
    campaign_snap: dict[str, Any] | None = None

    def _handler(_args: dict[str, Any]) -> str:
        executed["n"] += 1
        return "executed"

    handlers = {name: _handler for name in registry.names()}
    runner = AssuredRunner(eng, handlers)

    adaptive = None
    if mode == "adaptive":
        from mcp_assure.adaptive import AdaptiveGate
        from mcp_assure.campaign import CampaignWatch

        adaptive = AdaptiveGate(
            eng,
            watch=CampaignWatch(
                window_seconds=300.0,
                escalate_score=5.0,
                freeze_score=10.0,
                swarm_unique_sources=4,
                spray_unique_tools=4,
                unknown_burst=3,
            ),
            auto_freeze=False,
            block_critical_arg_smells=True,
        )

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
        if adaptive is not None:
            ar = adaptive.evaluate(call)
            campaign_snap = ar.snapshot.as_dict()
            # adaptive path never executes handlers (gate only)
            row = {
                "tool": call.tool,
                "decision": ar.verdict.decision.value,
                "code": ar.verdict.code,
                "executed": False,
                "adapted": ar.adapted,
                "adaptation": ar.adaptation,
            }
        elif step.get("use_runner", True):
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

    if adaptive is not None and campaign_snap is None:
        campaign_snap = adaptive.watch.snapshot().as_dict()

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

    # --- proactive / adaptive campaign expectations ---
    if campaign_snap is not None:
        if "campaign_min_score" in expect:
            need = float(expect["campaign_min_score"])
            got = float(campaign_snap.get("score") or 0)
            checks.append(
                CheckResult(
                    "campaign_min_score",
                    got >= need,
                    f"score={got} need>={need} rec={campaign_snap.get('recommendation')}",
                )
            )
        if "campaign_recommendation_in" in expect:
            want = set(expect["campaign_recommendation_in"])
            got = str(campaign_snap.get("recommendation") or "")
            checks.append(
                CheckResult(
                    "campaign_recommendation_in",
                    got in want,
                    f"got {got!r} want one of {sorted(want)}",
                )
            )
        if "campaign_codes_any" in expect:
            want = set(expect["campaign_codes_any"])
            have = set(campaign_snap.get("top_codes") or [])
            # also scan signal codes
            for s in campaign_snap.get("signals") or []:
                if isinstance(s, dict) and s.get("code"):
                    have.add(str(s["code"]))
            checks.append(
                CheckResult(
                    "campaign_codes_any",
                    bool(want & have),
                    f"want any of {sorted(want)} have {sorted(have)}",
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
