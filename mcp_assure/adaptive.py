"""Adaptive gate — wrap AssureEngine with proactive campaign posture.

Policy:
  * Always evaluate the static catalog first (deny-by-default remains law).
  * Observe every attempt into CampaignWatch (including denials — probes matter).
  * If recommendation is escalate/freeze, **upgrade** ALLOW/DRY_RUN to ESCALATE
    or DENY+FREEZE. Never downgrade a DENY to ALLOW.
  * Optional auto_freeze: touch freeze_path so subsequent calls hit FREEZE mode.

This is the proactive half: we do not wait for a novel 0-day name; we react to
swarm / spray / staging *shape* while the static pack blocks known-bad tools.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from mcp_assure.campaign import CampaignSnapshot, CampaignWatch
from mcp_assure.engine import AssureEngine, Verdict
from mcp_assure.policy import Decision, ToolCall


OnSignal = Callable[[CampaignSnapshot], None]


@dataclass
class AdaptiveResult:
    verdict: Verdict
    snapshot: CampaignSnapshot
    adapted: bool
    adaptation: str | None = None  # freeze | escalate | arg_block | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.as_dict(),
            "campaign": self.snapshot.as_dict(),
            "adapted": self.adapted,
            "adaptation": self.adaptation,
        }


class AdaptiveGate:
    """Proactive layer on top of AssureEngine."""

    def __init__(
        self,
        engine: AssureEngine,
        *,
        watch: CampaignWatch | None = None,
        auto_freeze: bool = True,
        block_critical_arg_smells: bool = True,
        freeze_allow: frozenset[str] | None = None,
        on_signal: OnSignal | None = None,
    ) -> None:
        self.engine = engine
        self.watch = watch or CampaignWatch()
        self.auto_freeze = auto_freeze
        self.block_critical_arg_smells = block_critical_arg_smells
        # High-confidence class markers: block without waiting for a named CVE
        self._block_codes = frozenset(
            {"TEMPLATE_SMELL", "PATH_SMELL", "PACKER_SMELL"}
        )
        self.freeze_allow = freeze_allow or frozenset({"echo", "health", "ping"})
        self.on_signal = on_signal
        # Align engine freeze path if set
        if engine.freeze_path and freeze_allow is None and engine.freeze_allow:
            self.freeze_allow = engine.freeze_allow

    def evaluate(self, call: ToolCall) -> AdaptiveResult:
        # --- proactive pre-block on high-confidence argument shape ---
        adaptation: str | None = None
        if self.block_critical_arg_smells:
            from mcp_assure.campaign import arg_smell_scan

            smells = arg_smell_scan(call.arguments)
            block = [
                s
                for s in smells
                if s.severity == "critical"
                or (s.severity == "high" and s.code in self._block_codes)
            ]
            if block:
                v = self.engine._finish(  # noqa: SLF001 — intentional reuse of receipt path
                    call,
                    Decision.DENY,
                    "PROACTIVE_ARG_BLOCK",
                    block[0].detail,
                    meta_extra={
                        "proactive": True,
                        "signals": [s.code for s in block],
                    },
                )
                snap = self._observe(call, v)
                return AdaptiveResult(
                    verdict=v, snapshot=snap, adapted=True, adaptation="arg_block"
                )

        base = self.engine.evaluate(call)
        snap = self._observe(call, base)

        # Campaign freeze: engage even when this call was already DENY
        # (swarm of probes should lock the plane before a later ALLOW sneaks through)
        if snap.recommendation == "freeze":
            engaged = False
            if self.auto_freeze and self.engine.freeze_path:
                engaged = self._engage_freeze()
            if base.decision is Decision.ALLOW or base.decision is Decision.DRY_RUN:
                v = self.engine._finish(  # noqa: SLF001
                    call,
                    Decision.DENY,
                    "CAMPAIGN_FREEZE",
                    f"adaptive freeze: campaign score={snap.score:.1f} "
                    f"codes={snap.top_codes}",
                    meta_extra={
                        "proactive": True,
                        "campaign_score": snap.score,
                        "recommendation": "freeze",
                    },
                )
                snap = self._observe(call, v)
                if self.on_signal:
                    self.on_signal(snap)
                return AdaptiveResult(
                    verdict=v, snapshot=snap, adapted=True, adaptation="freeze"
                )
            if self.on_signal:
                self.on_signal(snap)
            return AdaptiveResult(
                verdict=base,
                snapshot=snap,
                adapted=engaged,
                adaptation="freeze" if engaged else None,
            )

        # Never soften denies
        if base.decision is Decision.DENY:
            if snap.recommendation == "escalate" and self.on_signal:
                self.on_signal(snap)
            return AdaptiveResult(
                verdict=base, snapshot=snap, adapted=False, adaptation=None
            )

        if snap.recommendation == "escalate" and base.decision is Decision.ALLOW:
            v = self.engine._finish(  # noqa: SLF001
                call,
                Decision.ESCALATE,
                "CAMPAIGN_ESCALATE",
                f"adaptive escalate: campaign score={snap.score:.1f} "
                f"codes={snap.top_codes} — human review before execute",
                meta_extra={
                    "proactive": True,
                    "campaign_score": snap.score,
                    "recommendation": "escalate",
                    "would_have_allowed": True,
                },
            )
            snap = self._observe(call, v)
            if self.on_signal:
                self.on_signal(snap)
            return AdaptiveResult(
                verdict=v, snapshot=snap, adapted=True, adaptation="escalate"
            )

        if snap.recommendation in ("escalate", "freeze") and self.on_signal:
            self.on_signal(snap)
        return AdaptiveResult(
            verdict=base, snapshot=snap, adapted=False, adaptation=None
        )

    def _observe(self, call: ToolCall, v: Verdict) -> CampaignSnapshot:
        self.watch.observe(
            call,
            decision=v.decision.value,
            code=v.code,
        )
        return self.watch.snapshot()

    def _engage_freeze(self) -> bool:
        path = self.engine.freeze_path
        if not path:
            return False
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("mcp-assure adaptive campaign freeze\n")
        # ensure engine honors allowlist
        if not self.engine.freeze_allow:
            self.engine.freeze_allow = self.freeze_allow
        return True
