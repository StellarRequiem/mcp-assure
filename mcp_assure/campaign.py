"""Proactive campaign detection — agentic attack *shape*, not only known bad tools.

Background (public, July 2026): machine-speed agents produce thousands of low-signal
actions; successful paths hide in failed probes. Waiting to block only the final
exploit is too late. This module scores **behavioral patterns** in a sliding window
so hosts can escalate / freeze *before* a novel chain completes.

Zero network. No exploit payloads. Pure heuristics over tool names, verdicts, and
argument *shape* (paths, template markers, opaque encoding density).
"""

from __future__ import annotations

import base64
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from mcp_assure.policy import Decision, ToolCall

# --- smell patterns (class-level, not CVE-specific) ---

_PATH_SMELLS = (
    "/proc/self/environ",
    "/proc/self/",
    "/var/run/secrets",
    "169.254.169.254",
    "metadata.google.internal",
    "/etc/shadow",
    "kubernetes.default.svc",
    "file://",
)

_TEMPLATE_SMELLS = (
    "{{",
    "}}",
    "__globals__",
    "__builtins__",
    "cycler.__init__",
    "jinja2",
    "request.__class__",
)

_RECON_TOOL_FRAGMENTS = (
    "shell",
    "exec",
    "bash",
    "cmd",
    "subprocess",
    "kubectl",
    "docker",
    "ssh",
    "curl",
    "wget",
    "nc_",
    "netcat",
    "privilege",
    "sudo",
    "exfil",
    "mine_secret",
    "read_env",
    "dump_secret",
    "token_mint",
    "imds",
    "metadata",
)

_B64_RE = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")
_HEX_BLOB_RE = re.compile(r"\b[0-9a-fA-F]{64,}\b")


@dataclass(frozen=True)
class CampaignSignal:
    code: str
    severity: str  # low | medium | high | critical
    detail: str
    score: float
    tool: str = ""
    actor: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "detail": self.detail,
            "score": self.score,
            "tool": self.tool,
            "actor": self.actor,
        }


@dataclass
class _Event:
    ts: float
    tool: str
    actor: str
    source: str
    decision: str
    code: str
    arg_smell_score: float
    signals: tuple[str, ...]


@dataclass
class CampaignSnapshot:
    """Point-in-time adaptive posture."""

    score: float
    recommendation: str  # continue | escalate | freeze
    window_events: int
    unique_tools: int
    unique_sources: int
    deny_ratio: float
    unknown_tool_count: int
    signals: list[CampaignSignal] = field(default_factory=list)
    top_codes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "recommendation": self.recommendation,
            "window_events": self.window_events,
            "unique_tools": self.unique_tools,
            "unique_sources": self.unique_sources,
            "deny_ratio": round(self.deny_ratio, 3),
            "unknown_tool_count": self.unknown_tool_count,
            "signals": [s.as_dict() for s in self.signals],
            "top_codes": self.top_codes,
        }


def _flatten_args(obj: Any, depth: int = 0) -> str:
    if depth > 6:
        return ""
    if obj is None:
        return ""
    if isinstance(obj, (str, int, float, bool)):
        return str(obj)
    if isinstance(obj, dict):
        return " ".join(_flatten_args(v, depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_args(v, depth + 1) for v in obj)
    return str(obj)[:200]


def arg_smell_scan(arguments: dict[str, Any] | None) -> list[CampaignSignal]:
    """Proactive content heuristics on tool arguments (pre- and post-decision)."""
    text = _flatten_args(arguments or {})
    if not text:
        return []
    low = text.lower()
    out: list[CampaignSignal] = []

    for p in _PATH_SMELLS:
        if p.lower() in low:
            out.append(
                CampaignSignal(
                    code="PATH_SMELL",
                    severity="high",
                    detail=f"argument text contains sensitive-path class marker {p!r}",
                    score=2.5,
                )
            )
            break

    hits = [m for m in _TEMPLATE_SMELLS if m.lower() in low]
    if len(hits) >= 2 or ("{{" in text and "exec" in low):
        out.append(
            CampaignSignal(
                code="TEMPLATE_SMELL",
                severity="critical",
                detail=f"template/RCE-class markers in arguments: {hits[:5]}",
                score=4.0,
            )
        )

    b64_hits = _B64_RE.findall(text)
    opaque = 0
    for blob in b64_hits[:5]:
        try:
            raw = base64.b64decode(blob + "==", validate=False)
            # high entropy / non-text → staged payload shape
            if len(raw) >= 24:
                nonprint = sum(1 for b in raw if b < 9 or (13 < b < 32) or b > 126)
                if nonprint / max(len(raw), 1) > 0.3:
                    opaque += 1
        except Exception:  # noqa: BLE001
            opaque += 1
    if opaque >= 1 or _HEX_BLOB_RE.search(text):
        out.append(
            CampaignSignal(
                code="ENCODED_PAYLOAD",
                severity="medium",
                detail="opaque base64/hex blob density consistent with staged droppers",
                score=1.5 + min(opaque, 3) * 0.5,
            )
        )

    if "gzip" in low and ("base64" in low or "b64" in low or "decompress" in low):
        out.append(
            CampaignSignal(
                code="PACKER_SMELL",
                severity="high",
                detail="gzip+base64 packer pattern (C2 staging class)",
                score=3.0,
            )
        )

    return out


def tool_name_smells(tool: str) -> list[CampaignSignal]:
    t = (tool or "").lower()
    if not t:
        return []
    for frag in _RECON_TOOL_FRAGMENTS:
        if frag in t:
            return [
                CampaignSignal(
                    code="RECON_TOOL_NAME",
                    severity="medium",
                    detail=f"tool name matches high-risk fragment {frag!r}",
                    score=1.2,
                    tool=tool,
                )
            ]
    return []


class CampaignWatch:
    """Sliding-window observer. Feed every gate attempt (ALLOW or DENY).

    Adaptive thresholds (defaults tuned for local agent hosts, not hyperscale):
      escalate_score >= 6
      freeze_score    >= 12
    """

    def __init__(
        self,
        *,
        window_seconds: float = 120.0,
        escalate_score: float = 6.0,
        freeze_score: float = 12.0,
        swarm_unique_sources: int = 4,
        spray_unique_tools: int = 5,
        unknown_burst: int = 4,
    ) -> None:
        self.window_seconds = window_seconds
        self.escalate_score = escalate_score
        self.freeze_score = freeze_score
        self.swarm_unique_sources = swarm_unique_sources
        self.spray_unique_tools = spray_unique_tools
        self.unknown_burst = unknown_burst
        self._events: deque[_Event] = deque()
        self._last_signals: list[CampaignSignal] = []

    def _prune(self, now: float) -> None:
        while self._events and (now - self._events[0].ts) > self.window_seconds:
            self._events.popleft()

    def observe(
        self,
        call: ToolCall,
        *,
        decision: str,
        code: str,
        now: float | None = None,
    ) -> list[CampaignSignal]:
        """Record one attempt; return new signals from this observation + window."""
        now = time.time() if now is None else now
        self._prune(now)

        instant = [
            CampaignSignal(
                code=s.code,
                severity=s.severity,
                detail=s.detail,
                score=s.score,
                tool=call.tool,
                actor=call.actor,
            )
            for s in list(arg_smell_scan(call.arguments)) + list(tool_name_smells(call.tool))
        ]

        smell_score = sum(s.score for s in instant)
        self._events.append(
            _Event(
                ts=now,
                tool=call.tool or "",
                actor=call.actor or "",
                source=call.source or "",
                decision=decision,
                code=code,
                arg_smell_score=smell_score,
                signals=tuple(s.code for s in instant),
            )
        )

        window_sigs = self._window_signals(now)
        all_sigs = instant + window_sigs
        self._last_signals = all_sigs
        return all_sigs

    def _window_signals(self, now: float) -> list[CampaignSignal]:
        ev = list(self._events)
        if len(ev) < 2:
            return []
        tools = {e.tool for e in ev}
        sources = {e.source for e in ev}
        actors = {e.actor for e in ev}
        unknown = sum(1 for e in ev if e.code == "UNKNOWN_TOOL")
        denies = sum(1 for e in ev if e.decision == Decision.DENY.value)
        n = len(ev)
        out: list[CampaignSignal] = []

        # Swarm: many short-lived sources (sandbox-per-action class)
        if len(sources) >= self.swarm_unique_sources and n >= self.swarm_unique_sources:
            out.append(
                CampaignSignal(
                    code="SWARM_SOURCES",
                    severity="high",
                    detail=(
                        f"{len(sources)} distinct sources in {self.window_seconds}s "
                        f"({n} events) — ephemeral sandbox swarm shape"
                    ),
                    score=2.0 + min(len(sources), 20) * 0.35,
                )
            )

        # Tool spray: many different tools (recon breadth)
        if len(tools) >= self.spray_unique_tools:
            out.append(
                CampaignSignal(
                    code="TOOL_SPRAY",
                    severity="high",
                    detail=f"{len(tools)} unique tools in window — recon/coverage search",
                    score=1.5 + min(len(tools), 30) * 0.25,
                )
            )

        # Unknown-tool burst (catalog probing)
        if unknown >= self.unknown_burst:
            out.append(
                CampaignSignal(
                    code="UNKNOWN_TOOL_BURST",
                    severity="medium",
                    detail=f"{unknown} UNKNOWN_TOOL denials in window",
                    score=1.0 + unknown * 0.4,
                )
            )

        # High deny ratio with volume (failed probes dominating)
        if n >= 8 and denies / n >= 0.7:
            out.append(
                CampaignSignal(
                    code="PROBE_DOMINATED",
                    severity="medium",
                    detail=f"deny_ratio={denies/n:.2f} over {n} events — probe noise cover",
                    score=1.5,
                )
            )

        # Multi-actor or multi-source + encoded smells
        smell_events = sum(1 for e in ev if e.arg_smell_score >= 1.5)
        if smell_events >= 2 and (len(sources) >= 2 or len(actors) >= 2):
            out.append(
                CampaignSignal(
                    code="MULTI_CHANNEL_STAGING",
                    severity="critical",
                    detail="encoded/path smells across multiple sources/actors",
                    score=3.5,
                )
            )

        # Velocity-ish: dense events
        if n >= 15 and (ev[-1].ts - ev[0].ts) <= 30.0:
            out.append(
                CampaignSignal(
                    code="BURST_VELOCITY",
                    severity="high",
                    detail=f"{n} events in ≤30s window slice — machine cadence",
                    score=2.5,
                )
            )

        return out

    def snapshot(self, now: float | None = None) -> CampaignSnapshot:
        now = time.time() if now is None else now
        self._prune(now)
        ev = list(self._events)
        n = len(ev)
        tools = {e.tool for e in ev}
        sources = {e.source for e in ev}
        denies = sum(1 for e in ev if e.decision == Decision.DENY.value)
        unknown = sum(1 for e in ev if e.code == "UNKNOWN_TOOL")
        # Recompute signals without double-counting by re-running window + last instants
        sigs = list(self._last_signals) if self._last_signals else self._window_signals(now)
        # Score: max severity path + sum of unique codes (cap)
        by_code: dict[str, float] = {}
        for s in sigs:
            by_code[s.code] = max(by_code.get(s.code, 0.0), s.score)
        score = sum(by_code.values())
        # mild base pressure from volume alone (proactive, not only signature match)
        if n >= 10:
            score += min((n - 9) * 0.15, 2.0)

        if score >= self.freeze_score:
            rec = "freeze"
        elif score >= self.escalate_score:
            rec = "escalate"
        else:
            rec = "continue"

        top = sorted(by_code.keys(), key=lambda c: -by_code[c])[:8]
        return CampaignSnapshot(
            score=score,
            recommendation=rec,
            window_events=n,
            unique_tools=len(tools),
            unique_sources=len(sources),
            deny_ratio=(denies / n) if n else 0.0,
            unknown_tool_count=unknown,
            signals=sigs,
            top_codes=top,
        )

    def analyze_transcript(
        self,
        rows: Iterable[dict[str, Any]],
        *,
        start_ts: float | None = None,
    ) -> CampaignSnapshot:
        """Offline / purple: feed a list of {tool, actor, source, decision, code, arguments?}."""
        self._events.clear()
        self._last_signals = []
        t0 = start_ts if start_ts is not None else time.time()
        for i, row in enumerate(rows):
            call = ToolCall(
                tool=str(row.get("tool") or ""),
                arguments=dict(row.get("arguments") or {}),
                actor=str(row.get("actor") or "agent"),
                source=str(row.get("source") or f"offline.{i}"),
            )
            self.observe(
                call,
                decision=str(row.get("decision") or "DENY"),
                code=str(row.get("code") or ""),
                now=t0 + float(row.get("t", i * 0.05)),
            )
        return self.snapshot(now=t0 + 1000.0)
