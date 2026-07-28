"""Host-level tool dispatcher — drop-in for MCP client tool execution paths.

When ``adaptive=True``, every call goes through ``AdaptiveGate`` first. Handlers
are only reachable via ``call_tool`` — there is no public escape hatch that runs
a handler without a verdict. That is the "cannot bypass" host shape for demos
and Grok Build wiring.
"""

from __future__ import annotations

from typing import Any, Callable

from mcp_assure.adaptive import AdaptiveGate, AdaptiveResult
from mcp_assure.campaign import CampaignWatch
from mcp_assure.engine import AssureEngine
from mcp_assure.middleware import AssuredRunner
from mcp_assure.mcp_types import tool_call_from_mcp
from mcp_assure.policy import Decision, ToolCall

ToolHandler = Callable[[dict[str, Any]], Any]


class AssuredToolDispatcher:
    """Authorize then dispatch MCP-shaped tool calls.

    Typical host hook::

        dispatcher = AssuredToolDispatcher(engine, handlers, adaptive=True)
        result = dispatcher.call_tool({"name": "read_file", "arguments": {...}})
        # result["executed"] is True only if gate ALLOWed
    """

    def __init__(
        self,
        engine: AssureEngine,
        handlers: dict[str, ToolHandler] | None = None,
        *,
        actor: str = "agent",
        source: str = "mcp-host",
        default_lab_mode: bool = False,
        adaptive: bool = False,
        auto_freeze: bool = True,
        campaign_watch: CampaignWatch | None = None,
    ) -> None:
        self.engine = engine
        # Handlers live only on the runner — not exposed for direct call.
        self._runner = AssuredRunner(engine, handlers or {})
        self.actor = actor
        self.source = source
        self.default_lab_mode = default_lab_mode
        self.adaptive_enabled = adaptive
        self._adaptive: AdaptiveGate | None = None
        if adaptive:
            self._adaptive = AdaptiveGate(
                engine,
                watch=campaign_watch or CampaignWatch(),
                auto_freeze=auto_freeze,
            )

    @property
    def runner(self) -> AssuredRunner:
        """Runner for tests/registration only — do not invoke handlers off-band."""
        return self._runner

    def register(self, name: str, handler: ToolHandler) -> None:
        self._runner.register(name, handler)

    def _to_call(
        self,
        payload: dict[str, Any] | ToolCall,
        *,
        lab_mode: bool | None,
    ) -> ToolCall:
        if isinstance(payload, ToolCall):
            call = payload
            if lab_mode is not None:
                call.lab_mode = lab_mode
            return call
        call = tool_call_from_mcp(
            payload,
            actor=self.actor,
            source=self.source,
            lab_mode=self.default_lab_mode if lab_mode is None else lab_mode,
        )
        if lab_mode is not None:
            call.lab_mode = lab_mode
        return call

    def call_tool(
        self,
        payload: dict[str, Any] | ToolCall,
        *,
        lab_mode: bool | None = None,
        raise_on_deny: bool = False,
    ) -> dict[str, Any]:
        """Single choke point: gate (static or adaptive) then handler if ALLOW."""
        call = self._to_call(payload, lab_mode=lab_mode)

        if self._adaptive is not None:
            ar: AdaptiveResult = self._adaptive.evaluate(call)
            out = self._runner.invoke(
                call,
                raise_on_deny=raise_on_deny,
                pre_verdict=ar.verdict,
            )
            out["campaign"] = ar.snapshot.as_dict()
            out["adapted"] = ar.adapted
            out["adaptation"] = ar.adaptation
            # Belt: never execute if adaptive said non-ALLOW (runner already checks)
            if ar.verdict.decision is not Decision.ALLOW:
                out["executed"] = False
            return out

        return self._runner.invoke(call, raise_on_deny=raise_on_deny)

    def authorize_only(self, payload: dict[str, Any] | ToolCall) -> dict[str, Any]:
        call = self._to_call(payload, lab_mode=None)
        if self._adaptive is not None:
            ar = self._adaptive.evaluate(call)
            return {
                **ar.verdict.as_dict(),
                "campaign": ar.snapshot.as_dict(),
                "adapted": ar.adapted,
            }
        return self.engine.evaluate(call).as_dict()
