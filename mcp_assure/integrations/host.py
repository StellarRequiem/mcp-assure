"""Host-level tool dispatcher — drop-in for MCP client tool execution paths."""

from __future__ import annotations

from typing import Any, Callable

from mcp_assure.engine import AssureEngine
from mcp_assure.middleware import AssuredRunner
from mcp_assure.mcp_types import tool_call_from_mcp
from mcp_assure.policy import ToolCall


class AssuredToolDispatcher:
    """Authorize then dispatch MCP-shaped tool calls.

    Typical host hook::

        dispatcher = AssuredToolDispatcher(engine, handlers)
        result = dispatcher.call_tool({"name": "read_file", "arguments": {...}})
    """

    def __init__(
        self,
        engine: AssureEngine,
        handlers: dict[str, Callable[[dict[str, Any]], Any]] | None = None,
        *,
        actor: str = "agent",
        source: str = "mcp-host",
        default_lab_mode: bool = False,
    ) -> None:
        self.engine = engine
        self.runner = AssuredRunner(engine, handlers or {})
        self.actor = actor
        self.source = source
        self.default_lab_mode = default_lab_mode

    def register(self, name: str, handler: Callable[[dict[str, Any]], Any]) -> None:
        self.runner.register(name, handler)

    def call_tool(
        self,
        payload: dict[str, Any] | ToolCall,
        *,
        lab_mode: bool | None = None,
        raise_on_deny: bool = False,
    ) -> dict[str, Any]:
        if isinstance(payload, ToolCall):
            call = payload
        else:
            call = tool_call_from_mcp(
                payload,
                actor=self.actor,
                source=self.source,
                lab_mode=self.default_lab_mode if lab_mode is None else lab_mode,
            )
            if lab_mode is not None:
                call.lab_mode = lab_mode
        return self.runner.invoke(call, raise_on_deny=raise_on_deny)

    def authorize_only(self, payload: dict[str, Any] | ToolCall) -> dict[str, Any]:
        if isinstance(payload, ToolCall):
            call = payload
        else:
            call = tool_call_from_mcp(
                payload,
                actor=self.actor,
                source=self.source,
                lab_mode=self.default_lab_mode,
            )
        return self.engine.evaluate(call).as_dict()
