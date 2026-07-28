"""AssuredRunner — invoke tools only after the gate ALLOWs.

Integration pattern for MCP hosts:

    runner = AssuredRunner(engine, handlers={"read_file": read_file})
    result = runner.invoke(ToolCall(tool="read_file", arguments={"path": "..."}))
"""

from __future__ import annotations

from typing import Any, Callable

from .engine import AssureEngine, Verdict
from .policy import Decision, ToolCall

ToolHandler = Callable[[dict[str, Any]], Any]


class ToolDenied(RuntimeError):
    """Raised when invoke(..., raise_on_deny=True) and the gate denies."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(f"{verdict.decision.value} {verdict.code}: {verdict.detail}")


class AssuredRunner:
    """Maps tool names → handlers; never calls a handler on DENY/DRY_RUN/ESCALATE."""

    def __init__(
        self,
        engine: AssureEngine,
        handlers: dict[str, ToolHandler] | None = None,
    ) -> None:
        self.engine = engine
        self.handlers: dict[str, ToolHandler] = dict(handlers or {})

    def register(self, name: str, handler: ToolHandler) -> None:
        self.handlers[name] = handler

    def authorize(self, call: ToolCall) -> Verdict:
        return self.engine.evaluate(call)

    def invoke(
        self,
        call: ToolCall,
        *,
        raise_on_deny: bool = False,
    ) -> dict[str, Any]:
        """Authorize then optionally execute.

        Returns:
          {
            "verdict": <dict>,
            "executed": bool,
            "result": <handler return or None>,
            "error": <str or None>
          }
        """
        verdict = self.engine.evaluate(call)
        out: dict[str, Any] = {
            "verdict": verdict.as_dict(),
            "executed": False,
            "result": None,
            "error": None,
        }
        if verdict.decision is not Decision.ALLOW:
            if raise_on_deny:
                raise ToolDenied(verdict)
            return out

        handler = self.handlers.get(call.tool)
        if handler is None:
            out["error"] = f"no handler registered for tool {call.tool!r}"
            # Authorization passed but integration incomplete — do not invent success
            out["verdict"] = {
                **verdict.as_dict(),
                "code": "NO_HANDLER",
                "detail": out["error"],
                "decision": Decision.DENY.value,
                "allowed": False,
            }
            return out

        try:
            result = handler(call.arguments or {})
            out["executed"] = True
            out["result"] = result
        except Exception as exc:  # noqa: BLE001 — surface to caller
            out["error"] = f"{type(exc).__name__}: {exc}"
        return out
