"""FastMCP middleware adapter — optional dependency.

Install::

    pip install "mcp-assure[fastmcp]"
    # or: pip install fastmcp

Usage (FastMCP ≥2.9)::

    from mcp_assure import AssureEngine
    from mcp_assure.packs import load_pack
    from mcp_assure.integrations.fastmcp_mw import build_assure_middleware

    engine = AssureEngine(load_pack("baseline"), receipts_path="receipts.jsonl")
    mcp.add_middleware(build_assure_middleware(engine))

Core stays zero-dependency: this module only imports ``fastmcp`` inside
``build_assure_middleware``. Authorization logic is pure and unit-tested.
"""

from __future__ import annotations

from typing import Any, Callable

from mcp_assure.engine import AssureEngine, Verdict
from mcp_assure.policy import Decision, ToolCall


def message_to_tool_call(
    message: Any,
    *,
    actor: str = "agent",
    source: str = "fastmcp",
    lab_mode: bool = False,
) -> ToolCall:
    """Map a FastMCP / MCP tools/call message object to ToolCall.

    Accepts either an object with ``.name`` / ``.arguments`` or a dict
    ``{"name": ..., "arguments": ...}``.
    """
    if isinstance(message, dict):
        name = message.get("name") or message.get("tool") or ""
        raw_args = message.get("arguments") or {}
    else:
        name = getattr(message, "name", None) or getattr(message, "tool", None) or ""
        raw_args = getattr(message, "arguments", None) or {}
    if not isinstance(raw_args, dict):
        raw_args = dict(raw_args) if raw_args else {}

    args = dict(raw_args)
    # Optional host-injected binding fields (stripped before handler sees them
    # only if the host wires them; here we lift them into ToolCall metadata).
    resource = args.pop("_mcp_resource", None)
    audience = args.pop("_mcp_audience", None)
    if "_mcp_lab_mode" in args:
        lab_mode = bool(args.pop("_mcp_lab_mode"))

    return ToolCall(
        tool=str(name),
        arguments=args,
        actor=actor,
        source=source,
        lab_mode=lab_mode,
        resource=str(resource) if resource is not None else None,
        audience=str(audience) if audience is not None else None,
    )


def authorize_message(
    engine: AssureEngine,
    message: Any,
    *,
    actor: str = "agent",
    source: str = "fastmcp",
    lab_mode: bool = False,
) -> Verdict:
    """Evaluate gate for a tools/call message. Never executes the tool."""
    call = message_to_tool_call(
        message, actor=actor, source=source, lab_mode=lab_mode
    )
    return engine.evaluate(call)


def deny_detail(verdict: Verdict) -> str:
    return f"mcp-assure {verdict.decision.value} {verdict.code}: {verdict.detail}"


def build_assure_middleware(
    engine: AssureEngine,
    *,
    actor: str = "agent",
    source: str = "fastmcp",
    lab_mode: bool = False,
    on_deny: Callable[[Verdict], None] | None = None,
) -> Any:
    """Construct a FastMCP ``Middleware`` that gates ``on_call_tool``.

    On DENY/DRY_RUN/etc. (anything not ALLOW): raises FastMCP ``ToolError``
    and does **not** call ``call_next`` — handler never runs.

    Raises:
        ImportError: if ``fastmcp`` is not installed.
    """
    try:
        from fastmcp.exceptions import ToolError
        from fastmcp.server.middleware import Middleware, MiddlewareContext
    except ImportError as exc:  # pragma: no cover - exercised only when missing
        raise ImportError(
            "FastMCP is required for build_assure_middleware. "
            'Install with: pip install "mcp-assure[fastmcp]"'
        ) from exc

    class AssureMiddleware(Middleware):
        """Deny-by-default mcp-assure gate on tools/call."""

        async def on_call_tool(  # type: ignore[no-untyped-def]
            self, context: MiddlewareContext, call_next
        ):
            verdict = authorize_message(
                engine,
                context.message,
                actor=actor,
                source=source,
                lab_mode=lab_mode,
            )
            if verdict.decision is not Decision.ALLOW:
                if on_deny is not None:
                    on_deny(verdict)
                raise ToolError(deny_detail(verdict))
            return await call_next(context)

    return AssureMiddleware()
