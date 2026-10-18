"""The mcp-assure config scored by the regression job: an operator pack for the served tools.

An operator writes one entry per tool their server exposes. Here that pack is built by one
mechanical rule from each served tool's ``inputSchema``, never from a test case:

* ``required_args`` = the schema's ``required``;
* ``allowed_args`` = its ``properties`` (left open when the schema declares none);
* ``forbidden_args`` = the baseline pack's credential names that the tool does not itself declare.

Everything else (``max_blast``, size, depth, velocity) stays at mcp-assure's defaults, and the gate
is ``build_assure_middleware`` unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastmcp.server.middleware import Middleware

from mcp_assure import AssureEngine, ToolPolicy, ToolPolicyRegistry
from mcp_assure.integrations.fastmcp_mw import build_assure_middleware

CREDENTIAL_ARGS = ("token", "password", "api_key", "authorization")


def policy_for(name: str, schema: Mapping[str, Any] | None) -> ToolPolicy:
    """The operator's entry for one served tool, from its declared input schema."""
    props = schema.get("properties") if isinstance(schema, Mapping) else None
    declared = tuple(props) if isinstance(props, Mapping) else ()
    required = schema.get("required") if isinstance(schema, Mapping) else None
    return ToolPolicy(
        name=name,
        required_args=tuple(required or ()),
        allowed_args=declared if isinstance(props, Mapping) else None,
        forbidden_args=tuple(a for a in CREDENTIAL_ARGS if a not in declared),
    )


class OperatorPack(Middleware):
    """``build_assure_middleware`` with a pack written for the tools this server serves.

    The pack is built from the server's tool list before the first call is gated, which is when
    an operator would have written it. The registry is filled before ``AssureEngine`` is built.
    """

    def __init__(self) -> None:
        self.gate: Any = None

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        if self.gate is None:
            server = context.fastmcp_context.fastmcp
            tools = await server.list_tools()
            registry = ToolPolicyRegistry([policy_for(t.name, t.parameters) for t in tools])
            self.gate = build_assure_middleware(AssureEngine(registry))
        return await self.gate.on_call_tool(context, call_next)


def operator_pack() -> OperatorPack:
    """A fresh middleware per fixture, so velocity state never leaks between fixtures."""
    return OperatorPack()
