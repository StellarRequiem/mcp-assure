"""Lightweight MCP-shaped structures (no SDK dependency).

Compatible with common tool-call dicts used by hosts and FastMCP-style servers.
"""

from __future__ import annotations

from typing import Any

from .policy import ToolCall


def tool_call_from_mcp(
    payload: dict[str, Any],
    *,
    actor: str = "agent",
    source: str = "mcp",
    lab_mode: bool = False,
) -> ToolCall:
    """Accept several common shapes:

    - {"name": "tool", "arguments": {...}}
    - {"tool": "tool", "arguments": {...}}
    - {"method": "tools/call", "params": {"name": "...", "arguments": {...}}}
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")

    name = payload.get("name") or payload.get("tool")
    arguments = payload.get("arguments")
    resource = payload.get("resource")
    audience = payload.get("audience")

    params = payload.get("params")
    if isinstance(params, dict):
        name = name or params.get("name") or params.get("tool")
        if arguments is None:
            arguments = params.get("arguments") or params.get("input")
        resource = resource or params.get("resource")
        audience = audience or params.get("audience")

    if not name:
        raise ValueError("could not extract tool name from payload")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise TypeError("arguments must be an object")

    return ToolCall(
        tool=str(name),
        arguments=arguments,
        actor=actor,
        source=source,
        resource=str(resource) if resource is not None else None,
        audience=str(audience) if audience is not None else None,
        lab_mode=lab_mode,
        metadata={"raw_keys": sorted(payload.keys())},
    )
