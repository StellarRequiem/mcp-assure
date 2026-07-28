"""Decorators to wrap plain callables with mcp-assure."""

from __future__ import annotations

import functools
from typing import Any, Callable

from mcp_assure.engine import AssureEngine
from mcp_assure.middleware import AssuredRunner, ToolDenied
from mcp_assure.policy import ToolCall

ToolHandler = Callable[[dict[str, Any]], Any]


def assure_callable(
    engine: AssureEngine,
    *,
    name: str | None = None,
    actor: str = "agent",
    source: str = "decorator",
    lab_mode: bool = False,
    raise_on_deny: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a kwargs-style function so every call is authorized first.

    Reserved kwargs (stripped before the tool runs):
      ``_mcp_resource``, ``_mcp_audience``, ``_mcp_lab_mode``
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or fn.__name__

        def dict_handler(arguments: dict[str, Any]) -> Any:
            return fn(**arguments)

        runner = AssuredRunner(engine, {tool_name: dict_handler})

        @functools.wraps(fn)
        def wrapper(**kwargs: Any) -> Any:
            resource = kwargs.pop("_mcp_resource", None)
            audience = kwargs.pop("_mcp_audience", None)
            lab = kwargs.pop("_mcp_lab_mode", lab_mode)
            call = ToolCall(
                tool=tool_name,
                arguments=dict(kwargs),
                actor=actor,
                source=source,
                lab_mode=bool(lab),
                resource=str(resource) if resource is not None else None,
                audience=str(audience) if audience is not None else None,
            )
            out = runner.invoke(call, raise_on_deny=raise_on_deny)
            if out["executed"]:
                return out["result"]
            if raise_on_deny and out["verdict"]["decision"] != "ALLOW":
                # invoke already raised ToolDenied when decision is DENY and raise_on_deny
                # DRY_RUN / NO_HANDLER fall through here
                raise RuntimeError(
                    f"tool not executed: {out['verdict'].get('code')} "
                    f"{out.get('error') or out['verdict'].get('detail')}"
                )
            return out

        wrapper.__mcp_assure_tool__ = tool_name  # type: ignore[attr-defined]
        return wrapper

    return decorator
