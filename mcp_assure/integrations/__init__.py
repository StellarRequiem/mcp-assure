"""Optional host integrations (stdlib core; no hard deps on FastMCP)."""

from .decorators import assure_callable
from .fastmcp_mw import authorize_message, build_assure_middleware, message_to_tool_call
from .host import AssuredToolDispatcher

__all__ = [
    "AssuredToolDispatcher",
    "assure_callable",
    "authorize_message",
    "build_assure_middleware",
    "message_to_tool_call",
]
