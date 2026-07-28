"""Optional host integrations (stdlib core; no hard deps on FastMCP)."""

from .host import AssuredToolDispatcher
from .decorators import assure_callable

__all__ = ["AssuredToolDispatcher", "assure_callable"]
