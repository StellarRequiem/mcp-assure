"""mcp-assure — deny-by-default assurance runtime for MCP tool calls.

The model proposes. The gate decides. Receipts remember.
"""

from .engine import AssureEngine, Verdict
from .middleware import AssuredRunner, ToolDenied
from .packs import list_packs, load_pack
from .policy import (
    Decision,
    ToolCall,
    ToolPolicy,
    ToolPolicyRegistry,
)
from .receipts import ReceiptChain

__version__ = "0.2.0"

__all__ = [
    "AssureEngine",
    "AssuredRunner",
    "Decision",
    "ReceiptChain",
    "ToolCall",
    "ToolDenied",
    "ToolPolicy",
    "ToolPolicyRegistry",
    "Verdict",
    "list_packs",
    "load_pack",
    "__version__",
]
