"""mcp-assure — deny-by-default assurance runtime for MCP tool calls.

The model proposes. The gate decides. Receipts remember.
"""

from .engine import AssureEngine, Verdict
from .middleware import AssuredRunner, ToolDenied
from .policy import (
    Decision,
    ToolCall,
    ToolPolicy,
    ToolPolicyRegistry,
)
from .receipts import ReceiptChain

__version__ = "0.1.0"

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
    "__version__",
]
