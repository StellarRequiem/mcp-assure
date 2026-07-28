"""mcp-assure — deny-by-default assurance runtime for MCP tool calls.

The model proposes. The gate decides. Receipts remember.
"""

from .adaptive import AdaptiveGate, AdaptiveResult
from .campaign import CampaignSnapshot, CampaignWatch, arg_smell_scan
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

__version__ = "0.3.1"

__all__ = [
    "AdaptiveGate",
    "AdaptiveResult",
    "AssureEngine",
    "AssuredRunner",
    "CampaignSnapshot",
    "CampaignWatch",
    "Decision",
    "ReceiptChain",
    "ToolCall",
    "ToolDenied",
    "ToolPolicy",
    "ToolPolicyRegistry",
    "Verdict",
    "arg_smell_scan",
    "list_packs",
    "load_pack",
    "__version__",
]
