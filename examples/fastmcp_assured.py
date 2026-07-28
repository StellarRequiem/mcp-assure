#!/usr/bin/env python3
"""Minimal FastMCP server with mcp-assure on_call_tool middleware.

Requires: pip install "mcp-assure[fastmcp]"   # or: pip install fastmcp

Run (stdio)::

    python examples/fastmcp_assured.py

Then point an MCP client at this process. Unknown tools / forbidden args
are denied before the handler runs; receipts land in ./mcp-assure-fastmcp.jsonl
when the gate evaluates.
"""

from __future__ import annotations

import sys
from pathlib import Path

# allow running from repo without install
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from fastmcp import FastMCP
except ImportError:
    print("fastmcp not installed. pip install 'mcp-assure[fastmcp]'", file=sys.stderr)
    raise SystemExit(2)

from mcp_assure import AssureEngine
from mcp_assure.integrations.fastmcp_mw import build_assure_middleware
from mcp_assure.packs import load_pack


def main() -> int:
    receipts = ROOT / "mcp-assure-fastmcp.jsonl"
    engine = AssureEngine(load_pack("baseline"), receipts_path=str(receipts))
    mcp = FastMCP("mcp-assure-demo")
    mcp.add_middleware(build_assure_middleware(engine, source="fastmcp-example"))

    @mcp.tool
    def echo(text: str) -> dict:
        """Echo text (allowlisted in baseline pack)."""
        return {"echo": text}

    @mcp.tool
    def read_file(path: str) -> dict:
        """Read a short file under the package root (demo sandbox)."""
        target = (ROOT / path).resolve()
        if not str(target).startswith(str(ROOT.resolve())):
            raise PermissionError("path escapes workspace")
        data = target.read_text(encoding="utf-8")[:400]
        return {"path": path, "preview": data}

    # Intentional: shell_exec is NOT in baseline pack → DENY at middleware
    @mcp.tool
    def shell_exec(cmd: str) -> dict:
        return {"ran": cmd}  # never reached if gate works

    print(
        f"mcp-assure FastMCP demo — receipts → {receipts}\n"
        "tools: echo (ALLOW), read_file (ALLOW), shell_exec (DENY by pack)",
        file=sys.stderr,
    )
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
