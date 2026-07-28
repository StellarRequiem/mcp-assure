"""CLI entry: python -m mcp_assure | mcp-assure"""

from __future__ import annotations

import sys

from mcp_assure.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
