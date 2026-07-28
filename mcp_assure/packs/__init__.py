"""Shipped policy packs — loadable catalogs for common MCP risk classes."""

from __future__ import annotations

import json
import os
from typing import Any

from mcp_assure.policy import ToolPolicyRegistry

_PACK_DIR = os.path.dirname(os.path.abspath(__file__))


def list_packs() -> list[str]:
    return sorted(
        n[: -len(".json")]
        for n in os.listdir(_PACK_DIR)
        if n.endswith(".json") and not n.startswith("_")
    )


def load_pack(name: str) -> ToolPolicyRegistry:
    """Load a built-in pack by name (e.g. ``baseline``, ``mcp_authz_boundaries``)."""
    path = os.path.join(_PACK_DIR, f"{name}.json")
    if not os.path.isfile(path):
        known = ", ".join(list_packs()) or "(none)"
        raise FileNotFoundError(f"unknown pack {name!r}; known: {known}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return ToolPolicyRegistry.from_mapping(data)


def load_pack_raw(name: str) -> dict[str, Any]:
    path = os.path.join(_PACK_DIR, f"{name}.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
