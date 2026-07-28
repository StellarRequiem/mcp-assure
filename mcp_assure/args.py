"""Argument inspection helpers (no external schema lib)."""

from __future__ import annotations

import json
from typing import Any


def arg_byte_size(arguments: dict[str, Any]) -> int:
    try:
        return len(json.dumps(arguments, sort_keys=True, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return 10**9


def arg_depth(obj: Any, depth: int = 0) -> int:
    if isinstance(obj, dict):
        if not obj:
            return depth
        return max(arg_depth(v, depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        if not obj:
            return depth
        return max(arg_depth(v, depth + 1) for v in obj)
    return depth


def validate_arguments(
    arguments: dict[str, Any],
    *,
    required: tuple[str, ...],
    allowed: tuple[str, ...] | None,
    forbidden: tuple[str, ...],
    max_bytes: int,
    max_depth: int,
) -> tuple[bool, str]:
    if not isinstance(arguments, dict):
        return False, "arguments must be an object"
    keys = set(arguments.keys())
    for r in required:
        if r not in keys:
            return False, f"missing required argument: {r}"
    for f in forbidden:
        if f in keys:
            return False, f"forbidden argument present: {f}"
    if allowed is not None:
        extra = keys - set(allowed)
        if extra:
            return False, f"arguments not in allowlist: {sorted(extra)}"
    size = arg_byte_size(arguments)
    if size > max_bytes:
        return False, f"arguments exceed max_arg_bytes ({size}>{max_bytes})"
    depth = arg_depth(arguments)
    if depth > max_depth:
        return False, f"arguments exceed max_arg_depth ({depth}>{max_depth})"
    return True, "ok"
