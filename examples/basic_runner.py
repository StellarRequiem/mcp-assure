#!/usr/bin/env python3
"""Minimal AssuredRunner example (stdlib only; no network)."""

from __future__ import annotations

from mcp_assure import (
    AssureEngine,
    AssuredRunner,
    ToolCall,
    ToolPolicy,
    ToolPolicyRegistry,
)


def main() -> None:
    reg = ToolPolicyRegistry(
        [
            ToolPolicy(
                name="echo",
                required_args=("text",),
                allowed_args=("text",),
                max_blast=1,
            )
        ]
    )
    engine = AssureEngine(reg)
    runner = AssuredRunner(engine, {"echo": lambda a: {"echo": a["text"]}})

    for call in (
        ToolCall(tool="echo", arguments={"text": "hello"}),
        ToolCall(tool="echo", arguments={"text": "x", "token": "no"}),  # extra arg if allowed_args set
        ToolCall(tool="rm_rf", arguments={}),
    ):
        # tighten: second case — allowed_args rejects token only if present in allowed set
        # first policy allows only text; token is extra → DENY
        out = runner.invoke(call)
        v = out["verdict"]
        print(f"{v['decision']:5} {v['code']:14} executed={out['executed']} result={out['result']}")


if __name__ == "__main__":
    main()
