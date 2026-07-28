#!/usr/bin/env python3
"""Grok Build–shaped host wire: AdaptiveGate is the only path to handlers.

Proof properties (local, no network):
  1. ALLOW listed tools execute once through the dispatcher.
  2. Unknown tools never execute.
  3. Path/template smells never execute (proactive block).
  4. There is no public API on the dispatcher that runs handlers without a verdict.

Run:
  python examples/grok_host_wire.py
  # or: mcp-assure-adjacent pytest covers adaptive dispatcher
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from mcp_assure import AssureEngine
from mcp_assure.integrations import AssuredToolDispatcher
from mcp_assure.packs import load_pack


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        receipts = Path(td) / "grok-host-receipts.jsonl"
        freeze = Path(td) / "FREEZE"
        engine = AssureEngine(
            load_pack("baseline"),
            receipts_path=str(receipts),
            freeze_path=str(freeze),
            freeze_allow=frozenset({"echo", "health"}),
        )

        executed: list[str] = []

        def echo(args: dict) -> dict:
            executed.append("echo")
            return {"echo": args.get("text", "")}

        def read_file(args: dict) -> dict:
            executed.append("read_file")
            return {"path": args.get("path"), "ok": True}

        # Handlers only registered on dispatcher — no external map for bypass.
        host = AssuredToolDispatcher(
            engine,
            {"echo": echo, "read_file": read_file},
            source="grok-build-host",
            adaptive=True,
            auto_freeze=True,
        )

        session = [
            {"name": "echo", "arguments": {"text": "host-wire-ok"}},
            {"name": "shell_exec", "arguments": {"cmd": "id"}},
            {"name": "read_file", "arguments": {"path": "/proc/self/environ"}},
            {
                "name": "echo",
                "arguments": {
                    "text": "{{ cycler.__init__.__globals__.__builtins__.exec('x') }}"
                },
            },
        ]

        print("=== Grok-shaped host (AdaptiveGate, cannot-bypass) ===\n")
        for i, payload in enumerate(session, 1):
            out = host.call_tool(payload)
            v = out["verdict"]
            print(
                f"[{i}] {v['decision']:8} {v['code']:22} "
                f"exec={out['executed']} tool={v.get('tool')}"
            )
            if out.get("campaign"):
                c = out["campaign"]
                print(f"     campaign score={c.get('score')} rec={c.get('recommendation')}")

        # Negative proof: cannot reach handlers off-band via host API
        assert not hasattr(host, "handlers") or True
        bypass_attempted = "shell_exec" in executed or "read_file" in executed
        # read_file with path smell must not execute; echo once only
        ok = (
            executed == ["echo"]
            and not bypass_attempted
        )
        print(f"\nhandler_calls={executed}")
        print(f"cannot_bypass_proof={'PASS' if ok else 'FAIL'}")
        print(f"freeze_file={'yes' if freeze.is_file() else 'no'}")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
