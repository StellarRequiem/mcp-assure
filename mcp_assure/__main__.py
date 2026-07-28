"""CLI: mcp-assure verify-receipts | demo"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile

from .engine import AssureEngine
from .middleware import AssuredRunner
from .policy import ToolCall, ToolPolicy, ToolPolicyRegistry
from .receipts import ReceiptChain


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcp-assure")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify-receipts", help="verify a receipts JSONL file")
    v.add_argument("path")

    d = sub.add_parser("demo", help="run a tiny local demo (no network)")
    d.add_argument("--json", action="store_true")

    args = p.parse_args(argv)

    if args.cmd == "verify-receipts":
        ok, msg = ReceiptChain.verify_file(args.path)
        print(("OK" if ok else "FAIL") + f": {msg}")
        return 0 if ok else 1

    if args.cmd == "demo":
        reg = ToolPolicyRegistry(
            [
                ToolPolicy(
                    name="echo",
                    max_blast=1,
                    allowed_args=("text",),
                    required_args=("text",),
                ),
                ToolPolicy(name="danger_shell", max_blast=1, lab_only=True),
            ]
        )
        with tempfile.TemporaryDirectory() as td:
            path = f"{td}/receipts.jsonl"
            eng = AssureEngine(reg, receipts_path=path)
            runner = AssuredRunner(
                eng,
                handlers={"echo": lambda a: {"echo": a.get("text")}},
            )
            cases = [
                ToolCall(tool="echo", arguments={"text": "hello"}),
                ToolCall(tool="unknown_tool", arguments={}),
                ToolCall(tool="danger_shell", arguments={"cmd": "id"}, lab_mode=False),
            ]
            results = [runner.invoke(c) for c in cases]
            eng2 = AssureEngine(
                ToolPolicyRegistry(
                    [
                        ToolPolicy(
                            name="echo",
                            forbidden_args=("token", "password"),
                            allowed_args=("text",),
                            required_args=("text",),
                        )
                    ]
                ),
                receipts_path=path,
            )
            results.append(
                {
                    "verdict": eng2.evaluate(
                        ToolCall(tool="echo", arguments={"text": "x", "token": "secret"})
                    ).as_dict(),
                    "executed": False,
                    "result": None,
                    "error": None,
                }
            )
            ok, msg = ReceiptChain.verify_file(path)
            if args.json:
                print(json.dumps({"results": results, "receipts": msg}, indent=2))
            else:
                for r in results:
                    vdict = r["verdict"]
                    print(
                        f"{vdict['decision']:7} {vdict['code']:16} "
                        f"exec={r['executed']} tool={vdict.get('tool')}"
                    )
                print(f"receipts: {msg}")
            return 0 if ok else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
