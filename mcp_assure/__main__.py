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

    p_packs = sub.add_parser("packs", help="list built-in policy packs")
    p_purple = sub.add_parser("purple", help="run purple stress fixtures")
    p_purple.add_argument("--json", action="store_true")

    p_camp = sub.add_parser(
        "campaign-demo",
        help="proactive campaign watch demo (synthetic swarm; no network)",
    )
    p_camp.add_argument("--json", action="store_true")

    args = p.parse_args(argv)

    if args.cmd == "packs":
        from .packs import list_packs, load_pack_raw

        for name in list_packs():
            meta = (load_pack_raw(name).get("meta") or {})
            print(f"{name:24} {meta.get('description', '')[:70]}")
        return 0

    if args.cmd == "purple":
        from .purple import run_all

        reports = run_all()
        all_pass = True
        if args.json:
            print(json.dumps([r.as_dict() for r in reports], indent=2))
        else:
            for r in reports:
                all_pass = all_pass and r.passed
                mark = "PASS" if r.passed else "FAIL"
                print(f"[{mark}] {r.fixture_id} — {r.as_dict()['summary']}")
            print(f"\n# {len(reports)} fixture(s) — {'ALL PASS' if all_pass else 'FAILURES'}")
        return 0 if all(r.passed for r in reports) else 1

    if args.cmd == "campaign-demo":
        from .adaptive import AdaptiveGate
        from .campaign import CampaignWatch
        from .packs import load_pack

        eng = AssureEngine(load_pack("agent_eval_strict"))
        gate = AdaptiveGate(
            eng,
            watch=CampaignWatch(escalate_score=5.0, freeze_score=12.0),
            auto_freeze=False,
        )
        rows = []
        # synthetic ephemeral-source recon spray (HF-class shape, not a live attack)
        for i in range(8):
            ar = gate.evaluate(
                ToolCall(
                    tool=f"probe_{i}",
                    arguments={"path": "/proc/self/environ"} if i == 3 else {},
                    source=f"synth.sandbox.{i}",
                    actor="agent",
                )
            )
            rows.append(ar.as_dict())
        # template-class arg
        ar = gate.evaluate(
            ToolCall(
                tool="echo",
                arguments={
                    "text": "{{ cycler.__init__.__globals__.__builtins__.exec('x') }}"
                },
                source="synth.sandbox.x",
            )
        )
        rows.append(ar.as_dict())
        snap = gate.watch.snapshot().as_dict()
        if args.json:
            print(json.dumps({"steps": rows, "final": snap}, indent=2))
        else:
            for r in rows:
                v = r["verdict"]
                print(
                    f"{v['decision']:8} {v['code']:22} "
                    f"adapted={r['adapted']} score={r['campaign']['score']}"
                )
            print(
                f"\nfinal recommendation={snap['recommendation']} "
                f"score={snap['score']} codes={snap['top_codes']}"
            )
        return 0

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
