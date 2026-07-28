"""mcp-assure security CLI — local control-plane checks (no network required).

Positioning (honest): this is a **runtime tool-call assurance** CLI, not a
hosted vulnerability scanner. OpenAI's Codex Security CLI finds/patches code
bugs via their cloud; mcp-assure decides whether an agent tool call may run,
with receipts and adaptive campaign scoring — fully local, zero core deps.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp_assure import __version__
from mcp_assure.adaptive import AdaptiveGate
from mcp_assure.campaign import CampaignWatch, arg_smell_scan
from mcp_assure.engine import AssureEngine
from mcp_assure.middleware import AssuredRunner
from mcp_assure.packs import list_packs, load_pack, load_pack_raw
from mcp_assure.policy import ToolCall, ToolPolicy, ToolPolicyRegistry
from mcp_assure.purple import list_fixtures, run_all
from mcp_assure.receipts import ReceiptChain


def _cmd_status(args: argparse.Namespace) -> int:
    packs = list_packs()
    fixtures = list_fixtures()
    payload = {
        "name": "mcp-assure",
        "version": __version__,
        "role": "runtime_tool_call_assurance_cli",
        "not": [
            "hosted_vulnerability_scanner",
            "full_SOC",
            "oauth_authorization_server",
            "replacement_for_codex_security",
        ],
        "packs": packs,
        "purple_fixtures": fixtures,
        "core_dependencies": [],
        "docs": {
            "proactive": "docs/PROACTIVE_DEFENSE.md",
            "threat_model": "THREAT_MODEL.md",
            "claims": "CLAIMS.md",
        },
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"mcp-assure {__version__} — runtime tool-call assurance CLI")
        print("  local · deny-by-default · adaptive campaign watch · hash-chained receipts")
        print(f"  packs: {', '.join(packs)}")
        print(f"  purple fixtures: {len(fixtures)}")
        print("  not a hosted vuln scanner (see: docs vs Codex Security in README)")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    """CI-friendly control-plane health: purple suite (+ optional campaign)."""
    reports = run_all()
    all_pass = all(r.passed for r in reports)
    camp_ok = True
    camp_snap: dict[str, Any] | None = None
    if not args.skip_campaign:
        eng = AssureEngine(load_pack("agent_eval_strict"))
        gate = AdaptiveGate(
            eng,
            watch=CampaignWatch(escalate_score=5.0, freeze_score=12.0),
            auto_freeze=False,
        )
        for i in range(6):
            gate.evaluate(
                ToolCall(
                    tool=f"probe_{i}",
                    arguments={},
                    source=f"synth.sandbox.{i}",
                )
            )
        gate.evaluate(
            ToolCall(
                tool="echo",
                arguments={
                    "text": "{{ cycler.__init__.__globals__.__builtins__.exec('x') }}"
                },
                source="synth.sandbox.x",
            )
        )
        camp_snap = gate.watch.snapshot().as_dict()
        # Health: detector must fire on synthetic agentic shape
        camp_ok = (
            camp_snap.get("score", 0) >= 5.0
            and camp_snap.get("recommendation") in ("escalate", "freeze")
        )

    out = {
        "ok": all_pass and camp_ok,
        "version": __version__,
        "purple": [r.as_dict() for r in reports],
        "campaign": camp_snap,
        "campaign_ok": camp_ok,
    }
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        for r in reports:
            mark = "PASS" if r.passed else "FAIL"
            print(f"[{mark}] purple/{r.fixture_id}")
        if camp_snap is not None:
            mark = "PASS" if camp_ok else "FAIL"
            print(
                f"[{mark}] campaign/synthetic "
                f"score={camp_snap.get('score')} rec={camp_snap.get('recommendation')}"
            )
        print(
            f"\n# control-plane check: "
            f"{'OK' if out['ok'] else 'FAIL'} (mcp-assure {__version__})"
        )
    return 0 if out["ok"] else 1


def _cmd_evaluate(args: argparse.Namespace) -> int:
    pack = args.pack
    try:
        reg = load_pack(pack)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    arguments: dict[str, Any] = {}
    if args.args_json:
        arguments = json.loads(args.args_json)
    call = ToolCall(
        tool=args.tool,
        arguments=arguments,
        actor=args.actor,
        source=args.source,
        lab_mode=bool(args.lab),
    )
    smells = [s.as_dict() for s in arg_smell_scan(call.arguments)]
    if args.adaptive:
        gate = AdaptiveGate(
            AssureEngine(reg),
            watch=CampaignWatch(),
            auto_freeze=False,
        )
        ar = gate.evaluate(call)
        payload = {
            "verdict": ar.verdict.as_dict(),
            "adapted": ar.adapted,
            "adaptation": ar.adaptation,
            "campaign": ar.snapshot.as_dict(),
            "arg_smells": smells,
        }
    else:
        v = AssureEngine(reg).evaluate(call)
        payload = {"verdict": v.as_dict(), "arg_smells": smells}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        vd = payload["verdict"]
        print(f"{vd['decision']:8} {vd['code']:22} {vd.get('detail', '')[:80]}")
        if smells:
            print("arg_smells:", ", ".join(s["code"] for s in smells))
        if "campaign" in payload:
            c = payload["campaign"]
            print(f"campaign: score={c['score']} rec={c['recommendation']}")
    return 0 if payload["verdict"].get("allowed") else 1


def _cmd_packs(args: argparse.Namespace) -> int:
    if args.json:
        data = []
        for name in list_packs():
            raw = load_pack_raw(name)
            data.append({"name": name, "meta": raw.get("meta") or {}})
        print(json.dumps(data, indent=2))
        return 0
    for name in list_packs():
        meta = load_pack_raw(name).get("meta") or {}
        print(f"{name:24} {meta.get('description', '')[:70]}")
    return 0


def _cmd_purple(args: argparse.Namespace) -> int:
    reports = run_all()
    if args.json:
        print(json.dumps([r.as_dict() for r in reports], indent=2))
    else:
        for r in reports:
            mark = "PASS" if r.passed else "FAIL"
            print(f"[{mark}] {r.fixture_id} — {r.as_dict()['summary']}")
        print(
            f"\n# {len(reports)} fixture(s) — "
            f"{'ALL PASS' if all(r.passed for r in reports) else 'FAILURES'}"
        )
    return 0 if all(r.passed for r in reports) else 1


def _cmd_campaign(args: argparse.Namespace) -> int:
    eng = AssureEngine(load_pack("agent_eval_strict"))
    gate = AdaptiveGate(
        eng,
        watch=CampaignWatch(escalate_score=5.0, freeze_score=12.0),
        auto_freeze=False,
    )
    rows = []
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


def _cmd_verify_receipts(args: argparse.Namespace) -> int:
    ok, msg = ReceiptChain.verify_file(args.path)
    print(("OK" if ok else "FAIL") + f": {msg}")
    return 0 if ok else 1


def _cmd_demo(args: argparse.Namespace) -> int:
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-assure",
        description=(
            "Open-source security CLI for MCP-style agent tool calls: "
            "deny-by-default policy, adaptive campaign watch, hash-chained receipts. "
            "Local only — not a hosted vulnerability scanner."
        ),
        epilog=(
            "Quick start:  mcp-assure status | mcp-assure check | mcp-assure purple\n"
            "Docs: https://github.com/StellarRequiem/mcp-assure"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"mcp-assure {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="version, packs, role (what this CLI is / is not)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_status)

    c = sub.add_parser(
        "check",
        help="CI control-plane health: purple fixtures + synthetic campaign detector",
    )
    c.add_argument("--json", action="store_true")
    c.add_argument(
        "--skip-campaign",
        action="store_true",
        help="only run purple fixtures",
    )
    c.set_defaults(func=_cmd_check)

    e = sub.add_parser("evaluate", help="authorize one tool call against a pack")
    e.add_argument("--tool", required=True)
    e.add_argument("--args-json", default="{}", help='JSON object, default "{}"')
    e.add_argument("--pack", default="baseline")
    e.add_argument("--actor", default="agent")
    e.add_argument("--source", default="cli")
    e.add_argument("--lab", action="store_true")
    e.add_argument("--adaptive", action="store_true", help="use AdaptiveGate")
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=_cmd_evaluate)

    pk = sub.add_parser("packs", help="list built-in policy packs")
    pk.add_argument("--json", action="store_true")
    pk.set_defaults(func=_cmd_packs)

    pu = sub.add_parser("purple", help="run purple stress fixtures")
    pu.add_argument("--json", action="store_true")
    pu.set_defaults(func=_cmd_purple)

    camp = sub.add_parser("campaign", help="synthetic agentic campaign demo (no network)")
    camp.add_argument("--json", action="store_true")
    camp.set_defaults(func=_cmd_campaign)
    # Compat alias (Python <3.13 has no subparser aliases)
    camp_old = sub.add_parser("campaign-demo", help=argparse.SUPPRESS)
    camp_old.add_argument("--json", action="store_true")
    camp_old.set_defaults(func=_cmd_campaign)

    v = sub.add_parser("verify-receipts", help="verify a receipts JSONL file")
    v.add_argument("path")
    v.set_defaults(func=_cmd_verify_receipts)

    d = sub.add_parser("demo", help="tiny local gate demo (no network)")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=_cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
