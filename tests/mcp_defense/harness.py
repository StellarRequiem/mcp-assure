"""Run mcp-defense-bench on mcp-assure and compare the per-fixture results with the baseline.

Shared by ``test_mcp_defense_bench.py`` (which only reads ``baseline.json``) and
``update_baseline.py`` (the one deliberate way to rewrite it). Dev and benign corpora only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from importlib import metadata, resources
from pathlib import Path
from typing import Any

from mcp_defense_bench import arun
from mcp_defense_bench.adapters.fastmcp import FastMCPAdapter
from mcp_defense_bench.bench import Bench
from mcp_defense_bench.scoring import wired
from operator_pack import operator_pack

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "baseline.json"
RESULTS = HERE / "RESULTS.md"

# What the baseline was recorded against. A mismatch fails the job instead of silently
# comparing results from a different scorer, corpus or FastMCP.
PINS = {
    "mcp-defense-bench": "0.3.0",
    "fastmcp": "4.1.0",
    "mcp": "2.3.0",
}
BENCH_COMMIT = "8f0812572693fe883ed207b476e8523dabcb9787"
MANIFEST_SHA256 = "7a3f7358d1d5fed305b1cd9ba7e2ce5132ccb7de947e9bc7740ed77db0429acd"
SCORER_SOURCE = "https://github.com/Gowthaman90/mcp-defense-bench-py/tree/v0.3.0"

# Why a fixture type is skipped: the FastMCP adapter can only replay tools/list and tools/call,
# so the bench's integrity rule leaves every other type "unknown" rather than scoring a miss.
SKIP_REASONS = {
    "http-request": "HTTP transport headers/body, below the MCP message a middleware sees",
    "http-request-sequence": "HTTP transport headers/body, below the MCP message a middleware sees",
    "scenario": "transport setup (origins, endpoints), not a tool call",
    "server-identity": "server identity / well-known metadata, not a tool call",
    "config-snapshot-diff": "host configuration snapshots, not a tool call",
    "capability-grant": "OAuth-style scope requests, not a tool call",
    "multi-server-registry": "a multi-server deployment (name collisions), not one server's traffic",
    "list-result": "list results with caching/visibility hints, not tools/list or tools/call",
    "cache-invalidation": "client cache and notification behaviour",
}
RANK = {"unknown": -1, "none": 0, "detect": 1, "enforce": 2}


def manifest_sha256() -> str:
    data = resources.files("mcp_defense_bench").joinpath("_bench/MANIFEST.json").read_bytes()
    return hashlib.sha256(data).hexdigest()


def pins() -> dict[str, Any]:
    bench = json.loads(
        resources.files("mcp_defense_bench").joinpath("_bench/MANIFEST.json").read_text("utf8")
    )
    got: dict[str, Any] = {name: metadata.version(name) for name in PINS}
    got["benchCommit"] = bench["benchCommit"]
    got["manifestSha256"] = manifest_sha256()
    got["scorerSource"] = SCORER_SOURCE
    return got


def pin_problems() -> list[str]:
    got = pins()
    want = {**PINS, "benchCommit": BENCH_COMMIT, "manifestSha256": MANIFEST_SHA256}
    return [f"{k}: want {v}, got {got.get(k)}" for k, v in want.items() if got.get(k) != v]


class CountingAdapter:
    """Wraps the scorer's FastMCP adapter so a per-fixture exception is counted, not fatal."""

    def __init__(self) -> None:
        self.inner = FastMCPAdapter(operator_pack, tool="mcp-assure")
        self.meta = self.inner.meta
        self.errors: list[dict[str, str]] = []

    async def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> Any:
        try:
            return await self.inner.assess(input, testcase)
        except Exception as e:  # noqa: BLE001 - recorded; any error fails the regression test
            err = f"{type(e).__name__}: {e}"[:200]
            self.errors.append({"id": str(testcase.get("id")), "error": err})
            return {"detect": False, "enforce": False, "signal": f"error: {err}"}


def _ftype(tc: Mapping[str, Any]) -> str:
    fixture = tc.get("fixture")
    return str(fixture.get("type")) if isinstance(fixture, Mapping) else "?"


def run() -> dict[str, Any]:
    """Score dev + benign and return the per-fixture results in the baseline's shape."""
    bench = Bench.vendored_snapshot()
    adapter = CountingAdapter()
    meta = adapter.inner.meta

    def go(corpus: str) -> dict[str, Any]:
        return asyncio.run(arun(adapter, corpus, bench=bench, measured_at="fixed"))

    dev_cases = bench.load_cases("dev")
    benign_cases = bench.load_cases("benign")
    dev, benign = go("dev"), go("benign")
    types = {tc["id"]: _ftype(tc) for tc in dev_cases + benign_cases}

    cases = {
        c["id"]: {"type": types[c["id"]], "level": c["level"], "falsePositive": c["falsePositive"]}
        for c in dev["cases"]
    }
    items = {
        i["id"]: {"kind": i["kind"], "denied": bool(i["falsePositive"])} for i in benign["items"]
    }
    dev_skipped = {tc["id"]: _ftype(tc) for tc in dev_cases if not wired(meta, tc)}
    benign_skipped = {tc["id"]: _ftype(tc) for tc in benign_cases if not wired(meta, tc)}
    levels = [c["level"] for c in cases.values()]
    s = dev["summary"]
    return {
        "pins": pins(),
        "dev": {
            "summary": {
                "cases": len(dev_cases),
                "scored": len(cases),
                "skipped": len(dev_skipped),
                "errors": sum(e["id"] in cases for e in adapter.errors),
                "enforce": levels.count("enforce"),
                "detect": levels.count("detect"),
                "none": levels.count("none"),
                "matchedFalsePositives": s["falsePositives"],
                "overall": s["overall"],
            },
            "cases": cases,
            "skipped": dev_skipped,
        },
        "benign": {
            "summary": {
                "items": len(benign_cases),
                "scored": len(items),
                "skipped": len(benign_skipped),
                "errors": sum(e["id"] in items for e in adapter.errors),
                "denied": benign["summary"]["falsePositives"],
                "deniedRate95ci": benign["summary"]["fpRate95ci"],
            },
            "items": items,
            "skipped": benign_skipped,
        },
        "errors": adapter.errors,
    }


def compare(base: Mapping[str, Any], cur: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """(regressions, improvements). Regressions fail CI; improvements only ask for an update."""
    bad: list[str] = []
    good: list[str] = []
    bad += [f"scorer error on {e['id']}: {e['error']}" for e in cur["errors"]]
    for corpus, key in (("dev", "cases"), ("benign", "items")):
        b, c = base[corpus][key], cur[corpus][key]
        if set(b) != set(c) or base[corpus]["skipped"] != cur[corpus]["skipped"]:
            bad.append(f"{corpus}: the set of scored/skipped fixtures changed")
    for fid, b in base["dev"]["cases"].items():
        c = cur["dev"]["cases"].get(fid)
        if c is None:
            continue
        if RANK[c["level"]] < RANK[b["level"]] and b["level"] in ("enforce", "detect"):
            bad.append(f"lost attack denial: {fid} {b['level']} -> {c['level']}")
        elif RANK[c["level"]] > RANK[b["level"]]:
            good.append(f"new attack denial: {fid} {b['level']} -> {c['level']}")
        if c["falsePositive"] and not b["falsePositive"]:
            bad.append(f"new benign denial (matched control): {fid}")
        elif b["falsePositive"] and not c["falsePositive"]:
            good.append(f"matched control no longer denied: {fid}")
    for fid, b in base["benign"]["items"].items():
        c = cur["benign"]["items"].get(fid)
        if c is None:
            continue
        if c["denied"] and not b["denied"]:
            bad.append(f"new benign denial: {fid}")
        elif b["denied"] and not c["denied"]:
            good.append(f"benign item no longer denied: {fid}")
    return bad, good
