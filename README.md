# mcp-assure

[![ci](https://github.com/StellarRequiem/mcp-assure/actions/workflows/ci.yml/badge.svg)](https://github.com/StellarRequiem/mcp-assure/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

**Deny-by-default assurance runtime for MCP-style tool calls.**

The model proposes. **The gate decides.** Receipts remember.

`mcp-assure` is a plug-in control plane you put **in front of tool execution**: policy catalog, argument constraints, optional resource/audience binding checks, velocity and blast limits, freeze mode, and **hash-chained decision receipts**. It is **not** a full SOC, not a scanner, and not a claim that all agent misuse is impossible.

Built by [Alex Price / StellarRequiem](https://xclusivexo.com). Apache-2.0. **Zero runtime dependencies** (core).  
Version **0.2.2** adds **proactive campaign detection** (swarm/spray/path/template smells → escalate/freeze), `agent_eval_strict` pack, FastMCP middleware, policy packs, purple stress fixtures, and an optional verity hook.

**Public page:** [xclusivexo.com/mcp-assurance/#mcp-assure](https://xclusivexo.com/mcp-assurance/#mcp-assure)

## Why this exists

MCP hosts give agents tools. Tools are power. Under MCP **2026-07-28**, more security responsibility sits with implementers (stateless core, auth expectations, extensions). Scanners help at build time; **runtime authorization** is still required at the moment of `tools/call`.

## Install

```bash
pip install mcp-assure
# optional FastMCP middleware:
pip install "mcp-assure[fastmcp]"
# from git (development tip):
pip install "git+https://github.com/StellarRequiem/mcp-assure"
# from a checkout:
pip install -e ".[dev,fastmcp]"
```

## Real host demo (local)

Simulates an MCP host `tools/call` path with `AssuredToolDispatcher`:

```bash
python examples/host_demo.py
```

Expect: ALLOW for allowlisted tools, DENY for unknown tools / smuggled args, receipts verify.

## 60-second integration

```python
from mcp_assure import (
    AssureEngine,
    AssuredRunner,
    ToolCall,
    ToolPolicy,
    ToolPolicyRegistry,
)

registry = ToolPolicyRegistry([
    ToolPolicy(
        name="read_file",
        required_args=("path",),
        allowed_args=("path",),
        forbidden_args=("token", "password"),
        max_blast=1,
    ),
])

engine = AssureEngine(registry, receipts_path="./mcp-assure-receipts.jsonl")

def read_file(args):
    # your real implementation
    return open(args["path"], encoding="utf-8").read()

runner = AssuredRunner(engine, handlers={"read_file": read_file})

out = runner.invoke(ToolCall(tool="read_file", arguments={"path": "README.md"}))
# out["executed"] is True only if the gate ALLOWed
# out["verdict"]["receipt_hash"] is the audit seal for this decision
```

**Property:** on `DENY` / `DRY_RUN`, the handler is **never** called.

## What it enforces (tested)

| ID | Property |
|----|----------|
| P1 | Unknown tool → DENY |
| P2 | Empty catalog → DENY |
| P3–P4 | DENY/DRY_RUN never invoke handlers |
| P5–P6 | Velocity / blast limits |
| P7 | `lab_only` tools require `lab_mode` |
| P8 | Model notes cannot flip DENY→ALLOW |
| P9 | Receipt chain verifies; tamper fails |
| P10 | Freeze mode blocks non-allowlisted tools |
| P11 | Forbidden / disallowed args → DENY |
| P12 | Resource/audience mismatch → DENY when configured |

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) and [`CLAIMS.md`](./CLAIMS.md).

## Policy from JSON

```python
import json
from mcp_assure import AssureEngine, ToolPolicyRegistry

with open("examples/policy.example.json") as f:
    reg = ToolPolicyRegistry.from_mapping(json.load(f))
engine = AssureEngine(reg)
```

## MCP-shaped payloads

```python
from mcp_assure.mcp_types import tool_call_from_mcp
from mcp_assure import AssureEngine, ToolPolicy, ToolPolicyRegistry

engine = AssureEngine(ToolPolicyRegistry([ToolPolicy(name="echo")]))
call = tool_call_from_mcp({"name": "echo", "arguments": {"text": "hi"}})
print(engine.evaluate(call).as_dict())
```

## Policy packs

```python
from mcp_assure import AssureEngine, load_pack

engine = AssureEngine(load_pack("baseline"))
# also: mcp_authz_boundaries, strict_local
```

```bash
python -m mcp_assure packs
```

`mcp_authz_boundaries` encodes **runtime** gates for resource/audience-style failures (the class of bugs mcp-bench measures in scanners) — call-time enforcement, not a scanner replacement.

## Host / FastMCP integration

```python
from mcp_assure.integrations import AssuredToolDispatcher, assure_callable
# See mcp_assure/integrations/fastmcp_notes.py for patterns.
```

Dispatcher is the usual host hook for `tools/call`. Decorators wrap kwargs-style tool functions before registration.

### FastMCP middleware (`on_call_tool`)

Requires `pip install "mcp-assure[fastmcp]"` (FastMCP ≥2.9):

```python
from fastmcp import FastMCP
from mcp_assure import AssureEngine
from mcp_assure.packs import load_pack
from mcp_assure.integrations import build_assure_middleware

engine = AssureEngine(load_pack("baseline"), receipts_path="receipts.jsonl")
mcp = FastMCP("secured")
mcp.add_middleware(build_assure_middleware(engine))

@mcp.tool
def echo(text: str) -> dict:
    return {"echo": text}
```

On DENY the middleware raises `ToolError` and **does not** call the tool handler.  
Demo: `python examples/fastmcp_assured.py`

## Proactive campaign watch (adaptive)

Static allowlists are necessary but not sufficient: agentic campaigns hide in
**volume and shape**. Wrap the engine with `AdaptiveGate`:

```python
from mcp_assure import AssureEngine, AdaptiveGate, ToolCall
from mcp_assure.packs import load_pack

engine = AssureEngine(load_pack("agent_eval_strict"), freeze_path="./FREEZE")
gate = AdaptiveGate(engine, auto_freeze=True)
out = gate.evaluate(ToolCall(tool="echo", arguments={"text": "ok"}))
print(out.snapshot.recommendation, out.verdict.code)
```

- **Pre-block:** path/IMDS, template/RCE-class, gzip+base64 packer markers → `PROACTIVE_ARG_BLOCK`
- **Window score:** swarm sources, tool spray, unknown-tool burst, probe-dominated traffic
- **Adapt:** `escalate` (human before execute) or `freeze` (touch freeze file; only freeze-allow tools)

```bash
python -m mcp_assure campaign-demo
```

See [`docs/PROACTIVE_DEFENSE.md`](./docs/PROACTIVE_DEFENSE.md).

## Purple stress suite

Synthetic adversarial sequences (no network), including adaptive fixtures:

```bash
python -m mcp_assure purple
```

## Optional verity hook

If `verity-core` is installed, claim-like tool results can be soft-checked:

```python
from mcp_assure.verity_hook import maybe_verify_tool_result
maybe_verify_tool_result({"accuracy": 0.99, "sample_size": 5})
```

Not required; no-ops cleanly when verity is absent.

## CLI

```bash
python -m mcp_assure demo
python -m mcp_assure packs
python -m mcp_assure purple
python -m mcp_assure verify-receipts ./mcp-assure-receipts.jsonl
```

## Adversarial stance

This package is designed to survive **hostile review**:

- Explicit threat model and claim gate  
- Properties P1–P12 locked to unit tests  
- No runtime deps in the TCB surface  
- Residual risk documented (host must not bypass the runner)  

```bash
pytest -q
```

## What this is not

- Not a replacement for OAuth authorization servers  
- Not host EDR / network IDS  
- Not “stops all prompt injection”  
- Not a full enterprise SOC platform  

## Related work (StellarRequiem)

- [mcp-bench](https://github.com/StellarRequiem/mcp-bench) — do scanners catch authz-logic bugs?  
- [scope-gate](https://github.com/StellarRequiem/scope-gate) — deny-by-default research authorization  
- [verity-core](https://github.com/StellarRequiem/verity-core) — refuse bad claims; audit chains  

## License

Apache-2.0. Copyright 2026 Alex Price / StellarRequiem.
