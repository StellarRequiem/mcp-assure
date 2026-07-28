# mcp-assure

**Deny-by-default assurance runtime for MCP-style tool calls.**

The model proposes. **The gate decides.** Receipts remember.

`mcp-assure` is a plug-in control plane you put **in front of tool execution**: policy catalog, argument constraints, optional resource/audience binding checks, velocity and blast limits, freeze mode, and **hash-chained decision receipts**. It is **not** a full SOC, not a scanner, and not a claim that all agent misuse is impossible.

Built by [Alex Price / StellarRequiem](https://xclusivexo.com). Apache-2.0. **Zero runtime dependencies.**

## Why this exists

MCP hosts give agents tools. Tools are power. Under MCP **2026-07-28**, more security responsibility sits with implementers (stateless core, auth expectations, extensions). Scanners help at build time; **runtime authorization** is still required at the moment of `tools/call`.

## Install

```bash
pip install -e ".[dev]"    # from a checkout
# later: pip install mcp-assure
```

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

## CLI

```bash
python -m mcp_assure demo
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
