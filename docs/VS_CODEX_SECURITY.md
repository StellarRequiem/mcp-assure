# mcp-assure vs OpenAI Codex Security CLI

**Claim boundary:** product-class comparison only. No win-rates. No “better than OpenAI.”

OpenAI open-sourced client tooling for **Codex Security**
([`openai/codex-security`](https://github.com/openai/codex-security)) — a CLI/SDK that
talks to their **hosted** security service to find, validate, and help fix
vulnerabilities in source code.

**mcp-assure** is a different layer. Following that open-client pattern *appropriately*
means shipping a clear, re-runnable **security CLI for the agent tool plane**, not
cloning a cloud scanner.

| | **Codex Security CLI** | **mcp-assure CLI** |
|--|------------------------|--------------------|
| **Job** | Find / validate / patch **code** vulns | Authorize **tool calls** at runtime |
| **When** | Build, PR, CI scan | Agent proposes `tools/call` |
| **Network** | Needs OpenAI access / API key | **None** for core gate |
| **Core deps** | Node + Python + cloud service | **Zero** runtime deps (core) |
| **Output** | Findings, patches, SARIF-class | ALLOW/DENY/ESCALATE + receipts |
| **Adaptive** | Model-driven analysis | Campaign shape score + freeze |
| **Human gate** | Review findings / merge patches | Host must not bypass runner |

## What we open-sourced (and why)

```bash
pip install mcp-assure
mcp-assure status          # what this is / is not
mcp-assure check           # purple + synthetic campaign detector (CI)
mcp-assure evaluate --tool echo --args-json '{"text":"hi"}'
mcp-assure purple
mcp-assure campaign
mcp-assure verify-receipts ./receipts.jsonl
```

After the July 2026 agentic-intrusion class of events, **runtime authority**
(who may call which tool, how fast, with what argument shape) is as important as
repo scanning. Scanners do not stop a live agent mid-chain; a gate can.

## What we do not claim

- That mcp-assure replaces Codex Security, EDR, or SAST  
- That open-sourcing a CLI equals open-sourcing frontier cyber models  
- End-to-end prevention of sandbox escape or data-plane RCE  

Use **both classes of tool** when you can: scan code before ship; gate tools at run.
