# Threat model — mcp-assure

## Asset

The **authority to invoke tools** on behalf of an AI agent (read files, call APIs,
mutate systems, spend tokens). The secondary asset is the **integrity of the
decision record** (receipts).

## Trust boundaries

| Zone | Trust |
|------|--------|
| Model / agent planner | **Untrusted** — may be wrong, jailbroken, or goal-misaligned |
| Host application using mcp-assure | Semi-trusted — must not bypass the gate |
| mcp-assure policy + engine | TCB (trusted computing base) for tool authorization |
| Downstream MCP tools / servers | Untrusted until gated; may be malicious or buggy |
| Receipt log storage | Integrity-sensitive; offline-verifiable |

## Adversaries

1. **Prompt / tool-injection** steering the model to call high-blast tools  
2. **Confused deputy** — agent holds a token for A, model tries tool against B  
3. **Swarm / automation** — thousands of tool calls in a short window  
4. **Policy bypass** — unknown tool name, aliasing, arg smuggling  
5. **Receipt forgery / tamper** — rewrite the audit trail after the fact  
6. **Authority inflation** — “the model said ALLOW” used to override DENY  

## In scope controls

- Deny-by-default tool catalog  
- Argument constraints (required keys, forbidden keys, max depth/size)  
- Audience / resource binding checks (when provided on the call)  
- Velocity ceilings (identity / actor / global)  
- Blast-radius caps  
- Lab-only flags for dangerous tools  
- Freeze mode (narrow allowlist)  
- Hash-chained receipts; verify offline  
- Middleware that **does not invoke** the tool on DENY / DRY_RUN  

## Out of scope (honest)

- Stopping all prompt injection inside the model  
- Cryptographic signatures / multi-party consensus (v0.1 is integrity via hash chain, not keyed authenticity)  
- Full OAuth server implementation (we *check* resource/audience fields when present)  
- Network IDS / host EDR replacement  
- Guaranteeing downstream tool honesty after ALLOW  

## Security properties we claim (must have tests)

| ID | Property |
|----|----------|
| P1 | Unknown tool → DENY |
| P2 | Empty catalog → DENY for any tool |
| P3 | DENY never invokes the tool handler |
| P4 | DRY_RUN never invokes the tool handler |
| P5 | Velocity exceed → DENY |
| P6 | Blast exceed → DENY |
| P7 | Lab tool without lab_mode → DENY |
| P8 | LLM suggestion cannot flip DENY→ALLOW |
| P9 | Receipt chain verifies; tamper fails verify |
| P10 | Freeze blocks non-allowlisted tools |
| P11 | Forbidden arg key → DENY |
| P12 | Resource/audience mismatch → DENY when binding required |

## Residual risk

A compromised host process that imports mcp-assure can still call tools directly
if the application bypasses the middleware. The control is **effective only on
the path that uses `AssuredRunner` / equivalent**. Document this to integrators.
