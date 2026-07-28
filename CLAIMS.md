# Claim gate — mcp-assure

Public language must stay **≤ evidence**. Adversarial review will check this file
against README and tests.

## Allowed now (after `pytest` green on this commit)

| Claim | Evidence |
|-------|----------|
| Deny-by-default tool authorization for agent tool calls | P1, P2 tests |
| Policy can block by velocity, blast, lab flag, freeze, forbidden args | P5–P7, P10–P11 |
| Decision receipts are hash-chained and tamper-detecting | P9 |
| Model text cannot authorize a denied call | P8 |
| Middleware does not execute tool on DENY/DRY_RUN | P3, P4 |
| Zero runtime dependencies for the core package | `pyproject.toml` |
| Built-in policy packs load and authorize only listed tools | `tests/test_control_plane_v1.py` |
| Purple fixtures (unknown tool, authz bindings, velocity) pass | `python -m mcp_assure purple` |
| Host dispatcher + decorator integration paths exist | integration tests |
| FastMCP `on_call_tool` middleware denies unknown tools without calling handler | `tests/test_fastmcp_mw.py` + async smoke |
| Optional verity hook soft-fails without verity installed | verity hook tests |

## Not allowed (do not put on site/X yet)

| Overclaim | Why |
|-----------|-----|
| “Full SOC” / “enterprise SOC platform” | Wrong product class; no SIEM/IR product surface |
| “Stops all MCP attacks” / “unbreakable” | Out of scope per threat model |
| “CVE-proof” / scanner replacement | mcp-bench shows different problem; this is a runtime gate |
| “OAuth complete” / “implements full 2026-07-28 auth” | We check bindings when provided; we are not an AS |
| “Proven in production at scale” | No public deploy proof yet |
| Any win-rate / detection-rate % without holdout study | N/A and forbidden |

## Recommended public wording

> **mcp-assure** is a plug-in, deny-by-default assurance layer for MCP-style tool
> calls: policy packs, rate/blast limits, resource/audience binding checks, and
> hash-chained decision receipts — with a re-runnable purple stress suite. The
> model proposes; the gate decides. It is not a full SOC and not a guarantee
> against all agent misuse.

## State

**Candidate → Verified locally** when CI/tests pass on the published tree.  
**Published** only after operator push + live install proof.
