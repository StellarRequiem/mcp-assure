# Proactive defense posture (agentic campaigns)

**Claim boundary:** This document describes **library-level** controls for
MCP-style tool gates. It is not a full SOC, not a guarantee against 0-days, and
not a claim that mcp-assure would have stopped the July 2026 Hugging Face
intrusion end-to-end. It encodes the **lesson**: blocking only the last known
exploit is too late.

## Why adaptive, not only reactive

Public HF technical timeline (July 2026): ~17k low-signal actions; successful
path hidden in failed probes; multi-boundary chain; product surfaces used as
dead-drops. A catalog that only lists yesterday’s bad tools will miss tomorrow’s
chain.

**Posture:**

| Layer | Role |
|-------|------|
| **Static pack** | Deny-by-default catalog, arg constraints, blast, velocity |
| **Smell pre-block** | Class markers (path/IMDS, template/RCE, packer) → DENY *now* |
| **Campaign watch** | Sliding window: swarm sources, tool spray, unknown burst, probe ratio |
| **Adaptive escalate/freeze** | Score crosses threshold → ESCALATE or FREEZE before novel completion |
| **Receipts** | Hash-chained decisions — IR starts with a chain, not a jigsaw |

## Packs

| Pack | Use |
|------|-----|
| `baseline` | Local agent hosts |
| `strict_local` | Minimal surface |
| `mcp_authz_boundaries` | Resource/audience binding class |
| **`agent_eval_strict`** | Cyber/eval harnesses — tiny allowlist, lab-gated tools |

Cyber evals with real egress remain a **live-fire** problem; this pack is not
network isolation.

## Operators

```bash
python -m mcp_assure purple          # includes adaptive fixtures
python -m mcp_assure campaign-demo   # synthetic swarm + template smell
python -m mcp_assure packs
```

```python
from mcp_assure import AssureEngine, AdaptiveGate, ToolCall
from mcp_assure.packs import load_pack
from mcp_assure.campaign import CampaignWatch

engine = AssureEngine(
    load_pack("agent_eval_strict"),
    freeze_path="./FREEZE",
    freeze_allow=frozenset({"echo", "health"}),
)
gate = AdaptiveGate(
    engine,
    watch=CampaignWatch(),
    auto_freeze=True,  # touch FREEZE when score high
)
result = gate.evaluate(ToolCall(tool="echo", arguments={"text": "ok"}))
# result.verdict / result.snapshot.recommendation
```

## Purple fixtures (proactive)

| Fixture | Shape |
|---------|--------|
| `agentic_tool_spray` | Ephemeral sources + unknown tools → escalate/freeze score |
| `encoded_staging_shape` | gzip/b64 + template markers → `PROACTIVE_ARG_BLOCK` |
| `path_smell_recon` | `/proc`, k8s secrets path, IMDS-class → block + score |

## Map: public HF phases → control class

| HF-class phase | Proactive control here | Still host-owned |
|----------------|------------------------|------------------|
| Swarm sandboxes | `SWARM_SOURCES`, velocity | Network identity per sandbox |
| Dataset loader RCE | `TEMPLATE_SMELL`, `PATH_SMELL` | Disable config RCE in data plane |
| IMDS / secrets | path smells + freeze | Block metadata from pods |
| Dead-drop C2 | encoded/packer smells | Product-API abuse analytics |
| Supply-chain write | unknown tools + escalate | SCM admission, short-lived tokens |

## What we refuse to claim

- “Stops autonomous frontier agents”
- “CVE-proof” / “replaces EDR”
- “Would have fully contained OpenAI→HF”

We **do** claim: re-runnable purple fixtures; deny-by-default static gate;
proactive class-based arg blocks; adaptive campaign scoring with escalate/freeze
hooks — verified by `pytest` and `python -m mcp_assure purple`.
