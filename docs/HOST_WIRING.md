# Host wiring — put mcp-assure on a real tools/call path

## Pattern (any MCP host)

Wherever your host would execute a tool:

```python
from mcp_assure import AssureEngine
from mcp_assure.integrations import AssuredToolDispatcher
from mcp_assure.packs import load_pack

engine = AssureEngine(load_pack("baseline"), receipts_path="mcp-assure-receipts.jsonl")
dispatcher = AssuredToolDispatcher(engine, handlers={
    "echo": lambda a: {"echo": a["text"]},
    # register real tools here
})

def on_tools_call(payload: dict):
    out = dispatcher.call_tool(payload)
    if not out["executed"]:
        return {"error": out["verdict"]}  # surface DENY to the model
    return out["result"]
```

## FastMCP-style

Wrap the tool function before registration (see `mcp_assure/integrations/fastmcp_notes.py`):

```python
from mcp_assure.integrations import assure_callable

@assure_callable(engine, name="read_file")
def read_file(path: str) -> str:
    ...
```

## Local proof on this machine

```bash
cd ~/mcp-assure
.venv/bin/python examples/host_demo.py
.venv/bin/python -m mcp_assure purple
```

## Grok / Cursor

These hosts load MCP servers via config; they do not always expose a single Python
`tools/call` hook. Options:

1. **Wrap each MCP server entry** in a thin proxy process that runs AssuredToolDispatcher
2. **Policy at server** — instrument servers you own with `assure_callable`
3. **browser-leash** — separate control plane for browser/X actions (not MCP tools)

Until the host offers a single dispatch hook, treat (2) as the reliable path for
servers you control, and (1) for third-party servers you choose to proxy.

## Residual risk

Any code path that calls tools **without** the dispatcher bypasses the gate.
Document that path or eliminate it.
