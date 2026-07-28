"""FastMCP / MCP SDK integration notes (no hard dependency).

FastMCP and official SDKs evolve quickly (especially around the 2026-07-28
spec). mcp-assure stays SDK-agnostic: wrap the function that *executes* a
tool, not the wire protocol.

## Pattern A — FastMCP middleware (preferred)

```python
from fastmcp import FastMCP
from mcp_assure import AssureEngine
from mcp_assure.packs import load_pack
from mcp_assure.integrations import build_assure_middleware

engine = AssureEngine(load_pack("baseline"), receipts_path="receipts.jsonl")
mcp = FastMCP("secured")
mcp.add_middleware(build_assure_middleware(engine))
```

## Pattern B — wrap handlers before registration

```python
from mcp_assure import AssureEngine, ToolPolicy, ToolPolicyRegistry
from mcp_assure.integrations import assure_callable

engine = AssureEngine(ToolPolicyRegistry([
    ToolPolicy(name="add", required_args=("a", "b"), allowed_args=("a", "b")),
]))

@assure_callable(engine, name="add")
def add(a: int, b: int) -> int:
    return a + b

# Then register ``add`` with your MCP server / FastMCP as usual.
```

## Pattern C — host dispatch intercept

Wherever the host would run ``tools/call``:

```python
from mcp_assure.integrations import AssuredToolDispatcher

dispatcher = AssuredToolDispatcher(engine, {"add": lambda a: a["a"] + a["b"]})
out = dispatcher.call_tool({"name": "add", "arguments": {"a": 1, "b": 2}})
if not out["executed"]:
    # return MCP error / tool result error to the model
    ...
return out["result"]
```

## Pattern D — policy from pack

```python
from mcp_assure.packs import load_pack
engine = AssureEngine(load_pack("baseline"))
```

Do **not** put secrets in tool arguments. Forbidden-arg policies help, but
application code must still avoid echoing credentials into receipts (mcp-assure
strips common secret *metadata keys* from receipts, not arg values you choose
to log yourself).
"""
