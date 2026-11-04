# mcp-defense-bench regression check

A CI regression test for mcp-assure's FastMCP middleware on the
[mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) corpus. It is
test-only: nothing in `mcp_assure/` changes, and the core stays zero-dependency.

## What runs

CI job `mcp-defense` (`.github/workflows/ci.yml`) installs the exact pins in `requirements.txt` and
runs `pytest tests/mcp_defense`. Without those pins installed (the main test matrix), the tests skip.

| File | Purpose |
|---|---|
| `requirements.txt` | Exact pins: scorer, FastMCP, MCP SDK |
| `operator_pack.py` | The scored config: `build_assure_middleware` with a pack built from each served tool's `inputSchema` |
| `harness.py` | Runs the scorer (dev + benign only), checks the pins, compares per-fixture results |
| `test_mcp_defense_bench.py` | Pin check, argument smuggling denied before the handler, baseline regression |
| `baseline.json` | Committed per-fixture results: every scored case and item, the skip lists, error list |
| `RESULTS.md` | The same run in readable form, with skip and error counts and the 25 skipped benign items |
| `update_baseline.py` | The only way to rewrite `baseline.json` and `RESULTS.md` |

## Pins

- Scorer: `mcp-defense-bench==0.3.0`, source <https://github.com/Gowthaman90/mcp-defense-bench-py/tree/v0.3.0>.
- Corpus: vendored in the scorer wheel. Bench v0.10.0 (rubric 0.10.0, 41 vectors) at commit
  `8f0812572693fe883ed207b476e8523dabcb9787`; `MANIFEST.json` sha256
  `7a3f7358d1d5fed305b1cd9ba7e2ce5132ccb7de947e9bc7740ed77db0429acd`. The scorer also checks
  every corpus file against that manifest on load.
- `fastmcp==4.1.0` (with `fastmcp-slim==4.1.0`), `mcp==2.3.0` (with `mcp-types==2.3.0`).

`test_scorer_corpus_and_fastmcp_are_the_pinned_versions` fails if any installed version or the
manifest hash differs from `harness.PINS`.

## What fails CI

- **A lost attack denial:** a dev case whose level drops below its baseline `enforce`/`detect`.
- **A new benign denial:** a matched control, or a benign-corpus item, denied where the baseline
  allowed it.
- **Any scorer error,** or a change in which fixtures are scored or skipped.
- **The smuggling check:** `out-of-scope-params/001-argument-smuggling` is served by a real
  FastMCP server whose handler records every invocation. The call with `__exec` must be denied
  with `ARG_POLICY`, and the handler must never run. The matched control must reach the handler
  exactly once.

Improvements (a new denial, or a benign item no longer denied) don't fail. The test prints them
and asks for a deliberate update.

## Updating the baseline (deliberate, never automatic)

```bash
pip install -e ".[dev]" -r tests/mcp_defense/requirements.txt
python tests/mcp_defense/update_baseline.py            # dry run: lists per-fixture changes
python tests/mcp_defense/update_baseline.py --write    # rewrites baseline.json + RESULTS.md
```

Review the diff and commit both files. To move to a new scorer, corpus or FastMCP version, bump
`requirements.txt` and `harness.PINS` together, then run the update. The test suite never writes
these files.

## Coverage: 312 of 337 benign items, 23 of 78 dev cases

The scorer's FastMCP adapter can only replay `tools/list` and `tools/call` traffic through the
middleware. Fixture types it can't express (HTTP transport, server identity, OAuth scope grants,
multi-server registries, host config snapshots, delegation tokens, and so on) stay `unknown` under
the bench's integrity rule. They are not counted as misses. `RESULTS.md` lists the 25 skipped
benign items with the reason for each, and the 55 skipped dev cases by type.

That includes the 12 `authorized-call` cases of bench 0.10.0's authorization family
(`authz-unentitled-tool`, `authz-argument-overreach`, `authz-delegated-agent-overreach`,
`authz-asserted-identity`). Each states a deployment policy and an authenticated caller. The
in-memory FastMCP session this job uses has no authenticated caller, and the scorer's FastMCP
adapter is not wired for that type, so those four vectors stay `unknown` here. They are not
scored as misses or passes. Scoring them would need an adapter that translates each fixture's
policy into an mcp-assure pack and maps its caller to mcp-assure's actor; that is not part of
this job.

Read the numbers as "this pack on this corpus", not as a rating of mcp-assure. mcp-assure gates
tool names and argument names; attacks carried in argument values, tool results or tool
definitions are outside that layer by design.
