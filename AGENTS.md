# Agents working on mcp-assure

- **Facts over narrative.** Claims in README must match `CLAIMS.md` and tests.
- **No claim inflation.** Never market as a full SOC.
- **Deny by default** stays non-negotiable.
- **Handlers never run on DENY/DRY_RUN.**
- Prefer zero runtime deps for core.
- Add a property test when adding a security control.
- Do not commit real secrets, private host paths, or ADM classified material.
