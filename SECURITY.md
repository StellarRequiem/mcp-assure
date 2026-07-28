# Security policy — mcp-assure

## Reporting

Report vulnerabilities privately to the maintainer via GitHub Security Advisories on
`StellarRequiem/mcp-assure` (once the repository is published), or through the
contact path on [xclusivexo.com](https://xclusivexo.com).

Please include:

- mcp-assure version / commit  
- minimal reproduction  
- impact (authz bypass, receipt forgery, execution on DENY, etc.)  

Do **not** open a public issue with a working bypass before coordinated disclosure.

## Scope

In scope: authorization bypass of the gate, execution of handlers on DENY/DRY_RUN,
receipt chain integrity failures, unsafe defaults in public examples.

Out of scope: vulnerabilities that require the host to bypass `AssuredRunner`;
prompt injection that never reaches a tool call; third-party MCP servers behind an
ALLOW decision.

## Threat model

See [`THREAT_MODEL.md`](./THREAT_MODEL.md).

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | yes (current) |
| 0.2.x   | yes |
| 0.1.x   | security fixes only |
