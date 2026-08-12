# dockerfile-audit-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Live on MCPize](https://img.shields.io/badge/Live%20on-MCPize-6d28d9)](https://mcpize.com/mcp/dockerfile-audit-mcp)

An MCP server that audits Dockerfiles for real container-security anti-patterns. Parses actual Dockerfile
structure (instructions, backslash line continuations, multi-stage builds) via a hand-written parser, not regex
over the raw text.

## What it catches

**Missing `USER`.** If the final stage that actually ships has no `USER` instruction (or explicitly sets
`USER root`), every process in the running container has root privileges by default. Correctly checks **only the
final stage** — matching real linter convention (hadolint's DL3002), since multi-stage builds exist specifically so
earlier build-only stages' root steps never ship.

**Baked-in secrets.** `ENV`/`ARG` values assigned to secret-shaped names (`API_KEY`, `PASSWORD`, `*_TOKEN`,
`STRIPE_*_KEY`, etc.) land permanently in the image's layer history — visible via `docker history --no-trunc` to
anyone who pulls the image, even after a later layer unsets the variable. Placeholder-looking values
(`<your-key>`, `changeme`) and bare `ARG` declarations with no default are correctly not flagged.

**`curl | sh` / `wget | bash`.** Pipes a remote script directly into a shell at build time with no integrity
check — if the host is compromised or the script changes, every future build silently pulls in whatever it now
serves.

**Unpinned base images.** `:latest` or no tag at all means the base your image builds on can change between builds
with nothing in the Dockerfile to explain why.

**`ADD` with a remote URL.** Same unverified-fetch problem as `curl | sh`, via a different instruction.

## Tools

### `audit_dockerfile`
Full audit. Returns a risk level and every finding with its exact location, why it matters, and a concrete fix.

## Use it

**Hosted (recommended):** [MCPize](https://mcpize.com/mcp/dockerfile-audit-mcp) — free tier, $7/mo Pro.

**Self-host:**
```bash
npm install
node server.js
```

## Part of a small suite

[github-actions-audit-mcp](https://github.com/tylerscomic-lab/github-actions-audit-mcp),
[regex-safety-audit-mcp](https://github.com/tylerscomic-lab/regex-safety-audit-mcp),
[secrets-leak-audit-mcp](https://github.com/tylerscomic-lab/secrets-leak-audit-mcp),
[mcp-trust-audit-mcp](https://github.com/tylerscomic-lab/mcp-trust-audit-mcp).

## License

MIT
