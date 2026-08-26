# Host adapters

These assets expose the same consent and evidence contract on each supported
agent surface. They do not contain scanner binaries or bypass the MCP server:

- `openai-codex/` — Codex-oriented agent definitions.
- `claude/` — Claude Code-oriented agent definitions.
- `opencode/` — OpenCode command and agent assets.
Every surface must retain the separate approvals for profile writing, active
network probing, traffic capture, each scanner command, host-AI sharing, and
independent review.
