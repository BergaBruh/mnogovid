# Host adapters

These assets expose the same consent and evidence contract on each supported
agent surface. They do not contain scanner binaries or bypass the MCP server.

| Host | Files | Activation |
| --- | --- | --- |
| Codex | `openai-codex/agents/*.md`; root `commands/system-scan.md` | Mention `@mnogovid-system-scanner` or run one unified `system-scan` command. Bootstrap checks the profile/toolchain before mode selection. |
| Claude Code | `claude/agents/*.md`; root `commands/system-scan.md` | Install the plugin, restart Claude Code, and run `/system-scan`. |
| OpenCode | npm MCP binary | Add an `mcp` stanza that runs `npx --yes @bergabruh/system-scanner`; OpenCode exposes the Python MCP tools with the server-name prefix. |

Every surface must retain separate approvals for profile creation, networked
image databases, active network probing, local service probes, traffic capture,
each scanner command, host-AI sharing, and independent review.
