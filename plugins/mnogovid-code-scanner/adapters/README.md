# Host-specific agent adapters

The root `agents/` directory remains the canonical behavior contract. These
files are host-native entrypoints and must not be treated as interchangeable.

| Host | Files | Activation |
| --- | --- | --- |
| Claude Code | `claude/agents/*.md`; root `commands/*.md` | The marketplace plugin uses compatible root agents and commands; these files are the Claude-specific definitions for a host-specific release. |
| Codex | `openai-codex/agents/*.md`; root `commands/security-scan.md` | `@mnogovid-code-scanner` or one unified `/security-scan` command runs bootstrap, then asks for analysis mode. |
| OpenCode | npm MCP binary | Add an `mcp` stanza that runs `npx --yes @bergabruh/code-scanner`; OpenCode exposes the Python MCP tools with the server-name prefix. |
