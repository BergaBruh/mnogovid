# Host-specific agent adapters

The root `agents/` directory remains the canonical behavior contract. These
files are host-native entrypoints and must not be treated as interchangeable.

| Host | Files | Activation |
| --- | --- | --- |
| Claude Code | `claude/agents/*.md`; root `commands/*.md` | The marketplace plugin uses compatible root agents and commands; these files are the Claude-specific definitions for a host-specific release. |
| Codex | `openai-codex/agents/*.md`; root `commands/security-scan.md` | `@mnogovid-code-scanner` or one unified `/security-scan` command runs bootstrap, then asks for analysis mode. |
| OpenCode | `opencode/.opencode/{agents,commands}/*.md` | Copy `.opencode/agents/` and `.opencode/commands/` into the target workspace after configuring the Mnogovid MCP server. |
