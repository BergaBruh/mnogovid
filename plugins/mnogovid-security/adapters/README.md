# Host-specific agent adapters

The root `agents/` directory remains the canonical behavior contract. These
files are host-native entrypoints and must not be treated as interchangeable.

| Host | Files | Activation |
| --- | --- | --- |
| Claude Code | `claude/agents/*.md` | The marketplace plugin currently uses compatible root agents; these files are the Claude-specific definitions for a host-specific release. |
| Codex | `openai-codex/agents/*.md` | The Codex plugin currently uses compatible root agents; these files preserve a separately maintainable Codex definition. |
| OpenCode | `opencode/.opencode/agents/*.md` | Copy `.opencode/agents/` into the target workspace after configuring the Mnogovid MCP server. |
| DeepSeek Harness | `dsh/agent-presets/*/agent.cordis.yml` | Merge one persona row into a user-authored preset copied from a shipped DSH preset. |

DSH presets are intentionally fragments: a preset needs the host's existing
agent spine, model, permission, and tool rows. Replacing those rows with this
plugin would create a broken or over-privileged composition.

For DSH, copy a shipped preset to the user preset directory, merge exactly one
of these `agent.cordis.yml` files into it, and select that preset for a new
session. The persona rows are scoped-only and must not be mounted in the host
composition.
