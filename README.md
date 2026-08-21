# Mnogovid Security Marketplace

This repository is the public distribution point for Mnogovid Security plugins.
It contains marketplace catalogs for Codex and Claude Code, a Git-installable
DeepSeek Harness bundle, and host-specific OpenCode configuration assets.

The marketplace itself is only a catalog: it does not scan repositories, send
data to an AI model, or install scanner programs. Those actions belong to the
installed plugin and remain consent-gated.

## Catalog

| Plugin | Status | What it provides | Primary users |
| --- | --- | --- | --- |
| `mnogovid-security` | Available | Local multi-scanner security workflow, report storage, optional AI triage, and independent-agent review. | Codex, Claude Code, DeepSeek Harness, and OpenCode users. |

The Codex catalog is defined in [`.agents/plugins/marketplace.json`](.agents/plugins/marketplace.json); the Claude Code catalog is in
[`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

## What `mnogovid-security` does

The plugin discovers a workspace, selects relevant allowlisted scanner CLIs,
previews commands, and runs only the scanners the user explicitly approves.
Every completed workflow produces a redacted Markdown report at:

```text
<project>/.mnogovid/code-scanner/<unixtime>/result.md
```

| Component | Responsibility | Explicitly does not do |
| --- | --- | --- |
| MCP server | Detects project technology, plans and runs allowlisted scanners, normalizes reports, writes Markdown reports, and prepares redacted AI payloads. | Execute arbitrary shell commands or call an LLM itself. |
| `security-orchestrator` agent | Owns the local-scan boundary: confirmation, preview, execution status, skipped-run reasons, and report storage. | AI triage, web advisory lookups, package installation, or code edits. |
| `security-triage` agent | Independently classifies supplied redacted findings and checks advisory evidence after approval. | Execute scanners or modify a workspace. |
| `security-scan` skill | Defines the evidence-first local scan workflow. | Bypass per-scanner and network approval. |
| `security-triage` skill | Defines redacted AI triage and advisory verification rules. | Treat model output as verified evidence. |

## Safety and consent

The following are independent decisions. A yes to one never implies a yes to
another:

1. Create or update `.mnogovid-security.json` with `--write`.
2. Permit network-dependent scanners with `--allow-network`.
3. Run each scanner process.
4. Share bounded, redacted findings with the host AI.
5. Request an independent agent review.

Scanner commands use an allowlist and argv execution without a shell. Network
permission is a policy gate, not operating-system egress isolation. Reports
redact secret-like fields before they are written.

## Install

### Codex

```bash
codex plugin marketplace add https://github.com/BergaBruh/mnogovid
```

Then install **Mnogovid Security** from the marketplace.

### Claude Code

```text
/plugin marketplace add BergaBruh/mnogovid
/plugin install mnogovid-security@mnogovid-security
/reload-plugins
```

### DeepSeek Harness

Install a pinned Git revision into the desired profile, then restart that
profile:

```bash
dsh plugin --profile web add github:BergaBruh/mnogovid#<commit-sha>
```

### OpenCode

OpenCode uses an MCP configuration rather than this marketplace format. Clone
this repository, merge
`plugins/mnogovid-security/opencode.json.example` into the OpenCode config,
and set `cwd` to the absolute path of `plugins/mnogovid-security`.

To use the native OpenCode agent adapters, also copy
`plugins/mnogovid-security/adapters/opencode/.opencode/agents/` into the
target workspace’s `.opencode/agents/` directory.

## Repository layout

```text
.agents/plugins/marketplace.json        Codex marketplace catalog
.claude-plugin/marketplace.json         Claude Code marketplace catalog
plugins/mnogovid-security/              Installable plugin
plugins/mnogovid-security/adapters/     Host-specific agent definitions
cordis.patch.yml                         DeepSeek Harness MCP bundle patch
```

See the plugin’s [own README](plugins/mnogovid-security/README.md) for the
scanner catalog, slash commands, adapter details, and implementation notes.

## Releases

Pushing a version tag that starts with `v` creates a GitHub Release
automatically. Its title is `Версия: <tag>` and GitHub generates the release
notes from changes since the previous release.

```bash
git tag -a v0.1.0 -m "Версия v0.1.0"
git push origin v0.1.0
```

The workflow is [`.github/workflows/release.yml`](.github/workflows/release.yml).

## License

`mnogovid-security` is licensed under Apache-2.0; see
[plugins/mnogovid-security/LICENSE](plugins/mnogovid-security/LICENSE).
