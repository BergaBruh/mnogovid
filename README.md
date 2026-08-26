# Mnogovid Marketplace

This repository is the public distribution point for Mnogovid plugins.
It contains marketplace catalogs for Codex and Claude Code and host-specific
OpenCode configuration assets.

The marketplace itself is only a catalog: it does not scan repositories, send
data to an AI model, or install scanner programs. Those actions belong to the
installed plugin and remain consent-gated.

## Catalog

| Plugin | Status | What it provides | Primary users |
| --- | --- | --- | --- |
| `mnogovid-code-scanner` | Available | Local multi-scanner security workflow, report storage, optional AI triage, and independent-agent review. | Codex, Claude Code, and OpenCode users. |
| `mnogovid-system-scanner` | Available | Consent-gated Linux host assessment: hardening, malware/rootkits, integrity, packages, persistence, ports/firewall, and bounded traffic observation. | Codex and Claude Code users. |

The Codex catalog is defined in [`.agents/plugins/marketplace.json`](.agents/plugins/marketplace.json); the Claude Code catalog is in
[`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json).

## What the scanners do

The plugin discovers a workspace, selects relevant allowlisted scanner CLIs,
previews commands, and runs only the scanners the user explicitly approves.
Every completed workflow produces a redacted Markdown report at:

```text
<project>/.mnogovid/code-scanner/<unixtime>/result.md
```

`mnogovid-system-scanner` is the corresponding host-level plugin. It uses an
explicitly selected, private report directory; previews every fixed argv; and
requires separate approvals for each scanner, active probing of one authorized
IP, and bounded packet-metadata capture. Its report path is:

```text
<report-directory>/.mnogovid/system-scanner/<unixtime>/result.md
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

1. Create or update `.mnogovid-code-scanner.json` with `--write`.
2. Permit network-dependent scanners with `--allow-network`.
3. Run each scanner process.
4. Share bounded, redacted findings with the host AI.
5. Request an independent agent review.

For the system scanner, active port scanning and traffic capture are additional
independent consents. It never installs a tool, invokes `sudo`, applies a fix,
or writes a packet-capture file.

Scanner commands use an allowlist and argv execution without a shell. Network
permission is a policy gate, not operating-system egress isolation. Reports
redact secret-like fields before they are written.

## Install

### Codex

```bash
codex plugin marketplace add https://github.com/BergaBruh/mnogovid
```

Then install **Mnogovid Code Scanner** from the marketplace.

### Claude Code

```bash
claude plugin marketplace add https://github.com/BergaBruh/mnogovid
```

### OpenCode

OpenCode uses an MCP configuration rather than this marketplace format. Clone
this repository, merge
`plugins/mnogovid-code-scanner/opencode.json.example` into the OpenCode config,
and set `cwd` to the absolute path of `plugins/mnogovid-code-scanner`.

To use the native OpenCode agent adapters, also copy
`plugins/mnogovid-code-scanner/adapters/opencode/.opencode/agents/` into the
target workspace’s `.opencode/agents/` directory.

## Repository layout

```text
.agents/plugins/marketplace.json        Codex marketplace catalog
.claude-plugin/marketplace.json         Claude Code marketplace catalog
plugins/mnogovid-code-scanner/          Installable plugin
plugins/mnogovid-code-scanner/adapters/ Host-specific agent definitions
plugins/mnogovid-system-scanner/         Installable Linux host-scanning plugin
```

See the plugins’ READMEs for their scanner catalogs and implementation notes:
[code scanner](plugins/mnogovid-code-scanner/README.md) and
[system scanner](plugins/mnogovid-system-scanner/README.md).

## License

Both bundled plugins are licensed under Apache-2.0; see their respective
[`LICENSE`](plugins/mnogovid-code-scanner/LICENSE) files.
