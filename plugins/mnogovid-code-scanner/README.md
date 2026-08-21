# Mnogovid Code Scanner

An autonomous, dependency-free security orchestration plugin

## Components

- MCP server: catalog, doctor, plan, virtual run, direct run, report ingest
  and Markdown storage, OSV advisory lookup, and redacted AI-triage payload.
- Agents: scanner orchestration and evidence-first finding triage.
- Skills and commands: safe multi-scanner workflows and AI/web advisory triage.

## Safety model

Only allowlisted scanner executables run, always as an argv array without a
shell. Network-dependent scanners require `allowNetwork=true`; this is a policy
gate, not OS egress isolation. The plugin never calls an LLM itself: it creates
a redacted, bounded payload so the host can request informed consent before
sharing findings with an AI provider.

The user may explicitly authorize a whole-workspace scan. That authorizes
discovery and planning across the complete current project rather than a named
subdirectory or a selected set of files. It does not bypass the separate
approvals for profile writing, network access, or each scanner process, and it
does not include scanner-standard excluded directories such as `.git`,
`node_modules`, virtual environments, or previous `.mnogovid` reports.

For web advisory checks, `security_advisory_lookup` queries OSV only after the
caller sets `allowNetwork=true`; its response retains OSV references for human
verification. NVD, vendor advisories, and other sites stay available to the
host's web-search tool for corroboration.

## Host integration

| Host | Native entry point |
| --- | --- |
| Codex | `.codex-plugin/plugin.json` and `.mcp.json`; scan modes are skills |
| Claude Code | `.claude-plugin/plugin.json` plus `claude-code.mcp.json.example` |
| OpenCode | `opencode.json.example` merged into its configuration |
| DeepSeek Harness | `package.json` bundle and `cordis.patch.yml` through first-party DSH MCP client |

The plugin root contains common `agents/`, `skills/`, and `commands/` assets;
each host receives the same scanner policy and MCP tool surface.

## Skills and agents

| Component | Purpose | Output | Cannot do |
| --- | --- | --- | --- |
| `security-scan` skill | Consent-gated local scanner workflow: discovery, preview, execution, and report storage. | A redacted Markdown report with scanner status, per-scanner vulnerability tables, and a severity graph. | Use AI, modify code, install tools, or bypass scanner approval. |
| `security-triage` skill | Evidence-led classification and advisory/version validation of existing findings. | Classification, confidence, evidence sources, and reviewable remediation proposals. | Run scans, make unapproved network requests, or patch the project. |
| `security-orchestrator` agent | Executes the local scan boundary used by `/security-scan`. | `<workspace>/.mnogovid/code-scanner/<unixtime>/result.md` plus skipped-scanner reasons. | Use AI or advisory lookups; it only orchestrates approved local scans. |
| `security-triage` agent | Independently reviews scanner evidence and any approved host-AI triage. | A distinct `agentReview` section for `/security-scan-agent`. | Alter code, install packages, or treat model output as verified evidence. |

All components preserve the same consent boundary: profile writing, network
access, each scanner run, host-AI sharing, and independent agent review are
separate decisions.

## Host-specific agent adapters

The canonical behavior lives in `agents/`, while separately maintained host
definitions live in `adapters/`:

- `adapters/claude/agents/` for Claude Code agent Markdown.
- `adapters/openai-codex/agents/` for Codex agent Markdown.
- `adapters/opencode/.opencode/agents/` for OpenCode subagents. Copy this
  `.opencode/agents/` directory into the target workspace after configuring
  the Mnogovid MCP server.
- `adapters/dsh/agent-presets/` for DeepSeek Harness scoped persona rows. Merge
  one into a user preset copied from a shipped DSH preset; do not mount it in
  the host composition.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Project initialization

Check the scanners relevant to a project without modifying it:

```bash
python3 /path/to/mnogovid-code-scanner/scripts/init.py /path/to/project
```

To add the missing local project profile, use `--write`. The script creates
only `.mnogovid-code-scanner.json` and never replaces an existing file unless both
`--write --force` are specified. Add `--allow-network` only to record a
preference for network-dependent scanners; initialization itself does not make
network requests, install programs, or run a scan.

The initialization result includes an “If you want to add more tools” section.
It detects package managers available on the current system, shows their
installation command templates, and lists scanners missing from `PATH`.

```bash
python3 /path/to/mnogovid-code-scanner/scripts/init.py /path/to/project --write --allow-network
```

## Entry points by host

| Host | Local scan | AI analysis | Independent review |
| --- | --- | --- | --- |
| Codex | `security-scan` skill | `security-scan-ai` skill | `security-scan-agent` skill |
| Claude Code | `/security-scan` | `/security-scan-ai` | `/security-scan-agent` |
| OpenCode | `/security-scan` after copying the OpenCode command adapter | `/security-scan-ai` | `/security-scan-agent` |

Every entry point operates on the current workspace. It asks separately for
`--write`, `--allow-network`, and, where applicable, permission to share
redacted findings with the host AI or the review agent. Codex does not expose
the root `commands/` files as slash commands; it uses the corresponding skills.

Each scan stores its report without overwriting earlier results at
`<project>/.mnogovid/code-scanner/<unixtime>/result.md`. Reports are rendered as Markdown with
summary and per-scanner vulnerability tables plus a Mermaid severity chart.
AI and agent modes also include the exact recorded `Host AI triage` and
`Independent agent review` sections; an approved stage cannot be finalized
without its corresponding recorded result.
Each vulnerability table shows the issue, severity, affected version, fixed
version, and responsible file lines or libraries. Raw JSON is not written to
`result.md`.
