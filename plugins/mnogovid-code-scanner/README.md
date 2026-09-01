# Mnogovid Code Scanner

Mnogovid Code Scanner runs approved local security tools, turns their output
into a readable Markdown report, and can add an evidence-bound AI explanation
or an independent agent review. It does not install scanners, change project
files, or apply fixes.

## Install and run

All hosts need Python 3 and the scanner executables they intend to run on
`PATH`. The normal entrypoint bootstraps the profile and toolchain itself; the
manual initializer below is only for inspection outside an agent session.

Choose the section for your agent host. The scan modes and consent policy are
the same everywhere; only installation and invocation differ.

### Codex

Install from the marketplace that contains the plugin:

```bash
codex plugin add mnogovid-code-scanner@<marketplace-name>
```

Open a new Codex task after installation, then invoke the plugin or its one
unified command:

```text
@mnogovid-code-scanner
/mnogovid-code-scanner:security-scan
```

The onboarding workflow checks the profile and scanner toolchain first. On the
first run it asks before creating `.mnogovid-code-scanner.json`; later runs
validate that profile and show missing adapters before asking how to analyze the
evidence: adapters only, adapters plus AI triage, or adapters plus AI triage
and independent review. Each scanner still needs a preview and approval.

### Claude Code

Install the plugin from your configured Claude Code marketplace. Its
`.claude-plugin/plugin.json` and bundled MCP configuration provide the plugin
entry point. Start Claude in the target project:

```bash
cd /path/to/project
claude
```

Then invoke one of the plugin's slash commands:

```text
/security-scan
```

### OpenCode

Add the MCP server to the project or global `opencode.json` and restart
OpenCode:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mnogovid-code-scanner": {
      "type": "local",
      "command": ["npx", "--yes", "@bergabruh/code-scanner"],
      "enabled": true
    }
  }
}
```

`npx` installs and starts the bundled Python MCP server; no absolute path or
copied `.opencode` assets are needed. OpenCode exposes its tools with the
`mnogovid-code-scanner_` prefix and still requests every recorded consent.
`python3` and individual scanner executables remain system prerequisites and
are never installed by the package.

## Choose a mode

| Mode | Use it when | Result |
| --- | --- | --- |
| Adapters only | You need reproducible scanner evidence. | Findings and coverage report. |
| Adapters + AI triage | You want bounded, redacted AI classification. | Scanner evidence plus AI notes. |
| Adapters + AI triage + independent review | You need a second assessment. | Scanner evidence, AI notes, and review. |

The AI and agent are reviewers, not vulnerability scanners. Scanner evidence
remains the source of record.

## Scope and consent

Say “scan the whole workspace” to authorize discovery and planning across the
entire current project. The normal scanner exclusions still apply: `.git`,
dependency/vendor directories, virtual environments, caches, build artifacts,
and previous `.mnogovid` reports.

Each permission is independent:

| Permission | What it allows |
| --- | --- |
| Profile creation | Create a missing `.mnogovid-code-scanner.json`; an invalid profile stops the workflow. |
| Network consent | Run a network-dependent scanner after it is separately approved. It is a policy gate, not network isolation. |
| Per-scanner approval | Start one specific scanner process after its command preview and recorded lifecycle `runId`. |
| AI sharing | Send only a bounded, redacted findings payload to the host AI. |
| Agent review | Give the same bounded evidence and recorded AI triage to `security-triage`. |

No permission implies another. A whole-workspace authorization does not permit
network access, profile writing, or scanner execution by itself.

## Report

Every scan writes a new report to:

```text
<project>/.mnogovid/code-scanner/<timestamp>/result.md
```

The report is reader-first:

1. **Verdict** — whether action or human review is needed and whether scan
   coverage is incomplete.
2. **What needs attention** — one item per finding with scanner, location,
   severity, AI assessment, and a detailed explanation.
3. **Scan coverage** — completed, incomplete, and failed scanners.
4. **Coverage gaps** — a concrete recovery step and a short redacted
   diagnostic when a scanner did not produce usable output.

For AI and agent modes, every scanner finding must have a detailed AI note.
The report cannot finalize with an approved but unrecorded AI or agent stage.

## Initialize a project profile manually

Initialization only discovers the project and checks which scanner executables
are available; it does not run a scan, install software, or use the network.

```bash
python3 /path/to/mnogovid-code-scanner/scripts/init.py /path/to/project --json
```

To create the optional local profile and record that network scanners may be
considered later:

```bash
python3 /path/to/mnogovid-code-scanner/scripts/init.py /path/to/project --json --write --allow-network
```

The command prints missing executables and package-manager installation
templates. It never installs them. The unified workflow is preferred because it
also validates the existing profile and binds every execution to a recorded
preview.

## Develop and update the Codex plugin

After changing this local plugin, validate it and bump its normal semantic
version before publishing:

```bash
python3 /path/to/plugin-creator/scripts/validate_plugin.py /path/to/mnogovid-code-scanner
```

Publish the updated marketplace source, then reinstall the plugin:

```bash
codex plugin add mnogovid-code-scanner@<marketplace-name>
```

Start a new Codex task after reinstalling so the updated skills and MCP tools
are loaded.

## Troubleshooting

- **Profile missing:** rerun the unified workflow and approve profile creation.
- **Profile invalid:** do not scan; inspect or deliberately replace it through
  the manual initializer.
- **Adapter missing:** install it through normal system administration, then
  restart the workflow; the plugin never installs tools.
- **MCP not visible:** reinstall/update the plugin and start a new Codex or
  Claude Code session. In OpenCode, confirm `opencode mcp list` shows it as
  connected after merging the example config.
- **No findings:** this is not proof that the workspace is secure; review
  skipped and failed adapters first.

## Safety model

Only allowlisted scanner executables run, always as an argv array without a
shell. AI receives only the redacted payload produced by the MCP server. OSV
advisory lookup requires separate network approval. The plugin never performs
automatic remediation.

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
