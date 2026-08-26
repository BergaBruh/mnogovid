# Mnogovid Code Scanner

Mnogovid Code Scanner runs approved local security tools, turns their output
into a readable Markdown report, and can add an evidence-bound AI explanation
or an independent agent review. It does not install scanners, change project
files, or apply fixes.

## Install and run

All hosts need Python 3 and the scanner executables you want to use on `PATH`.
Run the initialization command in [Initialize a project profile manually](#initialize-a-project-profile-manually)
first to see the available and missing scanners. It never installs tools or
starts a scan.

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

Merge [`opencode.json.example`](opencode.json.example) into the project
`opencode.json`, replacing `/absolute/path/to/mnogovid-code-scanner` with the
real plugin path. Then copy the adapters into the project's `.opencode/`
directory:

```bash
mkdir -p /path/to/project/.opencode
cp -R /path/to/mnogovid-code-scanner/adapters/opencode/.opencode/agents /path/to/project/.opencode/
cp -R /path/to/mnogovid-code-scanner/adapters/opencode/.opencode/commands /path/to/project/.opencode/
```

Restart OpenCode and run:

```text
/security-scan
```

## Choose a mode

| Mode | Use it when | Result |
| --- | --- | --- |
| One `security-scan` workflow | You choose adapters only, AI triage, or AI triage plus independent review after bootstrap. | One consent-gated evidence lifecycle. |

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
| `--write` | Create `.mnogovid-code-scanner.json`; no existing profile is replaced without `--force`. |
| `--allow-network` | Run a network-dependent scanner after it is separately approved. It is a policy gate, not network isolation. |
| Per-scanner approval | Start one specific scanner process after its command preview. |
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
templates. It never installs them. Replacing an existing profile requires both
`--write --force`.

## Develop and update the Codex plugin

After changing this local plugin, validate it and update the cachebuster:

```bash
python3 /path/to/plugin-creator/scripts/validate_plugin.py /path/to/mnogovid-code-scanner
python3 /path/to/plugin-creator/scripts/update_plugin_cachebuster.py /path/to/mnogovid-code-scanner
```

Publish the updated marketplace source, then reinstall the plugin:

```bash
codex plugin add mnogovid-code-scanner@<marketplace-name>
```

Start a new Codex task after reinstalling so the updated skills and MCP tools
are loaded.

## Safety model

Only allowlisted scanner executables run, always as an argv array without a
shell. AI receives only the redacted payload produced by the MCP server. OSV
advisory lookup requires separate network approval. The plugin never performs
automatic remediation.

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
