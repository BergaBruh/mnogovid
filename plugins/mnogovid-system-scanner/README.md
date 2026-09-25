# Mnogovid System Scanner

Scanner evidence is saved server-side. Synchronous system_run results are
recorded automatically; system_record_job records completed background jobs.
Before triage/finalization the server collects pending results and refuses to
continue while jobs are running. Use system_read_run to inspect saved results.
Return findingId unchanged in every AI/reviewer note; numeric indexes alone
are insufficient for new evidence. Never synthesize scanner entries or Python
generators. Reports retain the full document up to 16 MiB; over-limit reports
fail explicitly while retaining state. Finalized state stays readable and
repeat finalization returns the same report.

Mnogovid System Scanner is a consent-gated Linux host assessment plugin. It
orchestrates installed local tools and records redacted evidence; it never
installs software, applies a fix, deletes/quarantines a file, saves PCAPs, or
runs shell text.

It is intentionally layered. No tool can prove a Linux host is clean: a
rootkit can hide from user-space checks, package CVE state can differ because
of distribution backports, and encrypted or unobserved traffic cannot be fully
inspected.

## Coverage

| Area | Allowlisted adapters |
| --- | --- |
| Hardening | Lynis |
| Malware / rootkits | ClamAV, rkhunter, chkrootkit |
| File/package integrity | AIDE, `rpm -Va` |
| Installed-package CVEs | debsecan |
| Runtime inventory | osquery |
| Listener and firewall exposure | `ss`, nftables |
| Persistence | enabled systemd units and timers |
| Audit, kernel, and logs | audit rules, loaded kernel modules, warning journal entries |
| Containers | Docker and Podman inventory when their CLI is available |
| Docker hardening and image CVEs | Docker security options/container posture, Trivy, Grype, Dockle |
| Service posture | Nginx syntax; bounded local MySQL, PostgreSQL, Redis, MongoDB, and ClickHouse probes |
| Active ports (explicit target only) | Nmap, top 100 ports with light version detection |
| Live traffic metadata (bounded) | TShark, 5–300 seconds, no packet file |

Missing executables are recorded as coverage gaps. The plugin does not attempt
to install them. Root-required adapters (including full-filesystem ClamAV,
Lynis, AIDE, firewall/audit inspection, listener ownership, rootkit checks, and
TShark) use non-interactive `sudo -n` only after separate consent; if
passwordless sudo is unavailable, the result is a coverage gap.

Claude Code integration includes a `PreToolUse` hook that auto-allows only this
plugin's MCP tool names. It does not allow Bash, native file reads, or other
MCP servers; server-side lifecycle, consent, preview, scope, and target checks
remain mandatory. Reload plugins or restart Claude Code after installing an
update.

## Run

Before ClamAV, select the total runtime budget (1–60 minutes, default 60).
Use the same timeoutSeconds in preview and execution. The approved command
runs trusted GNU timeout under sudo: TERM at the deadline, KILL after 5 seconds.
Sudo policy must permit that wrapper. Record timeout results as incomplete;
partial findings are retained. Silence with --infected --no-summary is normal,
and an AI stream interruption does not mean the scanner must be killed.

Install it from the Mnogovid marketplace, then use one of the native Codex
commands:

```text
@mnogovid-system-scanner
/mnogovid-system-scanner:system-scan
```

The `@` mention invokes the plugin onboarding prompt. The unified command first
asks whether to assess the local host or a remote SSH alias, checks
the profile and toolchain, and creates a missing profile only after consent.
On later runs it validates the existing profile and available adapters before
asking which mode to use: adapters only, adapters plus AI triage, or adapters
plus AI triage and independent review. It collects all scanner permissions
separately.

### Remote server over SSH-stdio MCP

For the usual setup, define an exact `Host` alias directly in `~/.ssh/config`
for a dedicated audit account, then use the same unified command and choose
the remote option. You may instead enter a complete `user@host` or
`user@host:port` target; that form does not read `~/.ssh/config`. For a
config-free target, an optional local `identityFile` path is passed to SSH as
`-i` after connection consent; the key contents are never read or sent to a
model. Raw hostnames and wildcard aliases are
rejected:

```text
/mnogovid-system-scanner:system-scan
```

The command asks the user to provide the alias/target; it never enumerates
aliases by reading `~/.ssh/config`. It asks for explicit connection approval
before validating an alias, reading `~/.ssh/config`, or connecting. It then connects over
SSH stdio with agent and forwarding disabled, validates the host key, finds a
Python 3 executable (`python3`, `python`, or a common absolute path). The
non-interactive probe adds `$HOME/.local/bin`, `/usr/local/bin`, `/usr/bin`, and
`/bin` to the remote PATH before checking names, then checks the
fixed runner path under `~/.local/share/mnogovid-system-scanner`. If the runner
is absent or outdated, it separately asks before deploying or updating it.
There is no remote MCP port, remote path, Python path, or local TOML to manage.
The workflow passes the current local report directory to the bridge. Scanner
state is kept privately on the remote host while the finalized redacted
`result.md` is copied into the local `.mnogovid/system-scanner/<timestamp>/`
directory and returned with `storedLocally: true`.

### Demo initialization

For a restricted demonstration workflow, invoke the unified command with the
single optional flag:

```text
/mnogovid-system-scanner:system-scan --flag=demo
```

The flag is accepted only during first profile creation and is persisted in
`.mnogovid-system-scanner.json`. Demo mode retains local and remote scans,
normal system/network scanner tool calls, all analysis modes, report ingestion,
OSV advisory lookups, and independent review. Remote runner
preparation/deployment remains available because it is part of a remote scan.
An existing standard profile is not silently converted to demo mode.

### Claude Code

Install the plugin from the configured marketplace, start Claude in the
selected report directory, then invoke:

```text
/system-scan
```

### OpenCode

Add the MCP server to the project or global `opencode.json` and restart
OpenCode:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mnogovid-system-scanner": {
      "type": "local",
      "command": ["npx", "--yes", "@bergabruh/system-scanner"],
      "enabled": true
    }
  }
}
```

`npx` installs and starts the bundled Python MCP server; no absolute path or
copied `.opencode` assets are needed. OpenCode exposes its tools with the
`mnogovid-system-scanner_` prefix and still requests every recorded consent.
`python3` and individual scanner executables remain system prerequisites and
are never installed by the package.

First inspect the host/tool availability without starting a scanner:

```bash
python3 /path/to/mnogovid-system-scanner/scripts/init.py /safe/report-directory --json
```

This manual initializer is optional; the unified workflow uses `system_bootstrap`
first. A profile records discovery only and never grants scanner permission:

```bash
python3 /path/to/mnogovid-system-scanner/scripts/init.py /safe/report-directory --json --write
```

The equivalent manual demo initialization is:

```bash
python3 /path/to/mnogovid-system-scanner/scripts/init.py /safe/report-directory --json --write --flag=demo
```

For every adapter the agent previews its exact argv and asks for approval. Two
additional controls are deliberately separate:

- Image scanners with external vulnerability databases require `network`
  consent, an image reference, and per-scanner approval.
- `nmap-local` needs recorded lifecycle active-network consent,
  `authorizedTarget=true`, and one explicitly authorized literal IP.
- Database clients require `serviceProbe` consent and use only fixed local,
  read-only status commands. Their raw output is withheld after normalization.
- `tshark-summary` needs recorded lifecycle traffic-capture consent, a named
  interface, and a 5–300 second capture interval. It emits metadata to the
  scanner result only, not a PCAP file; packet metadata can still be sensitive.

The database adapters use fixed local read-only status/version commands. They
can be unavailable when a service is not local, its socket is inaccessible, or
it requires credentials; such a result is a coverage gap, not a clean bill of
health.

Before choosing an analysis mode, bootstrap sends a separate utility-readiness
message. It lists every available and missing adapter, detected package managers,
candidate package names, and install command templates. The same readiness
message is collected from a remote host through the SSH runner. Package names
are candidates and must be verified for the target distribution; the plugin
never installs utilities itself.

The workflow then asks which scan groups to enable (host baseline,
malware/rootkits, integrity/CVEs, containers, services/databases, network
exposure, and traffic). `system_plan` marks groups with detected runtimes or
service hints; unselected groups are enforced in the lifecycle and their
adapters cannot execute. This prevents probing an absent database or starting
traffic capture when it was not requested.

Long-running jobs expose `system_record_job`, which polls and records the
normalized result server-side. The agent must not run raw SSH/Bash checks,
transcribe scanner JSON, or invent recorder names such as `registry_record`.

`system_poll_job` and `system_record_job` accept `waitSeconds` (default 5,
range 0–10). They return early on completion, or return running after the wait
so the chat can show progress. This works through `system_remote_call` too;
put `waitSeconds` inside `arguments`. It reduces rapid polling but cannot
prevent an AI-provider stream failure. Preserve runId/jobId and check the same
job after reconnecting, without restarting the scan.

Reports are written only after `system_finalize_run`:

```text
<report-directory>/.mnogovid/system-scanner/<timestamp>/result.md
```

The report is reader-first: verdict, executive summary, actionable findings,
severity/status tables, text bar charts with Mermaid chart equivalents,
coverage-by-group, a bounded group-to-adapter-to-evidence relationship graph,
coverage gaps with recovery guidance, scanner coverage,
security-relevant observations, recorded consent, and distinct AI/independent-
review tables. Transport JSON is kept out of `result.md`; structured lifecycle
state remains in the private `run-state.json`. Priority findings get a
bug-report-style detail block: summary, evidence reference, verification step,
impact boundary, and conditional mitigation guidance; lower-priority findings
remain in the overview table. AI/reviewer comments are shown next to priority
findings, while the report keeps only aggregate classification counts for the
rest. The final
`Sources and manual verification` section maps lifecycle, scanner-result, and
finding IDs back to `system_read_run` and explains what can be checked in an
external advisory database. A failed, missing, or declined adapter is a
coverage gap—not a clean result.

## AI and independent review

The AI and independent-review modes create bounded payloads only after their
own separate approvals. Strict-redacted mode is the default; `trustedAi` can
expand non-secret diagnostics for the selected AI. Both assessments are
advisory and remain distinct from the scanner evidence.
The lifecycle also has a separate `trustedAi` consent. When enabled, the
selected AI can receive expanded non-secret diagnostics; credentials, tokens,
private keys, and authentication headers are still scrubbed.

Read saved results with system_read_run(reportDirectory, runId, scannerOffset).
It returns one scanner per page, including exit code and retained diagnostics.
AI triage payloads are capped at 40 findings per call. Pass reportDirectory,
runId and findingOffset, without findings, to read stored evidence directly;
the server merges recorded AI batches, ignores
duplicate records, and requires complete index coverage before finalization.

Use `system_ingest` to normalize a pre-existing private local JSON or SARIF
report inside the selected report directory without starting a process.
`system_advisory_lookup` queries OSV for one
package version only after a separate `allowNetwork=true` approval; it is
advisory evidence and does not account for distribution backports by itself.

## Development

Validate the manifest and exercise the JSON-RPC server without starting a
scanner:

```bash
python3 /path/to/plugin-creator/scripts/validate_plugin.py /path/to/mnogovid-system-scanner
python3 -m unittest discover -s /path/to/mnogovid-system-scanner/tests -v
```

Licensed under the Apache License 2.0.

## Troubleshooting

- **Profile missing:** rerun the unified workflow and approve profile creation.
- **Profile invalid:** stop and repair it explicitly; the workflow will not
  scan through an invalid profile.
- **Adapter missing or permission denied:** install or grant the required
  read-only access through normal system administration, then rerun bootstrap.
- **Remote runner unavailable:** verify only the SSH alias and known host key,
  then rerun the remote bootstrap. It finds Python automatically and asks before
  deploying the fixed runner path.
- **No findings:** a completed set of checks cannot prove the absence of
  compromise, unseen traffic, or kernel-level stealth. Review coverage gaps.
