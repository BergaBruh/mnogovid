# Mnogovid System Scanner

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
to install them or elevate privilege. Some checks need root access and will
report failure rather than invoke `sudo`.

## Run

Install it from the Mnogovid marketplace, then use one of the native Codex
commands:

```text
@mnogovid-system-scanner
/mnogovid-system-scanner:system-scan
```

The `@` mention invokes the plugin onboarding prompt. The unified command first
asks whether to assess the local host or a configured remote MCP host, checks
the profile and toolchain, and creates a missing profile only after consent.
On later runs it validates the existing profile and available adapters before
asking which mode to use: adapters only, adapters plus AI triage, or adapters
plus AI triage and independent review. It collects all scanner permissions
separately.

### Remote server over SSH-stdio MCP

Install the same plugin on the remote host, preferably at
`/opt/mnogovid-system-scanner`, and define an SSH alias for a dedicated audit
account. Generate a static local Codex configuration stanza:

```bash
python3 /path/to/mnogovid-system-scanner/scripts/remote_mcp_config.py prod-audit
```

Copy its output into local `~/.codex/config.toml`, restart Codex, then use:

```text
/mnogovid-system-scanner:system-scan
```

The MCP protocol stays inside SSH stdio: no remote TCP listener or secret is
required in the generated configuration. It explicitly disables SSH agent and
other forwarding, enables batch mode, and requires a known host key. The utility
only renders TOML; it does not edit the local configuration or contact the
host. See [`remote-mcp.toml.example`](remote-mcp.toml.example).

The unified command asks in chat which configured remote MCP connection to use
when there is more than one, then asks a separate first consent before it
connects or starts discovery. It defaults reports to the remote MCP process's
current working directory and shows its resolved path before scanner planning.

### Claude Code

Install the plugin from the configured marketplace, start Claude in the
selected report directory, then invoke:

```text
/system-scan
```

### OpenCode

Merge [`opencode.json.example`](opencode.json.example) into the OpenCode
configuration, replacing its placeholder `cwd`. Then copy the supplied agent
and command assets into the target workspace:

```bash
mkdir -p /safe/report-directory/.opencode
cp -R /path/to/mnogovid-system-scanner/adapters/opencode/.opencode/agents /safe/report-directory/.opencode/
cp -R /path/to/mnogovid-system-scanner/adapters/opencode/.opencode/commands /safe/report-directory/.opencode/
```

First inspect the host/tool availability without starting a scanner:

```bash
python3 /path/to/mnogovid-system-scanner/scripts/init.py /safe/report-directory --json
```

The optional profile is separate from execution consent:

```bash
python3 /path/to/mnogovid-system-scanner/scripts/init.py /safe/report-directory --json --write
```

For every adapter the agent previews its exact argv and asks for approval. Two
additional controls are deliberately separate:

- Image scanners with external vulnerability databases require `network`
  consent, an image reference, and per-scanner approval.
- `nmap-local` needs `--allow-active-network`, `authorizedTarget=true`, and one
  explicitly authorized literal IP.
- Database clients require `serviceProbe` consent and use only fixed local,
  read-only status commands. Their raw output is withheld after normalization.
- `tshark-summary` needs `--allow-traffic-capture`, a named interface, and a
  5–300 second capture interval. It emits metadata to the scanner result only,
  not a PCAP file; packet metadata can still be sensitive.

Reports are written only after `system_finalize_run`:

```text
<report-directory>/.mnogovid/system-scanner/<timestamp>/result.md
```

The report is reader-first: verdict, actionable findings, coverage gaps with
recovery guidance, scanner coverage, security-relevant observations, recorded
consent, and distinct AI/independent-review sections. A failed, missing, or
declined adapter is a coverage gap—not a clean result.

## AI and independent review

The AI and independent-review modes create bounded, secret-redacted payloads
only after their own separate approvals. Both assessments are advisory and
remain distinct from the scanner evidence.

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
