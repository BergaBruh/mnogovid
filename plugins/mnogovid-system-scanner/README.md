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
asks whether to assess the local host or a remote SSH alias, checks
the profile and toolchain, and creates a missing profile only after consent.
On later runs it validates the existing profile and available adapters before
asking which mode to use: adapters only, adapters plus AI triage, or adapters
plus AI triage and independent review. It collects all scanner permissions
separately.

### Remote server over SSH-stdio MCP

Define an exact `Host` alias directly in `~/.ssh/config` for a dedicated audit
account, then use the same unified command and choose the remote option. Raw
hostnames and wildcard aliases are rejected:

```text
/mnogovid-system-scanner:system-scan
```

The command asks only for that alias. It connects over SSH stdio with agent and
forwarding disabled, validates the host key, finds `python3`, and checks the
fixed runner path under `~/.local/share/mnogovid-system-scanner`. If the runner
is absent or outdated, it separately asks before deploying or updating it.
There is no remote MCP port, remote path, Python path, or local TOML to manage.

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
