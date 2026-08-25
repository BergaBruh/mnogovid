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
| Active ports (explicit target only) | Nmap, top 100 ports with light version detection |
| Live traffic metadata (bounded) | TShark, 5–300 seconds, no packet file |

Missing executables are recorded as coverage gaps. The plugin does not attempt
to install them or elevate privilege. Some checks need root access and will
report failure rather than invoke `sudo`.

## Run

Install it from the Mnogovid marketplace, then use one of the native Codex
commands:

```text
/mnogovid-system-scanner:system-scan
/mnogovid-system-scanner:system-scan-ai /safe/report-directory
/mnogovid-system-scanner:system-scan-agent /safe/report-directory
```

`system-scan` performs local evidence collection only; `system-scan-ai` adds
consent-gated host-model triage; and `system-scan-agent` adds a separately
approved independent review. The optional argument is the existing directory
where the plugin may store reports; it is not the host scan target.

### Claude Code

Install the plugin from the configured marketplace, start Claude in the
selected report directory, then invoke:

```text
/system-scan
/system-scan-ai
/system-scan-agent
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

### DeepSeek Harness

Use the supplied `package.json` and merge exactly one persona fragment from
`adapters/dsh/agent-presets/*/agent.cordis.yml` into a user-authored DSH
preset. The supplied `cordis.patch.yml` starts the local MCP server; it does
not authorize scanners or alter the host.

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

- `nmap-local` needs `--allow-active-network`, `authorizedTarget=true`, and one
  explicitly authorized literal IP.
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

`system-scan-ai` creates a bounded, secret-redacted payload only after a
separate approval to share findings with the host model. `system-scan-agent`
asks a further separate question before sending that same bounded evidence to
the independent reviewer. Both assessments are advisory and remain distinct
from the scanner evidence.

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
