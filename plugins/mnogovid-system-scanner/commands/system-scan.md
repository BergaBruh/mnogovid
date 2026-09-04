---
description: Choose and run a consent-gated local or remote Linux security assessment
---

Run one unified system-scanner workflow. Do not require command arguments.

Before scanner-mode selection, complete bootstrap for the selected target.

1. **Target:** “Analyze this local host, or a remote SSH alias/target?” If
   remote is chosen, ask the user to provide either a configured alias or a
   complete `user@host` or `user@host:port` target. Never read `~/.ssh/config` to discover or list
   aliases, and never use a native file-read tool for that purpose. A complete
   target does not read `~/.ssh/config`. After the user supplies the target,
   ask: “May I connect read-only to `<ssh-target>` and inspect whether the
   Mnogovid runner is ready?” After yes,
   call exactly `system_remote_prepare` with `approveConnection=true`. It
   accepts a remote Python 3 binary exposed as `python3`, `python`, or a common
   absolute path; its non-interactive probe also checks standard user/system
   bin directories. If the user supplied a custom local private key, pass its
   path as `identityFile` on every remote operation; never read or expose key
   contents. Never
   call the nonexistent names `system-prepare-remote` or
   `mcp-prepare-system-remote`. Do not request a remote plugin path or Python
   path. If the runner is missing or outdated, ask a separate question: “May I
   deploy or update the Mnogovid runner under the remote user's
   `~/.local/share/mnogovid-system-scanner`?” Only after yes, call
   `system_remote_authorize_deploy` with `approveDeployment=true`, then consume
   its ticket with `system_remote_deploy_runner`. Remote tool calls must use
   `system_remote_call` with that alias; local tool calls must use `system_*`
   directly. Never mix the two in one lifecycle.
2. **Bootstrap:** Call `system_bootstrap` with `createProfile=false`. If its
   profile action is `missing`, ask: “Create the missing system-scanner profile
   in this directory? This records discovery only; it does not start a scan.”
   Call it again with `createProfile=true` only after yes. If the profile is
   invalid, stop and report that it must be repaired explicitly. Show a separate
   utility-readiness message: available adapters, missing adapters, detected
   package managers, candidate package names, and install command templates.
   For a remote target, obtain the same message through `system_remote_call`.
   Pass the current local working directory as `localReportDirectory` on every
   remote call; it is used only for the final local report mirror.
   Do not continue to scanning while required selected adapters are missing.
3. **Scope:** Before mode selection, show the `groups` from `system_plan` and
   ask which groups to scan. Offer only groups with relevant adapters, marking
   unavailable/undetected groups explicitly:
   - **Host baseline** — hardening, persistence, audit, logs and kernel.
   - **Malware/rootkits** — ClamAV, rkhunter and chkrootkit.
   - **Integrity/CVEs** — AIDE, package integrity and vulnerability data.
   - **Containers** — Docker/Podman and image posture (only when a runtime is detected).
   - **Services/databases** — Nginx, MySQL, PostgreSQL, Redis, MongoDB and ClickHouse (only when service hints exist, unless the user explicitly opts in).
   - **Network exposure** — listeners, firewall and explicitly authorized Nmap target.
   - **Traffic** — bounded TShark metadata capture, only when explicitly requested.
   Record the selected IDs as `scopeGroups` in `system_start_run`; never run an
   adapter outside those groups. A missing database/runtime is a skip, not a
   reason to probe every client by default.
4. **Mode:** Only after successful bootstrap and scope selection, ask: “How should I analyze the evidence?” Present exactly these modes:
   - **Adapters only** — reproducible local scanner evidence.
   - **Adapters + AI triage** — scanner evidence plus bounded, redacted host-AI
     classification.
   - **Adapters + AI triage + independent review** — adds a separately approved
     `system-triage` assessment after host-AI triage.

Map the mode to `system_start_run`: `scan`, `scan-ai`, or `scan-agent`, and pass
the selected `scopeGroups`.
Use only the chosen target's tools; never mix local and remote tool results in
one lifecycle.

Then request independent consent for: creating the profile, passwordless root
execution for root-required adapters, whether the selected AI may receive
expanded non-secret diagnostics (`trustedAi`), networked image vulnerability databases,
active Nmap probes, local service probes, traffic capture, every scanner
command, host-AI sharing (AI modes), and independent review (review mode).
Treat anything but an unambiguous yes as denial.

Use bootstrap's doctor result and then call `system_plan`; start exactly one
lifecycle; preview every adapter; and execute only an identical, recorded
preview with that lifecycle `runId`. When `system_run` returns a `jobId`, use
`system_record_job` to poll and record the normalized result directly; use
`system_poll_job` only for status checks. Never construct scanner-result JSON
from raw logs yourself.
Record all results and skips. Never install tools, request a sudo password,
apply remediation, save a PCAP, expose a remote MCP port, copy credentials, or
enable SSH agent forwarding. Root-required adapters may use `sudo -n` only
after recorded root-privilege consent; a password prompt is an actionable gap.

Do not run Bash, `ssh`, `which`, `command -v`, `ssh-keygen`, or any native file
read to verify adapters or credentials; `system_doctor`/`system_plan` are the
only readiness source and MCP tools are the only execution path. Valid
recording tools are exactly `system_record_run` and `system_record_job` (or
remote `system_remote_call` with those operation names); never invent a
`registry_record` tool.

For AI modes, create `system_ai_triage_payload` only after AI consent. If the
user approved `trustedAi`, pass `trustedAi: true`; otherwise use strict-redacted
mode. Secrets, credentials, private keys, and auth headers remain scrubbed in
both modes. For more
than 40 findings, pass the full redacted list with `findingOffset` 0, 40, 80,
and so on, and record each returned batch with the same `findingOffset`; the
server merges batches and rejects missing indexes at finalization. For
independent review, ask a final separate consent, then keep scanner, host-AI,
and reviewer evidence distinct. Finalize once and return the local report path
and coverage gaps. A remote finalize response includes `storedLocally: true`;
the remote copy is an implementation cache, not the handoff location.
