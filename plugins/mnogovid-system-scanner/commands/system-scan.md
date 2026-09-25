---
description: Choose and run a consent-gated local or remote Linux security assessment
argument-hint: "[--flag=demo]"
---

Run one unified system-scanner workflow. The optional invocation flag is
`--flag=demo`. Do not require command arguments.

When the exact `--flag=demo` argument is present, this is a demo initialization:
pass `flag: "demo"` to the first `system_bootstrap` call and, if the profile is
missing, to the approved profile-creation call as well. The server persists the
flag in the profile and validates it. It can only be enabled while the profile is
created; an already initialized standard profile must not be silently changed.
Demo mode retains the complete scanner workflow: local and remote scans,
normal system/network tool calls, all three analysis modes, report ingestion,
advisory lookup, and independent review. Remote runner preparation and
deployment remain available because they are required to perform a remote scan.

Scanner evidence is saved server-side. Synchronous system_run results are
recorded automatically; system_record_job records completed background jobs.
Before triage/finalization the server collects pending results and refuses to
continue while jobs are running. Use system_read_run to inspect saved results.
Return findingId unchanged in every AI/reviewer note; numeric indexes alone
are insufficient for new evidence. Never synthesize scanner entries or Python
generators. Reports retain the full document up to 16 MiB; over-limit reports
fail explicitly while retaining state. Finalized state stays readable and
repeat finalization returns the same report.

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
2. **Bootstrap:** Call `system_bootstrap` with `createProfile=false` (and
   `flag: "demo"` when the command was invoked with `--flag=demo`). If its
   profile action is `missing`, ask: “Create the missing system-scanner profile
   in this directory? This records discovery only; it does not start a scan.”
   Call it again with `createProfile=true` (preserving `flag: "demo"` when
   requested) only after yes. If the profile is
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

Map the selected mode to `system_start_run`: `scan`, `scan-ai`, or `scan-agent`,
and pass the selected `scopeGroups`.
Use only the chosen target's tools; never mix local and remote tool results in
one lifecycle.

Then request independent consent for: creating the profile, passwordless root
execution for root-required adapters, whether the selected AI may receive
expanded non-secret diagnostics (`trustedAi`), networked image vulnerability databases,
active Nmap probes, local service probes, traffic capture, every scanner
command, host-AI sharing (AI modes), and independent review (review mode).
Treat anything but an unambiguous yes as denial.

Before ClamAV, select the total runtime budget (1–60 minutes, default 60).
Use the same timeoutSeconds in preview and execution. The approved command
runs trusted GNU timeout under sudo: TERM at the deadline, KILL after 5 seconds.
Sudo policy must permit that wrapper. Record timeout results as incomplete;
partial findings are retained. Silence with --infected --no-summary is normal,
and an AI stream interruption does not mean the scanner must be killed.

Use bootstrap's doctor result and then call `system_plan`; start exactly one
lifecycle; preview every adapter; and execute only an identical, recorded
preview with that lifecycle `runId`. When `system_run` returns a `jobId`, use
`system_record_job` to poll and record the normalized result directly; use
`system_poll_job` only for status checks. Never construct scanner-result JSON
from raw logs yourself.
Polling tools wait up to 5 seconds by default (waitSeconds: 0..10), returning
early when the job finishes. Repeat system_record_job with the same jobId
while recorded=false and resultStatus=running; do not use Bash sleep or restart
system_run to wait. Show progress between calls. An API stream error does not
prove a scanner stopped: retain runId/jobId and check the same job on recovery.
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
both modes. Read saved results with system_read_run (one scanner per page).
For AI batches pass reportDirectory, runId and findingOffset; omit findings.
For more than 40 findings, use `findingOffset` 0, 40, 80,
and so on, and record each returned batch with the same `findingOffset`; the
server merges batches and rejects missing indexes at finalization. For
failed checks, read their exitCode and stderrSnippet before explaining the
cause; do not guess a missing database or signature issue from counts alone.
Never generate Python to read transcripts, private job logs, or run-state.json.
Use system_read_run and system_ai_triage_payload for these data instead. For
independent review, ask a final separate consent, then keep scanner, host-AI,
and reviewer evidence distinct. Finalize once and return the local report path
and coverage gaps. A remote finalize response includes `storedLocally: true`;
the remote copy is an implementation cache, not the handoff location.

## Tool discovery and recovery

Before calling a tool, resolve its exact callable name and input schema from
the current session's available tools. Names in this document are logical MCP
operation names; the client may expose them with a server/plugin prefix. Use
the exposed name verbatim. Do not manufacture prefixes, hyphenated aliases, or
a tool named registry_record.

After "No such tool available" or an unknown-tool response:
1. Preserve the target, approvals, runId, jobId, and last confirmed result.
   Do not start a new lifecycle or rerun a scanner.
2. Check the current tool inventory. If the client exposes a tool-discovery
   facility, use that registered facility once to locate this plugin's tools.
   Do not invent a discovery tool or call tools/list as if it were a tool:
   tools/list is an MCP protocol method, not a model-callable operation.
3. Retry only when an exact matching tool and its schema are available.
   For remote work, call the discovered system_remote_call tool with the
   logical operation inside operation (system_record_run or system_record_job
   for recording); keep identityFile, target, and report directories unchanged.
4. If discovery is unavailable, the tool is absent, or the corrected call still
   fails with an unknown-tool error, stop this workflow and report the missing
   tool and saved IDs. Ask the user to reconnect/reload the plugin in the client.
   Do not fall back to Bash, raw SSH, generated Python/JSON-RPC scripts, direct
   state-file edits, or guessed tool names.

This procedure does not authorize retrying a permission denial or bypassing
host policy. A transport timeout leaves execution status uncertain: inspect
the saved job through a registered status tool after reconnection rather than
restarting it.
