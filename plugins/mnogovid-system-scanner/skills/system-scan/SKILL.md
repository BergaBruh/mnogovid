---
name: system-scan
description: Plan, approve, execute, and report an evidence-first Linux host security assessment.
---

# Linux system scan

Scanner evidence is saved server-side. Synchronous system_run results are
recorded automatically; system_record_job records completed background jobs.
Before triage/finalization the server collects pending results and refuses to
continue while jobs are running. Use system_read_run to inspect saved results.
Return findingId unchanged in every AI/reviewer note; numeric indexes alone
are insufficient for new evidence. Never synthesize scanner entries or Python
generators. Reports retain the full document up to 16 MiB; over-limit reports
fail explicitly while retaining state. Finalized state stays readable and
repeat finalization returns the same report.

Use this skill for the adapters-only branch of the unified System Scanner
workflow. Bootstrap the selected local or remote target first, then assess
installed tools, malware/rootkits, integrity, packages, persistence, listeners,
firewall configuration, and optional bounded traffic observation.

## Required consent

The user must separately approve each of the following:

1. Create a missing `.mnogovid-system-scanner.json` profile in the selected
   report directory.
2. Passwordless root execution for adapters explicitly marked root-required.
3. Networked image scanner databases, active Nmap probes, local service probes,
   and bounded TShark observation as applicable.
4. Every individual `system_run` after seeing its exact virtual command.

Group selection is a separate scope decision and is not implied by command
consent.

No approval implies another. Local scanners can consume CPU, disk I/O, or need
privilege, so each still needs an explicit per-command approval.

## Workflow

1. Resolve an existing report directory; never use `/` as that directory.
2. Call `system_bootstrap` with `createProfile=false`. Ask before creating a
   missing profile; stop on an invalid profile. Use its doctor result, then call
   `system_plan`.
3. Present `system_plan.groups` and ask which groups to scan: host baseline,
   malware/rootkits, integrity/CVEs, containers, services/databases, network
   exposure, and traffic. Mark groups with no detected runtime/service as
   optional and do not select them by default. Start `system_start_run` in mode
   `scan` with the selected `scopeGroups`, recording every approval or denial.
4. Preview only adapters belonging to selected groups with
   `system_virtual_run`; record each as `preview`.
5. Run only individually approved commands through `system_run`. If it returns
   a `jobId`, call `system_record_job` to poll and record the normalized result
   directly; use `system_poll_job` only for status checks. Never transcribe raw
   scanner JSON into `system_record_run`. Record unavailable or declined
   adapters as `skipped`.
6. For `nmap-local`, record lifecycle active-network consent,
   require `authorizedTarget=true`, and use exactly one literal IP the user is
   allowed to scan. For `tshark-summary`, record lifecycle traffic-capture
   consent, require an interface, and use a 5–300 second duration. Explain that
   its packet metadata may be sensitive.
7. Call `system_finalize_run`; it stores the report in
   `<report-directory>/.mnogovid/system-scanner/<timestamp>/result.md`.

For a remote target, pass the local working directory as
`localReportDirectory` on `system_remote_call`. Finalization returns the
redacted report and the bridge stores it under that local directory; the
remote runner retains its private working copy only for resumability.

When host-AI triage has more than 40 findings, call
`system_ai_triage_payload` with reportDirectory, runId and offsets 0, 40, 80,
and so on. Record each batch with the matching `findingOffset`; duplicate
previews, scanner results, and batches are idempotent.
Omit findings in lifecycle mode. Read individual saved scanner results with
system_read_run; never generate Python to parse transcripts or state files.

## Boundaries

Before ClamAV, select the total runtime budget (1–60 minutes, default 60).
Use the same timeoutSeconds in preview and execution. The approved command
runs trusted GNU timeout under sudo: TERM at the deadline, KILL after 5 seconds.
Sudo policy must permit that wrapper. Record timeout results as incomplete;
partial findings are retained. Silence with --infected --no-summary is normal,
and an AI stream interruption does not mean the scanner must be killed.

Polling uses bounded server-side waiting: waitSeconds defaults to 5, accepts
0..10, and returns early on completion. Repeat system_record_job with the same
runId/jobId while running; use 0 for an immediate check. Do not invoke shell
sleep or restart a scanner to wait. Keep those IDs for recovery after a chat
or API interruption and report progress between calls.

- Never install packages, run remediation, quarantine files, or write PCAPs.
- Never run arbitrary commands or a shell; use only the adapter allowlist.
- Every execution requires the current lifecycle `runId` and an argv-identical
  recorded preview.
- A clean report is not proof that the system is uncompromised.
- Encrypted or unobserved traffic, kernel-level stealth, unavailable tools, and
  distribution backports are explicit coverage gaps.

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
