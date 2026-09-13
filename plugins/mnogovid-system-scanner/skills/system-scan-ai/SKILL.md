---
name: system-scan-ai
description: Run approved Linux host checks, then analyze bounded evidence with the host AI under strict-redacted or trusted-ai consent.
---

# Linux system scan with AI triage

Scanner evidence is saved server-side. Synchronous system_run results are
recorded automatically; system_record_job records completed background jobs.
Before triage/finalization the server collects pending results and refuses to
continue while jobs are running. Use system_read_run to inspect saved results.
Return findingId unchanged in every AI/reviewer note; numeric indexes alone
are insufficient for new evidence. Never synthesize scanner entries or Python
generators. Reports retain the full document up to 16 MiB; over-limit reports
fail explicitly while retaining state. Finalized state stays readable and
repeat finalization returns the same report.

Use this skill for the “adapters + AI triage” branch selected from the unified
workflow. Follow `system-scan` through bootstrap, toolchain validation, plan,
preview, and per-adapter consent first. Ask separately whether redacted findings
may be shared with the host model; no model analysis occurs until the answer is
an unambiguous yes.

Ask separately whether the selected AI is trusted to receive expanded
non-secret diagnostics (`trustedAi`). Pass that flag only when approved.

After the evidence is complete, call `system_ai_triage_payload` in batches of
40 using reportDirectory, runId and `findingOffset`; omit findings so the server
reads its saved evidence. Use system_read_run for scanner diagnostics. Never
generate Python or parse chat logs to recover findings. Record each batch with
`host_ai_triage` and the same offset; the server merges batches and rejects
missing indexes at finalization. The model must classify every finding as
`true_positive`, `false_positive`, or `needs_review`, cite only the provided
evidence, and treat package CVE matches as unverified until distribution
backports are checked. Then finalize in `scan-ai` mode.

AI judgement is advisory. Even in `trustedAi` mode, do not give it raw packet
captures, credentials, tokens, private keys, authentication headers, or
unredacted scanner reports.

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
