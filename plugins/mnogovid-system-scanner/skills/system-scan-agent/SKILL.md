---
name: system-scan-agent
description: Run consent-gated Linux host checks, then obtain host-AI triage and an independent system-triage review.
---

# Linux system scan with independent review

Use this skill for the “adapters + AI triage + independent review” branch of
the unified workflow. Follow bootstrap, toolchain validation, local/remote
target selection, and host-AI triage first. Once triage is recorded, ask a
separate question: “May I share the bounded, redacted results and AI triage
with the independent system-triage agent?” Do not delegate before a clear yes.
The host-AI step may use `trustedAi` only after its own separate approval;
that expands non-secret diagnostics but never permits credentials or keys.

The reviewer is not another scanner: it validates only the supplied evidence,
distinguishes confirmed facts from hypotheses, and does not modify the host.
It may call `system_advisory_lookup` only after a distinct approval for that
network request; otherwise it marks advisory claims unverified.
Record its exact response with `system_record_run` using `agent_review`, then
finalize in `scan-agent` mode. Keep scanner facts, host-AI notes, and reviewer
notes as separate sections.

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
