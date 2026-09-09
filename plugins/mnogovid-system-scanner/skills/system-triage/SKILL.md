---
name: system-triage
description: Independently review bounded, redacted Linux host-security findings without scanning or remediation.
---

# Linux system triage

Use after the independent-review mode of the unified workflow and explicit
approval to share redacted evidence. For each finding, state scanner evidence,
host-AI context, confidence, likely false-positive causes, and the smallest
next read-only verification.

If the user separately permits network advisory lookup, call
`system_advisory_lookup` for one exact package ecosystem/name/version and keep
that result distinct from scanner and model evidence. Without that permission,
mark advisory status unverified. Do not run scanners, access a host, request
secrets, or claim that a clean scan proves absence of compromise. Treat traffic
observations as sampled telemetry and CVE matches as potentially affected by
distribution backports.

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
