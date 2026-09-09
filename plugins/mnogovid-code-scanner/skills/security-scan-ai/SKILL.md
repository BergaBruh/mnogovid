---
name: security-scan-ai
description: Run approved local security scanners, then use host AI to analyze bounded findings under strict-redacted or trusted-ai consent.
---

# Security scan with AI analysis

Use this skill for the “adapters + AI triage” branch selected from the unified
workflow. The scanners themselves never invoke an AI model.

## Workflow

1. Follow `security-scan` through bootstrap, toolchain validation, plan,
   preview, and per-scanner consent. Start one lifecycle in mode `scan-ai` and
   record every granted or denied consent.
2. Preview every candidate, obtain explicit approval for each scanner process,
   and record each preview, result, and skip in that lifecycle.
3. After local results are collected, ask separately: “May I send the bounded,
   redacted findings to the host AI for analysis?” Do not construct an AI
   payload or use model analysis before an unambiguous yes.
   Ask separately whether that AI is trusted to receive expanded non-secret
   diagnostics (`trustedAi`); keep it false unless explicitly approved.
4. After approval, call `security_ai_triage_payload`, then have the host model
   analyze its returned payload. Treat the model assessment as advisory:
   preserve scanner evidence and classify each finding as true positive, false
   positive, or needs review. It must return a detailed evidence-based note for
   every input finding using the payload's zero-based `findingIndex`.
5. Record that exact redacted assessment in the lifecycle with
   `security_record_run` using kind `host_ai_triage`. The final report must use
   the recorded assessment, not a reconstructed summary.
6. Do not make web lookups or apply patches as part of this skill. Finalize
   the lifecycle once with the initialization, doctor, plan, and AI-triage
   evidence.

## Boundaries

- Model analysis is never a substitute for scanner evidence or an advisory.
- Share only the bounded payload prepared by the MCP server. In `trustedAi`
  mode it may contain expanded non-secret diagnostics; secrets, tokens, private
  keys, and authentication headers remain scrubbed.
- An approved AI scan cannot be finalized while its host-AI triage is still
  unrecorded.
- An approved AI scan with findings cannot be recorded or finalized unless each
  finding has a detailed AI note; the report renders that note in its row.
- No project source, dependency, or lockfile is modified.

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
   Use the discovered security_record_run tool for lifecycle records.
   Copy its required workspace, runId, kind, and entry shape from the schema;
   do not guess alternate recorder names.
4. If discovery is unavailable, the tool is absent, or the corrected call still
   fails with an unknown-tool error, stop this workflow and report the missing
   tool and saved IDs. Ask the user to reconnect/reload the plugin in the client.
   Do not fall back to Bash, raw SSH, generated Python/JSON-RPC scripts, direct
   state-file edits, or guessed tool names.

This procedure does not authorize retrying a permission denial or bypassing
host policy. A transport timeout leaves execution status uncertain: inspect
the saved job through a registered status tool after reconnection rather than
restarting it.
