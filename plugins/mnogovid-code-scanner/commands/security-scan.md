---
description: Choose and run a consent-gated workspace security assessment
---

Run one unified Code Scanner workflow for the current workspace. Do not require
command arguments.

Before scanner-mode selection, call `security_bootstrap` with
`createProfile=false`. If its profile action is `missing`, ask: “Create the
missing `.mnogovid-code-scanner.json` profile in this workspace? This records
discovery only; it does not start a scan.” Call it again with
`createProfile=true` only after yes. If the profile is invalid, stop and report
that it needs explicit repair. Send a separate utility-readiness message from
the bootstrap doctor result: available adapters, missing adapters, detected
package managers, and installation command templates. Package names must be
verified for the current distribution. Do not proceed with selected unavailable
adapters.

Only after successful bootstrap, ask: “How should I analyze the evidence?”
Present exactly these modes:

- **Adapters only** — reproducible scanner evidence.
- **Adapters + AI triage** — scanner evidence plus bounded, redacted host-AI
  classification.
- **Adapters + AI triage + independent review** — adds a separately approved
  `security-triage` assessment after host-AI triage.

Map the selected mode to `security_start_run`: `scan`, `scan-ai`, or
`scan-agent`. Then ask separately about network-dependent scanners and every
individual `security_run`; no answer other than an unambiguous yes permits the
corresponding action. For AI modes, ask whether the selected AI is trusted to
receive expanded non-secret diagnostics (`trustedAi`). Pass it only after an
explicit yes; secrets, tokens, private keys, and authentication headers remain
scrubbed in either mode.

Call `security_plan`, start exactly one lifecycle, preview every adapter, and
run only the approved allowlisted scanner with that lifecycle `runId`. The MCP
server rejects an execution without an identical recorded preview. Record every preview, result, and
skip. Do not install tools, edit code, make advisory lookups, or apply fixes.

For AI modes, create `security_ai_triage_payload` only after AI-sharing consent
and record one detailed `findingNotes` entry per finding. For independent
review, ask a final separate consent and preserve scanner, host-AI, and agent
evidence as distinct report sections. Finalize once and return the report path
and coverage gaps.

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
