---
name: security-scan
description: Plan, approve, execute, and report an evidence-first security scan with local scanner CLIs.
---

# Security scan

Use this skill for the adapters-only branch of the unified Code Scanner
workflow. Bootstrap the workspace first; then use it when the requested result
must be reproducible local scanner evidence rather than AI interpretation. It
supports SAST, secret scanning, software-composition analysis, SBOM, and IaC
scanners from the plugin allowlist.

## Inputs

- The current workspace as an absolute directory path.
- Optional permission to create `.mnogovid-code-scanner.json` with `--write`.
- Optional permission for network-dependent scanners with `--allow-network`.
- Explicit approval for every scanner process that will actually run.

## Scope consent

When the user explicitly authorizes scanning the whole project or workspace,
discover and plan all relevant allowlisted scanners across the complete current
workspace. Do not narrow that scope to selected components unless the user asks
to do so. This scope consent is distinct from, and does not replace, approval
for profile writing, network access, or every scanner process. Standard scanner
exclusions still apply: `.git`, dependency/vendor directories, virtual
environments, caches, build artifacts, and prior `.mnogovid` reports are not
treated as project source.

## Workflow

1. Call `security_bootstrap` with `createProfile=false`. Ask before creating a
   missing profile, and stop on an invalid profile. Report available and missing
   executables; do not install tools.
2. Ask separately about network-dependent scanners; a denied or unclear answer
   means that permission is absent.
3. Call `security_plan` to discover project languages, manifests, and relevant
   allowlisted scanners.
4. Start a lifecycle with `security_start_run`, recording the network answer
   in `consent` and retaining its `runId`.
5. For every candidate, call `security_virtual_run`, record it with kind
   `preview`, and explain its command, working directory, and network need.
6. Obtain a distinct confirmation for each `security_run`. Pass the active
   `runId`; a network scanner needs both recorded network consent and approval
   for that exact preview. Record results and skips via `security_record_run`.
7. Call `security_finalize_run`; it validates the lifecycle-owned report shape
   and stores Markdown in `<workspace>/.mnogovid/code-scanner/<unixtime>/result.md`.

## Outputs

The report contains scanner status, a per-scanner vulnerability table, a
severity graph, skipped-scanner reasons, and redacted evidence. It does not
contain host-model reasoning, AI triage, automatic remediation, or raw secrets.

## Boundaries

- Never execute a command outside the adapter allowlist or through a shell.
- Every execution requires the current lifecycle `runId` and an argv-identical
  recorded preview; permission language alone is not enough.
- Do not treat `allowNetwork=true` as operating-system egress isolation.
- Do not modify application source code, dependencies, or lockfiles.
- After unified mode selection, route to the AI or independent-review branch
  only when the user explicitly chooses it and grants the corresponding consent.

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
