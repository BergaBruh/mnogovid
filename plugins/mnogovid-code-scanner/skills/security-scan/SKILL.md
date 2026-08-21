---
name: security-scan
description: Plan, approve, execute, and report an evidence-first security scan with local scanner CLIs.
---

# Security scan

Use this skill for a scan of the current workspace when the requested result
must be reproducible local scanner evidence rather than an AI-only review. It
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

1. Ask separately about `--write` and `--allow-network`; a denied or unclear
   answer means that permission is absent.
2. Run `scripts/init.py <workspace> --json` with only the approved flags.
   Report available and missing scanner executables and do not install tools.
3. Call `security_doctor` and `security_plan` to discover project languages,
   manifests, and relevant allowlisted scanners.
4. For every candidate, call `security_virtual_run` first. Explain its command,
   working directory, and network requirement.
5. Obtain a distinct confirmation for each `security_run`. A network scanner
   needs both the earlier network approval and approval for that specific run.
6. Start a lifecycle with `security_start_run`, record every preview, scanner
   result, and skipped scanner via `security_record_run`.
7. Call `security_finalize_run`; it validates the lifecycle-owned report shape
   and stores Markdown in `<workspace>/.mnogovid/code-scanner/<unixtime>/result.md`.

## Outputs

The report contains scanner status, a per-scanner vulnerability table, a
severity graph, skipped-scanner reasons, and redacted evidence. It does not
contain host-model reasoning, AI triage, automatic remediation, or raw secrets.

## Boundaries

- Never execute a command outside the adapter allowlist or through a shell.
- Do not treat `allowNetwork=true` as operating-system egress isolation.
- Do not modify application source code, dependencies, or lockfiles.
- Use the `security-scan-ai` or `security-scan-agent` skills only when the
  user also wants consent-gated model or agent analysis.
