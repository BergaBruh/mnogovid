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
corresponding action.

Call `security_plan`, start exactly one lifecycle, preview every adapter, and
run only the approved allowlisted scanner with that lifecycle `runId`. The MCP
server rejects an execution without an identical recorded preview. Record every preview, result, and
skip. Do not install tools, edit code, make advisory lookups, or apply fixes.

For AI modes, create `security_ai_triage_payload` only after AI-sharing consent
and record one detailed `findingNotes` entry per finding. For independent
review, ask a final separate consent and preserve scanner, host-AI, and agent
evidence as distinct report sections. Finalize once and return the report path
and coverage gaps.
