---
name: security-scan-ai
description: Run approved local security scanners, then use host AI to analyze bounded, redacted findings.
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
- Share only the bounded, redacted payload prepared by the MCP server.
- An approved AI scan cannot be finalized while its host-AI triage is still
  unrecorded.
- An approved AI scan with findings cannot be recorded or finalized unless each
  finding has a detailed AI note; the report renders that note in its row.
- No project source, dependency, or lockfile is modified.
