---
description: Run Linux host checks with AI triage and independent review
argument-hint: '[report-directory]'
---

Follow the local-scanner and host-AI stages of
`/mnogovid-system-scanner:system-scan-ai` against the same report directory,
but start exactly one lifecycle in mode `scan-agent` — never `scan-ai`.
Preserve all scanner evidence and record all denied, missing, and failed
adapters; do not broaden scope or run a second set of tools.

After the host-AI triage is recorded, ask separately:

> May I give the bounded, redacted findings and host-AI triage to the dedicated
> `system-triage` agent for an independent review?

Do not delegate before a clear yes. Give the reviewer only the redacted,
structured scanner evidence and host-AI triage. It must not access the target
host, execute scanner commands, or modify any file. It may make one
`system_advisory_lookup` request only after a separate explicit network
approval; otherwise it must label advisory status unverified.

Require exactly one structured `findingNotes` item per finding, distinguish the
reviewer judgement from scanner facts and host-AI judgement, and record the
result through `system_record_run` using kind `agent_review`. Then call
`system_finalize_run` once and return its report path plus coverage gaps.
