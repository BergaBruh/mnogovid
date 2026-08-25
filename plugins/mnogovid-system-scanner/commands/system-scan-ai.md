---
description: Run Linux host checks, then triage bounded redacted results with host AI
argument-hint: '[report-directory]'
---

Run the complete `/mnogovid-system-scanner:system-scan` workflow against the
same report directory, including separate consent for profile writing, active
network probes, traffic capture, and every scanner command. Use mode `scan-ai`
when calling `system_start_run`.

After all approved local scanner results are recorded, ask separately:

> May I send the bounded, redacted findings to the host AI for analysis?

Do not call `system_ai_triage_payload` or perform model analysis until the user
answers yes. The model receives only that payload, must distinguish scanner
evidence from hypotheses, and must return exactly one detailed note for every
finding in zero-based `findingIndex` order. Valid classifications are
`true_positive`, `false_positive`, and `needs_review`.

Record the exact structured answer via `system_record_run` with kind
`host_ai_triage`. It is advisory: do not use web lookups, request secrets, or
apply changes. Before responding, call `system_finalize_run` with the recorded
lifecycle evidence and return the report path.
