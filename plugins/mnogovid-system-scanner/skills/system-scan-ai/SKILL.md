---
name: system-scan-ai
description: Run approved Linux host checks, then analyze bounded redacted evidence with the host AI.
---

# Linux system scan with AI triage

Use this skill for the “adapters + AI triage” branch selected from the unified
workflow. Follow `system-scan` through bootstrap, toolchain validation, plan,
preview, and per-adapter consent first. Ask separately whether redacted findings
may be shared with the host model; no model analysis occurs until the answer is
an unambiguous yes.

After the local evidence is complete, call `system_ai_triage_payload`. The
model must classify every finding as `true_positive`, `false_positive`, or
`needs_review`, cite only the provided evidence, and treat package CVE matches
as unverified until distribution backports are checked. Record the exact answer
with `system_record_run` using `host_ai_triage`, then finalize in `scan-ai`
mode.

AI judgement is advisory. Do not give it raw packet captures, credentials,
private keys, full process arguments, or unredacted scanner reports.
