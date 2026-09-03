---
name: system-scan-ai
description: Run approved Linux host checks, then analyze bounded evidence with the host AI under strict-redacted or trusted-ai consent.
---

# Linux system scan with AI triage

Use this skill for the “adapters + AI triage” branch selected from the unified
workflow. Follow `system-scan` through bootstrap, toolchain validation, plan,
preview, and per-adapter consent first. Ask separately whether redacted findings
may be shared with the host model; no model analysis occurs until the answer is
an unambiguous yes.

Ask separately whether the selected AI is trusted to receive expanded
non-secret diagnostics (`trustedAi`). Pass that flag only when approved.

After the evidence is complete, call `system_ai_triage_payload` in batches of
40 using `findingOffset` when needed. Record each batch with
`host_ai_triage` and the same offset; the server merges batches and rejects
missing indexes at finalization. The model must classify every finding as
`true_positive`, `false_positive`, or `needs_review`, cite only the provided
evidence, and treat package CVE matches as unverified until distribution
backports are checked. Then finalize in `scan-ai` mode.

AI judgement is advisory. Even in `trustedAi` mode, do not give it raw packet
captures, credentials, tokens, private keys, authentication headers, or
unredacted scanner reports.
