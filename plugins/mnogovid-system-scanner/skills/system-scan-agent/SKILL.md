---
name: system-scan-agent
description: Run consent-gated Linux host checks, then obtain host-AI triage and an independent system-triage review.
---

# Linux system scan with independent review

Use this skill for the “adapters + AI triage + independent review” branch of
the unified workflow. Follow bootstrap, toolchain validation, local/remote
target selection, and host-AI triage first. Once triage is recorded, ask a
separate question: “May I share the bounded, redacted results and AI triage
with the independent system-triage agent?” Do not delegate before a clear yes.
The host-AI step may use `trustedAi` only after its own separate approval;
that expands non-secret diagnostics but never permits credentials or keys.

The reviewer is not another scanner: it validates only the supplied evidence,
distinguishes confirmed facts from hypotheses, and does not modify the host.
It may call `system_advisory_lookup` only after a distinct approval for that
network request; otherwise it marks advisory claims unverified.
Record its exact response with `system_record_run` using `agent_review`, then
finalize in `scan-agent` mode. Keep scanner facts, host-AI notes, and reviewer
notes as separate sections.
