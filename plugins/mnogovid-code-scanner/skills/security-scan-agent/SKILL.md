---
name: security-scan-agent
description: Run local scanners, obtain host-AI triage, then request an independent security-triage agent review.
---

# Security scan with AI and independent agent review

Use this skill for the “adapters + AI triage + independent review” branch of
the unified workflow: approved local scanning, host-AI triage of redacted
findings, and a separate `security-triage` review.

## Workflow

1. Follow the unified workflow through bootstrap, toolchain validation, plan,
   preview, per-scanner consent, and host-AI sharing. Start one lifecycle in
   mode `scan-agent` and record every granted or denied consent.
2. Preview and run approved scanners, recording every preview, result, and
   skip in that lifecycle. Create the redacted payload and have the host model
   analyze it only after the separate AI-sharing approval. Record that exact
   assessment with kind `host_ai_triage` before delegation, including a detailed
   AI note for every finding at its zero-based `findingIndex`.
3. After host-AI triage is complete, ask separately: “May I give the bounded,
   redacted findings and AI triage to the dedicated `security-triage` agent for
   an independent review?” Do not delegate before an unambiguous yes.
4. Invoke `security-triage` with only the redacted scanner evidence and
   recorded host-AI triage. It may use primary advisory sources only when network access
   was approved; otherwise it must mark advisory claims as unverified.
5. Keep scanner evidence, host-AI assessment, and agent assessment as distinct
   sections. The agent may propose remediation but must not modify files.
6. Record the agent's exact review with kind `agent_review`.
7. Finalize the lifecycle once with initialization, doctor, plan, AI triage,
   and agent-review evidence.

## Boundaries

- The independent agent is a reviewer, not a second vulnerability scanner.
- No model or agent receives unredacted secrets or whole sensitive reports.
- No project source, dependency, or lockfile is modified.
