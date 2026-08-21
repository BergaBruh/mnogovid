---
name: security-scan-agent
description: Run local scanners, obtain host-AI triage, then request an independent security-triage agent review.
---

# Security scan with AI and independent agent review

Use this skill when the user wants the complete evidence-first security
workflow: approved local scanning, host-AI triage of redacted findings, and a
separate `security-triage` agent review.

## Workflow

1. Follow the foundational scan and AI-triage steps from `security-scan-ai`:
   ask separately about `--write`, `--allow-network`, every scanner process,
   and host-AI sharing; initialize, discover and plan scanners; then start one
   lifecycle in mode `scan-agent` and record every granted or denied consent.
2. Preview and run approved scanners, recording every preview, result, and
   skip in that lifecycle. Create the redacted payload and have the host model
   analyze it only after the separate AI-sharing approval. Record that exact
   assessment with kind `host_ai_triage` before delegation.
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
