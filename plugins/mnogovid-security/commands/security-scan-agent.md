---
description: Run scanners, use host AI triage, and obtain an independent security-triage agent review
---

Run the complete `/security-scan-ai` workflow for the current workspace,
including all three separate approvals: `--write`, `--allow-network`, and
sharing bounded, redacted findings with the host AI. Do not infer any one of
these approvals from the others.

Start and record the common lifecycle exactly as `/security-scan`, using mode
`scan-agent` and recording every granted or denied consent in `consent`.

Once the host AI triage is complete, ask a fourth separate question: “May I
give the bounded, redacted findings and AI triage to the dedicated
`security-triage` agent for an independent review?” Do not delegate before an
unambiguous yes.

After approval, invoke the `security-triage` agent with only the redacted
scanner evidence and host-AI triage. The agent must independently validate
claims against primary advisory sources when network access was approved; when
it was not, it must label those claims as unverified rather than browse. Report
scanner evidence, host-AI judgement, and agent judgement as separate sections.
The agent may propose remediation, but must not modify project files.

Before responding, call `security_finalize_run` with `runId`, initialization,
doctor, plan, `aiTriage`, and `agentReview`. Return its report path to the user.
