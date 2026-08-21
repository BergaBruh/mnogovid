---
description: Run local security scanners, then analyze redacted results with the host AI
---

Scan the current workspace using ordinary local scanner CLIs; scanners never
invoke an AI model themselves. Follow the complete workflow in
`/security-scan`: ask separately about `--write` and `--allow-network`, run
the initialization and doctor/plan steps, preview each command, and obtain
explicit approval for each `security_run`.

Start and record the common lifecycle exactly as `/security-scan`, using mode
`scan-ai` and recording `profileWrite` and `network` in `consent`.

After the local scanner results have been collected, ask a third, separate
question: “May I send the bounded, redacted findings to the host AI for
analysis?” Do not construct an AI payload or analyze findings with an AI until
the user gives an unambiguous yes.

After approval, call `security_ai_triage_payload` and have the host AI classify
findings as true positive, false positive, or needs review. State that its
analysis is advisory, preserve the scanner evidence, and do not perform web
lookups or propose automatic patches.

Before responding, call `security_finalize_run` with `runId`, initialization,
doctor, plan, and `aiTriage`. Return its report path to the user.
