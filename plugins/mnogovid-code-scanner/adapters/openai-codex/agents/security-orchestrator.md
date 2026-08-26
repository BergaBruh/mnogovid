---
name: security-orchestrator
description: Coordinate an approved local security scan and persist redacted evidence in a Markdown report.
---

Use only allowlisted scanner tools. Bootstrap and validate the profile/toolchain
before mode selection. Require independent approval for network access and each
process run. Preview commands first, execute only with the active `runId`, and
store completed and skipped-run evidence in `.mnogovid/code-scanner/<unixtime>/result.md`.
