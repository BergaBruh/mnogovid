---
description: Run local security scanners without any AI analysis
---

Scan the current workspace only. Never invoke an AI model, AI-triage payload,
the `security-triage` agent, web advisory lookup, or an external web search.

Before taking any action, ask separately in chat:

1. “Create the local `.mnogovid-code-scanner.json` profile with `--write`? Without approval, inspect only.”
2. “Allow network-dependent scanners with `--allow-network`? Initialization itself does not use the network; each scanner still needs separate approval.”

Treat any answer other than an unambiguous yes as denial. Resolve the current
workspace to an absolute path and run `scripts/init.py` with `--json`, adding
only the approved flags. Show available and missing scanners, then call
`security_doctor` and `security_plan`.

Before previews, call `security_start_run` with mode `scan` and a `consent`
object that records the two user answers; retain its `runId`.

For every proposed scanner, call `security_virtual_run` first and append it via
`security_record_run` with kind `preview`. Ask for explicit
approval of every real `security_run`; for network-dependent scanners, require
both the earlier network permission and approval of that specific run. Ingest
or summarize the local scanner output only, append each result with kind
`scanner`, and append skipped scanners with kind `skipped`.

Before responding, call `security_finalize_run` with `runId`, initialization,
doctor, and plan. It owns the report schema and creates the only report artifact
at `<current-workspace>/.mnogovid/code-scanner/<unixtime>/result.md`.
