---
description: Run a consent-gated Linux host security assessment without AI analysis
argument-hint: '[report-directory]'
---

Run a complete system assessment against the local Linux host. Never invoke an
AI model, `system_ai_triage_payload`, `system-triage`, web search, or an
external advisory lookup.

The user invoked `/mnogovid-system-scanner:system-scan` with:

```text
$ARGUMENTS
```

Use `$ARGUMENTS` as the report directory when supplied; otherwise use the
current workspace. Resolve it to an absolute existing directory. Never use `/`
as the report directory.

Before doing anything, ask separately in chat:

1. “Create the local `.mnogovid-system-scanner.json` profile with `--write`?
   Without approval, inspect only.”
2. “Allow active port probes of explicitly authorized IP addresses? This only
   permits consideration of an Nmap run; every target still needs a preview and
   a separate approval.”
3. “Allow bounded metadata-only traffic capture? This only permits
   consideration of a 5–300 second TShark summary; every capture still needs a
   preview and a separate approval.”

Treat any answer other than an unambiguous yes as denial. Run
`scripts/init.py <report-directory> --json` using only the approved flags;
then call `system_doctor` and `system_plan`. Report available and missing
executables but never install a package or invoke `sudo`.

Before previews, call `system_start_run` with mode `scan` and record the three
answers in `consent`. Retain the returned `runId`.

For every planned adapter:

1. Call `system_virtual_run` and record its exact result with
   `system_record_run` kind `preview`.
2. Show the command, its purpose, privilege/volume risk, and whether it needs
   active-network or traffic-capture consent.
3. Ask for approval of that exact `system_run` only. Pass the same `runId`; the
   server rejects execution unless its exact argv was already previewed in that
   lifecycle.
4. Record each result as `scanner`. Record unavailable or declined adapters as
   `skipped` with the reason.

For `nmap-local`, require lifecycle active-network consent, `authorizedTarget`
set to true, and exactly one literal IP explicitly authorized by the user. For
`tshark-summary`, require lifecycle traffic-capture consent, a valid interface,
and a duration from 5 through 300 seconds. Do not capture a PCAP.

Call `system_finalize_run` exactly once with `runId`, initialization, doctor,
and plan. Return its report path and concrete coverage gaps. The report belongs
at `<report-directory>/.mnogovid/system-scanner/<timestamp>/result.md`.
