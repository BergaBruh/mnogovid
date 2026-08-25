---
name: system-scan
description: Plan, approve, execute, and report an evidence-first Linux host security assessment.
---

# Linux system scan

Use this skill for a Linux host assessment covering installed tools, malware and
rootkit checks, file integrity, package vulnerability evidence, persistence,
listeners, firewall configuration, and optional bounded traffic observation.

## Required consent

The user must separately approve each of the following:

1. `--write` for an optional `.mnogovid-system-scanner.json` in the selected
   report directory.
2. `--allow-active-network` to consider an active Nmap probe of one explicitly
   authorized literal IP.
3. `--allow-traffic-capture` to consider a bounded live TShark summary.
4. Every individual `system_run` after seeing its exact virtual command.

No approval implies another. Local scanners can consume CPU, disk I/O, or need
privilege, so each still needs an explicit per-command approval.

## Workflow

1. Resolve an existing report directory; never use `/` as that directory.
2. Run `scripts/init.py <report-directory> --json` with only approved flags,
   then call `system_doctor` and `system_plan`.
3. Start `system_start_run` in mode `scan`, recording every approval or denial.
4. Preview every candidate with `system_virtual_run`; record it as `preview`.
5. Run only individually approved commands through `system_run`, then record
   their exact redacted result as `scanner`. Record unavailable or declined
   adapters as `skipped`.
6. For `nmap-local`, require `allowActiveNetwork=true`, `authorizedTarget=true`,
   and exactly one literal IP that the user is allowed to scan. For
   `tshark-summary`, require `allowTrafficCapture=true`, an interface, and a
   5–300 second duration. Explain that its packet metadata may be sensitive.
7. Call `system_finalize_run`; it stores the report in
   `<report-directory>/.mnogovid/system-scanner/<timestamp>/result.md`.

## Boundaries

- Never install packages, run remediation, quarantine files, or write PCAPs.
- Never run arbitrary commands or a shell; use only the adapter allowlist.
- A clean report is not proof that the system is uncompromised.
- Encrypted or unobserved traffic, kernel-level stealth, unavailable tools, and
  distribution backports are explicit coverage gaps.
