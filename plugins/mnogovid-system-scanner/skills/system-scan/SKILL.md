---
name: system-scan
description: Plan, approve, execute, and report an evidence-first Linux host security assessment.
---

# Linux system scan

Use this skill for the adapters-only branch of the unified System Scanner
workflow. Bootstrap the selected local or remote target first, then assess
installed tools, malware/rootkits, integrity, packages, persistence, listeners,
firewall configuration, and optional bounded traffic observation.

## Required consent

The user must separately approve each of the following:

1. Create a missing `.mnogovid-system-scanner.json` profile in the selected
   report directory.
2. Networked image scanner databases, active Nmap probes, local service probes,
   and bounded TShark observation as applicable.
3. Every individual `system_run` after seeing its exact virtual command.

No approval implies another. Local scanners can consume CPU, disk I/O, or need
privilege, so each still needs an explicit per-command approval.

## Workflow

1. Resolve an existing report directory; never use `/` as that directory.
2. Call `system_bootstrap` with `createProfile=false`. Ask before creating a
   missing profile; stop on an invalid profile. Use its doctor result, then call
   `system_plan`.
3. Start `system_start_run` in mode `scan`, recording every approval or denial.
4. Preview every candidate with `system_virtual_run`; record it as `preview`.
5. Run only individually approved commands through `system_run`, then record
   their exact redacted result as `scanner`. Record unavailable or declined
   adapters as `skipped`.
6. For `nmap-local`, record lifecycle active-network consent,
   require `authorizedTarget=true`, and use exactly one literal IP the user is
   allowed to scan. For `tshark-summary`, record lifecycle traffic-capture
   consent, require an interface, and use a 5–300 second duration. Explain that
   its packet metadata may be sensitive.
7. Call `system_finalize_run`; it stores the report in
   `<report-directory>/.mnogovid/system-scanner/<timestamp>/result.md`.

## Boundaries

- Never install packages, run remediation, quarantine files, or write PCAPs.
- Never run arbitrary commands or a shell; use only the adapter allowlist.
- Every execution requires the current lifecycle `runId` and an argv-identical
  recorded preview.
- A clean report is not proof that the system is uncompromised.
- Encrypted or unobserved traffic, kernel-level stealth, unavailable tools, and
  distribution backports are explicit coverage gaps.
