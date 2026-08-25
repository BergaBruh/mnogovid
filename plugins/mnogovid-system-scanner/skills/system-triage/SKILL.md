---
name: system-triage
description: Independently review bounded, redacted Linux host-security findings without scanning or remediation.
---

# Linux system triage

Use after a completed system scan and explicit approval to share redacted
evidence. For each finding, state the underlying scanner evidence, confidence,
likely false-positive causes, and the smallest next read-only verification.

If the user separately permits network advisory lookup, call
`system_advisory_lookup` for one exact package ecosystem/name/version and keep
that result distinct from scanner and model evidence. Without that permission,
mark advisory status unverified. Do not run scanners, access a host, request
secrets, or claim that a clean scan proves absence of compromise. Treat traffic
observations as sampled telemetry and CVE matches as potentially affected by
distribution backports.
