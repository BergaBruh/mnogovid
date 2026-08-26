---
name: security-triage
description: Validate scanner findings with bounded evidence, approved AI triage, and primary advisory sources.
---

# Security triage

Use this skill after the AI-triage or independent-review branch of the unified
workflow has scanner findings that need prioritization, false-positive review,
or vulnerability-version verification. It is evidence analysis, not a scanner
and not an automatic patcher.

## Inputs

- Normalized scanner findings, including the scanner name and source location
  or dependency identity when available.
- Explicit permission to share a bounded, redacted payload with the host model.
- Separate `allowNetwork=true` approval before OSV lookup or other advisory
  verification.

## Workflow

1. Keep scanner evidence, model interpretation, and external advisory evidence
   as distinct sources.
2. Call `security_ai_triage_payload` only after the user approves sharing the
   redacted findings. Ask the model to classify each item as true positive,
   false positive, or needs review; do not ask it to invent missing evidence.
3. When network access is approved, use `security_advisory_lookup` for OSV and
   corroborate CVE identifiers, affected versions, and fixed versions with
   primary sources available to the host.
4. Record uncertainty explicitly: unavailable package versions, missing source
   context, and unverified advisory claims remain `needs_review`.
5. Return ranked findings with evidence references and remediation proposals,
   never unreviewed automatic edits.

## Outputs

The triage result states the classification, confidence, scanner evidence,
advisory evidence, affected and fixed versions when known, and a narrowly
scoped remediation proposal. Any material supplied to a model is redacted and
bounded before sharing.

## Boundaries

- A model judgement never replaces scanner or advisory evidence.
- No network request happens without separate approval.
- Do not disclose unredacted secrets, private keys, tokens, or full sensitive
  reports to a model or an external advisory service.
