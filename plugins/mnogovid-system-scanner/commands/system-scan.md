---
description: Choose and run a consent-gated local or remote Linux security assessment
---

Run one unified system-scanner workflow. Do not require command arguments.

Before scanner-mode selection, complete bootstrap for the selected target.

1. **Target:** “Analyze this local host, or a remote SSH alias?” If remote is
   chosen, ask only for its SSH alias, then ask: “May I connect read-only to
   `<ssh-alias>` and inspect whether the Mnogovid runner is ready?” After yes,
   call `system_remote_prepare`. Do not request a remote plugin path or Python
   path. If the runner is missing or outdated, ask a separate question: “May I
   deploy or update the Mnogovid runner under the remote user's
   `~/.local/share/mnogovid-system-scanner`?” Only after yes, call
   `system_remote_authorize_deploy` with `approveDeployment=true`, then consume
   its ticket with `system_remote_deploy_runner`. Remote tool calls must use
   `system_remote_call` with that alias; local tool calls must use `system_*`
   directly. Never mix the two in one lifecycle.
2. **Bootstrap:** Call `system_bootstrap` with `createProfile=false`. If its
   profile action is `missing`, ask: “Create the missing system-scanner profile
   in this directory? This records discovery only; it does not start a scan.”
   Call it again with `createProfile=true` only after yes. If the profile is
   invalid, stop and report that it must be repaired explicitly. Show a separate
   utility-readiness message: available adapters, missing adapters, detected
   package managers, candidate package names, and install command templates.
   For a remote target, obtain the same message through `system_remote_call`.
   Do not continue to scanning while required selected adapters are missing.
3. **Mode:** Only after successful bootstrap, ask: “How should I analyze the evidence?” Present exactly these modes:
   - **Adapters only** — reproducible local scanner evidence.
   - **Adapters + AI triage** — scanner evidence plus bounded, redacted host-AI
     classification.
   - **Adapters + AI triage + independent review** — adds a separately approved
     `system-triage` assessment after host-AI triage.

Map the mode to `system_start_run`: `scan`, `scan-ai`, or `scan-agent`.
Use only the chosen target's tools; never mix local and remote tool results in
one lifecycle.

Then request independent consent for: creating the profile, networked image
vulnerability databases, active Nmap probes, local service probes, traffic
capture, every scanner command, host-AI sharing (AI modes), and independent
review (review mode). Treat anything but an unambiguous yes as denial.

Use bootstrap's doctor result and then call `system_plan`; start exactly one
lifecycle; preview every adapter; and execute only an identical, recorded
preview with that lifecycle `runId`. Record all results and skips. Never
install tools, use `sudo`, apply remediation, save a PCAP, expose a remote MCP
port, copy credentials, or enable SSH agent forwarding.

For AI modes, create `system_ai_triage_payload` only after AI consent and
record exactly one detailed `findingNotes` entry per finding. For independent
review, ask a final separate consent, then keep scanner, host-AI, and reviewer
evidence distinct. Finalize once and return the report path and coverage gaps.
