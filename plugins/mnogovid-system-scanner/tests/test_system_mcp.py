from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "system_mcp.py"
INIT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "init.py"
SPEC = importlib.util.spec_from_file_location("system_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
system_mcp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(system_mcp)


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class SystemMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name

    def tearDown(self) -> None:
        system_mcp.RUNS.clear()
        system_mcp.REMOTE_DEPLOYMENTS.clear()
        self.temp.cleanup()

    def test_plan_is_non_executing(self) -> None:
        value = payload(system_mcp.call("system_plan", {"reportDirectory": self.root}))
        self.assertFalse(value["processStarted"])
        self.assertTrue(value["runs"])
        self.assertIn("host", value)
        self.assertIn("installationGuide", value)

    def test_installation_guidance_is_per_detected_host(self) -> None:
        runs = [{"adapter": "lynis", "executable": "lynis", "available": False}]
        guide = system_mcp.installation_guide({"packageManagers": ["apt-get", "pacman"]}, runs)
        self.assertEqual(guide["missingAdapters"][0]["candidatePackages"]["apt-get"], "lynis")
        self.assertEqual(guide["packageManagers"][0]["commandTemplate"], "sudo apt-get install <package>")

    def test_bootstrap_creates_profile_only_after_explicit_request(self) -> None:
        first = payload(system_mcp.call("system_bootstrap", {"reportDirectory": self.root}))
        self.assertEqual(first["profile"]["action"], "missing")
        self.assertFalse(Path(first["profile"]["path"]).exists())
        created = payload(system_mcp.call("system_bootstrap", {"reportDirectory": self.root, "createProfile": True}))
        self.assertEqual(created["profile"]["action"], "created")
        repeated = payload(system_mcp.call("system_bootstrap", {"reportDirectory": self.root}))
        self.assertEqual(repeated["profile"]["action"], "verified")

    def test_virtual_listener_preview_never_starts_process(self) -> None:
        value = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "listeners"}))
        self.assertFalse(value["processStarted"])
        self.assertEqual(value["execution"], "virtual")
        self.assertEqual(value["command"]["argv"][-1], "-lntup")

    def test_active_scan_requires_authorized_literal_ip(self) -> None:
        result = system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "nmap-local", "target": "localhost"})
        self.assertTrue(result["isError"])
        self.assertIn("literal IP", payload(result)["error"])
        result = system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "nmap-local", "target": "127.0.0.1"})
        self.assertTrue(result["isError"])
        self.assertIn("authorizedTarget", payload(result)["error"])

    def test_traffic_preview_is_bounded(self) -> None:
        result = system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "tshark-summary", "interface": "eth0", "durationSeconds": 301})
        self.assertTrue(result["isError"])
        self.assertIn("5 through 300", payload(result)["error"])
        value = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "tshark-summary", "interface": "eth0", "durationSeconds": 30}))
        self.assertTrue(value["requiresTrafficCapture"])
        self.assertIn("duration:30", value["command"]["argv"])

    def test_container_image_and_inspect_previews_are_bounded(self) -> None:
        result = system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "docker-inspect", "containerId": "bad;value"})
        self.assertTrue(result["isError"])
        value = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "docker-inspect", "containerId": "web-api.1"}))
        self.assertEqual(value["command"]["argv"][-1], "web-api.1")
        image = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "trivy-image", "imageRef": "registry.example/app:1.2"}))
        self.assertTrue(image["requiresNetwork"])
        self.assertIn("registry.example/app:1.2", image["command"]["argv"])

    def test_docker_inspect_returns_only_security_findings(self) -> None:
        output = json.dumps([{"Config": {"Env": ["TOKEN=must-not-leak"], "User": ""}, "HostConfig": {"Privileged": True, "NetworkMode": "host", "CapAdd": ["SYS_ADMIN"], "SecurityOpt": ["seccomp=unconfined"]}, "Mounts": [{"Source": "/", "Destination": "/host"}, {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]}])
        findings, observations = system_mcp.normalize_docker_inspect(output)
        self.assertGreaterEqual(len(findings), 5)
        self.assertTrue(any("root filesystem" in item["title"] for item in findings))
        self.assertNotIn("must-not-leak", json.dumps(findings + [{"observation": item} for item in observations]))

    def test_image_scanners_normalize_findings_without_raw_report(self) -> None:
        trivy = {"Results": [{"Target": "app:1", "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-1", "Severity": "CRITICAL", "PkgName": "openssl", "InstalledVersion": "1.0", "FixedVersion": "1.1", "Title": "example"}]}]}
        findings, observations = system_mcp.normalize_image_scan("trivy-image", json.dumps(trivy))
        self.assertEqual(observations, [])
        self.assertEqual(findings[0]["ruleId"], "CVE-2026-1")
        self.assertEqual(findings[0]["fixedVersion"], "1.1")
        findings, observations = system_mcp.normalize_image_scan("dockle-image", "FATAL - CIS-DI-0001: Create a user for the container\nsecret details must not be retained\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(observations, [])

    def test_inventory_is_not_automatically_a_security_finding(self) -> None:
        findings, observations = system_mcp.normalize_output("listeners", "tcp LISTEN 0 4096 127.0.0.1:8080\n")
        self.assertEqual(findings, [])
        self.assertEqual(observations, ["tcp LISTEN 0 4096 127.0.0.1:8080"])
        findings, observations = system_mcp.normalize_output("clamav", "/tmp/example: Eicar-Test-Signature FOUND\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(observations, [])

    def test_lifecycle_writes_redacted_report_without_scanning(self) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {"profileWrite": False, "activeNetwork": False, "trafficCapture": False, "aiTriage": False, "agentReview": False}}))
        run_id = started["runId"]
        preview = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "listeners"}))
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "preview", "entry": preview})
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "skipped", "entry": {"adapter": "clamav", "reason": "not approved"}})
        final = payload(system_mcp.call("system_finalize_run", {"reportDirectory": self.root, "runId": run_id}))
        report = Path(final["path"])
        self.assertTrue(report.is_file())
        self.assertIn("clamav", report.read_text(encoding="utf-8"))

    def test_lifecycle_refuses_symlinked_report_root(self) -> None:
        outside = Path(self.root) / "outside"
        outside.mkdir()
        (Path(self.root) / ".mnogovid").symlink_to(outside, target_is_directory=True)
        result = system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {}})
        self.assertTrue(result["isError"])
        self.assertIn("symlink", payload(result)["error"])

    def test_lifecycle_refuses_replaced_state_symlink(self) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {}}))
        state = Path(started["statePath"])
        state.unlink()
        state.symlink_to(Path(self.root) / "outside")
        result = system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": started["runId"], "kind": "skipped", "entry": {"adapter": "clamav", "reason": "not approved"}})
        self.assertTrue(result["isError"])
        self.assertIn("symlink", payload(result)["error"])

    def test_active_network_execution_needs_lifecycle_consent(self) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {"activeNetwork": False}}))
        preview = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "nmap-local", "target": "127.0.0.1", "authorizedTarget": True}))
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": started["runId"], "kind": "preview", "entry": preview})
        result = system_mcp.call("system_run", {"reportDirectory": self.root, "runId": started["runId"], "adapter": "nmap-local", "target": "127.0.0.1", "authorizedTarget": True})
        self.assertTrue(result["isError"])
        self.assertIn("consent", payload(result)["error"])

    def test_service_probe_execution_needs_lifecycle_consent(self) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {"serviceProbe": False}}))
        preview = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "mysql-status"}))
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": started["runId"], "kind": "preview", "entry": preview})
        result = system_mcp.call("system_run", {"reportDirectory": self.root, "runId": started["runId"], "adapter": "mysql-status"})
        self.assertTrue(result["isError"])
        self.assertIn("service-probe consent", payload(result)["error"])

    def test_init_refuses_a_symlinked_profile(self) -> None:
        profile = Path(self.root) / ".mnogovid-system-scanner.json"
        profile.symlink_to(Path(self.root) / "outside-profile")
        completed = subprocess.run([sys.executable, str(INIT_PATH), self.root, "--write", "--json"], capture_output=True, text=True, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("symlinked profile", completed.stderr)

    def test_ingest_normalizes_sarif_without_starting_a_process(self) -> None:
        report = Path(self.root) / "report.sarif"
        report.write_text(json.dumps({"runs": [{"results": [{"ruleId": "CVE-2026-0001", "level": "error", "message": {"text": "vulnerable package"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/usr/bin/example"}, "region": {"startLine": 3}}}]}]}]}), encoding="utf-8")
        result = payload(system_mcp.call("system_ingest", {"reportDirectory": self.root, "report": str(report), "format": "sarif", "adapter": "imported"}))
        self.assertTrue(result["reportOnly"])
        self.assertEqual(result["counts"]["findings"], 1)
        self.assertEqual(result["findings"][0]["ruleId"], "CVE-2026-0001")

    def test_ingest_refuses_external_or_symlinked_report(self) -> None:
        external = Path(self.root).parent / "external-report.json"
        external.write_text("[]", encoding="utf-8")
        result = system_mcp.call("system_ingest", {"reportDirectory": self.root, "report": str(external), "format": "json"})
        self.assertTrue(result["isError"])
        self.assertIn("inside reportDirectory", payload(result)["error"])
        linked = Path(self.root) / "linked.json"
        linked.symlink_to(external)
        result = system_mcp.call("system_ingest", {"reportDirectory": self.root, "report": str(linked), "format": "json"})
        self.assertTrue(result["isError"])
        self.assertIn("symlink", payload(result)["error"])
        linked.unlink()
        external.unlink()

    def test_advisory_lookup_requires_network_consent(self) -> None:
        result = system_mcp.call("system_advisory_lookup", {"ecosystem": "Debian", "package": "openssl", "version": "1.0", "allowNetwork": False})
        self.assertTrue(result["isError"])
        self.assertIn("allowNetwork", payload(result)["error"])

    def test_catalog_exposes_ingest_and_advisory_workflows(self) -> None:
        catalog = payload(system_mcp.call("system_catalog", {}))
        names = {item["id"] for item in catalog["adapters"]}
        self.assertIn("journal-warnings", names)
        tools = {item["name"] for item in system_mcp.TOOLS}
        self.assertTrue({"system_bootstrap", "system_ingest", "system_advisory_lookup", "system_remote_prepare", "system_remote_authorize_deploy", "system_remote_deploy_runner", "system_remote_call"}.issubset(tools))

    def test_cross_surface_assets_exist(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for relative in ("claude-code.mcp.json.example", "opencode.json.example", "bin/mnogovid-system-scanner.mjs", "commands/system-scan.md", "adapters/openai-codex/agents/system-orchestrator.md", "adapters/claude/agents/system-triage.md", "adapters/opencode/.opencode/commands/system-scan.md"):
            self.assertTrue((root / relative).is_file(), relative)

    def test_npm_mcp_binary_proxies_to_the_python_server(self) -> None:
        root = Path(__file__).resolve().parents[1]
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["name"], "@bergabruh/system-scanner")
        self.assertEqual(package["bin"]["mnogovid-system-scanner"], "./bin/mnogovid-system-scanner.mjs")
        self.assertIn("bin/*.mjs", package["files"])
        self.assertIn("scripts/*.py", package["files"])
        entrypoint = root / "bin" / "mnogovid-system-scanner.mjs"
        self.assertTrue(entrypoint.is_file())
        entrypoint_text = entrypoint.read_text(encoding="utf-8")
        self.assertIn("python3", entrypoint_text)
        self.assertIn("system_mcp.py", entrypoint_text)
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        completed = subprocess.run(["node", str(entrypoint)], input=json.dumps(request) + "\n", text=True, capture_output=True, timeout=5, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        response = json.loads(completed.stdout)
        self.assertEqual(response["id"], 1)
        self.assertIn("tools", response["result"])

    @patch.object(system_mcp, "remote_probe")
    @patch.object(system_mcp, "deploy_remote_runner")
    def test_remote_runner_requires_one_time_deployment_ticket(self, deploy, probe) -> None:
        probe.return_value = {"sshAlias": "prod-audit", "pythonPath": "/usr/bin/python3", "home": "/home/audit", "runnerExists": False, "version": None}
        ticket = system_mcp.remote_deployment_ticket("prod-audit", True)
        result = system_mcp.consume_remote_deployment("prod-audit", ticket["deploymentId"])
        deploy.assert_called_once_with("prod-audit", "/usr/bin/python3")
        self.assertEqual(result["deployment"], "updated")
        with self.assertRaises(ValueError):
            system_mcp.consume_remote_deployment("prod-audit", ticket["deploymentId"])

    @patch.object(system_mcp, "remote_probe")
    @patch.object(system_mcp, "ssh_run")
    def test_remote_call_forwards_only_allowlisted_mcp_operation(self, ssh, probe) -> None:
        probe.return_value = {"sshAlias": "prod-audit", "pythonPath": "/usr/bin/python3", "home": "/home/audit", "runnerExists": True, "version": system_mcp.REMOTE_RUNNER_RELEASE}
        ssh.return_value = subprocess.CompletedProcess([], 0, json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"isError": False, "content": []}}), "")
        result = system_mcp.remote_call("prod-audit", "system_plan", {"reportDirectory": "/home/audit"})
        self.assertFalse(result["isError"])
        with self.assertRaises(ValueError):
            system_mcp.remote_call("prod-audit", "system_remote_deploy_runner", {})
        probe.return_value["version"] = "old"
        with self.assertRaises(ValueError):
            system_mcp.remote_call("prod-audit", "system_plan", {"reportDirectory": "/home/audit"})

    def test_remote_alias_must_be_declared_in_private_ssh_config(self) -> None:
        home = Path(self.root) / "home"
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(parents=True)
        ssh_dir.chmod(0o700)
        config = ssh_dir / "config"
        config.write_text("Host prod-audit\n  HostName example.invalid\n", encoding="utf-8")
        config.chmod(0o600)
        with patch.object(system_mcp.Path, "home", return_value=home):
            self.assertEqual(system_mcp.validate_ssh_alias("prod-audit"), "prod-audit")
            with self.assertRaises(ValueError):
                system_mcp.validate_ssh_alias("example.invalid")

    def test_ssh_remote_args_preserve_shell_boundaries(self) -> None:
        argv = system_mcp.ssh_argv("prod-audit", ["sh", "-lc", "command -v python3"])
        remote_command = " ".join(argv[11:])
        completed = subprocess.run(["sh", "-lc", remote_command], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(completed.stdout.strip(), remote_command)

    def test_unified_command_uses_chat_consent_and_mode_selection(self) -> None:
        root = Path(__file__).resolve().parents[1]
        command = (root / "commands" / "system-scan.md").read_text(encoding="utf-8")
        self.assertNotIn("argument-hint:", command)
        self.assertIn("May I connect read-only", command)
        self.assertIn("Do not require command arguments", command)
        self.assertIn("Adapters + AI triage", command)
        self.assertIn("system_bootstrap", command)
        self.assertFalse((root / "commands" / "system-scan-ai.md").exists())
        self.assertFalse((root / "commands" / "system-scan-agent.md").exists())
        self.assertFalse((root / "commands" / "system-scan-remote.md").exists())

    def test_report_has_reader_first_sections_and_recovery_gap(self) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {}}))
        run_id = started["runId"]
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "skipped", "entry": {"adapter": "aide", "reason": "scanner executable missing"}})
        final = payload(system_mcp.call("system_finalize_run", {"reportDirectory": self.root, "runId": run_id}))
        document = Path(final["path"]).read_text(encoding="utf-8")
        self.assertIn("## What needs attention", document)
        self.assertIn("## Coverage gaps", document)
        self.assertIn("## Scan coverage", document)
        self.assertIn("## Report details", document)

    def test_recommendation_is_distribution_aware(self) -> None:
        recommended = system_mcp.recommend_host({"packageManagers": ["apt-get"], "containerRuntimes": ["docker"]})
        self.assertIn("debsecan", recommended)
        self.assertNotIn("rpm-verify", recommended)
        self.assertIn("docker-containers", recommended)

    def test_reader_first_report_renders_structured_finding_and_ai_note(self) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan-ai", "consent": {"aiTriage": True}}))
        run_id = started["runId"]
        scanner = {"adapter": "listeners", "command": {"argv": ["ss", "-H", "-lntup"], "currentDir": self.root}, "resultStatus": "complete", "exitCode": 0, "findings": [{"severity": "high", "title": "unexpected listener", "location": "0.0.0.0:9000"}], "observations": []}
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "scanner", "entry": scanner})
        triage = {"findingNotes": [{"findingIndex": 0, "classification": "needs_review", "confidence": 0.8, "note": "Verify service ownership."}]}
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "host_ai_triage", "entry": triage})
        final = payload(system_mcp.call("system_finalize_run", {"reportDirectory": self.root, "runId": run_id}))
        document = Path(final["path"]).read_text(encoding="utf-8")
        self.assertIn("unexpected listener", document)
        self.assertIn("0.0.0.0:9000", document)
        self.assertIn("Verify service ownership.", document)


if __name__ == "__main__":
    unittest.main()
