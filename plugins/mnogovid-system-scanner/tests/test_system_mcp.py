from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


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

    @patch.object(system_mcp, "trusted_executable", side_effect=lambda name: "/usr/bin/" + name)
    def test_virtual_listener_preview_never_starts_process(self, trusted) -> None:
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

    @patch.object(system_mcp, "trusted_executable", side_effect=lambda name: "/usr/bin/" + name)
    def test_traffic_preview_is_bounded(self, trusted) -> None:
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
        preview = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "journal-warnings"}))
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

    @patch.object(system_mcp, "trusted_executable", side_effect=lambda name: "/usr/bin/" + name)
    def test_root_required_adapter_needs_lifecycle_consent(self, trusted) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {"rootPrivileges": False}}))
        preview = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "rkhunter"}))
        self.assertTrue(preview["requiresRoot"])
        self.assertEqual(preview["command"]["argv"][:2], ["/usr/bin/sudo", "-n"])
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": started["runId"], "kind": "preview", "entry": preview})
        result = system_mcp.call("system_run", {"reportDirectory": self.root, "runId": started["runId"], "adapter": "rkhunter"})
        self.assertTrue(result["isError"])
        self.assertIn("root-privilege consent", payload(result)["error"])

    @patch.object(system_mcp, "trusted_executable", side_effect=lambda name: "/usr/bin/" + name)
    @patch.object(system_mcp.shutil, "which")
    @patch.object(system_mcp.subprocess, "Popen")
    def test_long_root_adapter_starts_job_without_waiting(self, popen, which, trusted) -> None:
        which.side_effect = lambda name: "/usr/bin/" + name
        process = MagicMock()
        process.pid = 12345
        popen.return_value = process
        result = system_mcp.start_job(Path(self.root), {"adapter": "rkhunter"})
        self.assertEqual(result["resultStatus"], "running")
        self.assertIn("jobId", result)
        self.assertEqual(result["command"]["argv"][:2], ["/usr/bin/sudo", "-n"])
        job_dir = Path(self.root) / ".mnogovid" / "system-scanner" / result["jobId"]
        self.assertTrue((job_dir / "job-state.json").is_file())
        self.assertTrue((job_dir / "launch").is_file())

    def test_durable_background_job_can_be_polled_after_start(self) -> None:
        adapter = "test-background"
        system_mcp.ADAPTERS[adapter] = {"category": "test", "exe": sys.executable, "network": False, "traffic": False, "background": True, "timeout": 5, "argv": lambda _: ["-c", "print('job evidence')"]}
        try:
            started = system_mcp.start_job(Path(self.root), {"adapter": adapter})
            for _ in range(30):
                result = system_mcp.poll_job(Path(self.root), started["jobId"])
                if result["resultStatus"] != "running": break
                time.sleep(0.05)
            self.assertEqual(result["resultStatus"], "complete")
            self.assertEqual(result["jobId"], started["jobId"])
        finally:
            system_mcp.ADAPTERS.pop(adapter, None)

    def test_background_timeout_terminates_descendant_process_group(self) -> None:
        adapter = "test-timeout-group"
        child_code = "import time; time.sleep(30)"
        parent_code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c',%r]); print(p.pid,flush=True); time.sleep(30)" % child_code
        system_mcp.ADAPTERS[adapter] = {"category": "test", "exe": sys.executable, "network": False, "traffic": False, "background": True, "timeout": 0.1, "argv": lambda _: ["-c", parent_code]}
        try:
            started = system_mcp.start_job(Path(self.root), {"adapter": adapter})
            for _ in range(80):
                result = system_mcp.poll_job(Path(self.root), started["jobId"])
                if result["resultStatus"] != "running": break
                time.sleep(0.05)
            self.assertEqual(result["resultStatus"], "failed")
            job_dir = Path(self.root) / ".mnogovid" / "system-scanner" / started["jobId"]
            child_pid = int((job_dir / "stdout.log").read_text(encoding="utf-8").strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            system_mcp.ADAPTERS.pop(adapter, None)

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

    @patch.object(system_mcp, "ssh_run")
    def test_remote_probe_accepts_python3_under_python_name(self, ssh) -> None:
        probe_status = {"home": "/home/audit", "runnerPath": "/home/audit/.local/share/mnogovid-system-scanner/system_mcp.py", "versionPath": "/home/audit/.local/share/mnogovid-system-scanner/version", "runnerExists": False, "version": None}
        def reply(alias, args, **kwargs):
            if args[:2] == ["sh", "-lc"]:
                return subprocess.CompletedProcess([], 0, "/usr/local/bin/python\n" if "python'" in args[2] or "python\"" in args[2] or args[2].endswith("python") else "", "")
            if args[0] == "/usr/local/bin/python" and args[1] == "-c" and "version_info" in args[2]:
                return subprocess.CompletedProcess([], 0, "", "")
            return subprocess.CompletedProcess([], 0, json.dumps(probe_status), "")
        ssh.side_effect = reply
        status = system_mcp.remote_probe("audit@example.invalid:9922")
        self.assertEqual(status["pythonPath"], "/usr/local/bin/python")

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

    def test_explicit_ssh_target_skips_local_config_lookup(self) -> None:
        with patch.object(system_mcp.Path, "home", side_effect=AssertionError("config must not be read")):
            self.assertEqual(system_mcp.validate_ssh_alias("audit@example.invalid"), "audit@example.invalid")
            self.assertEqual(system_mcp.validate_ssh_alias("audit@example.invalid:9922"), "audit@example.invalid:9922")

    def test_explicit_ssh_target_port_is_passed_to_ssh(self) -> None:
        argv = system_mcp.ssh_argv("audit@example.invalid:9922", ["sh", "-lc", "command -v python3"])
        self.assertIn("-p", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "9922")
        self.assertIn("audit@example.invalid", argv)
        self.assertNotIn("audit@example.invalid:9922", argv)

    def test_remote_prepare_requires_connection_consent_before_config(self) -> None:
        with patch.object(system_mcp.Path, "home", side_effect=AssertionError("config must not be read")):
            result = system_mcp.call("system_remote_prepare", {"sshAlias": "audit@example.invalid", "approveConnection": False})
        self.assertTrue(result["isError"])
        self.assertIn("approval", payload(result)["error"])

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
        self.assertIn("Never read `~/.ssh/config` to discover or list", command)
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

    def test_lifecycle_and_preview_retries_are_idempotent(self) -> None:
        consent = {"rootPrivileges": False}
        first = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": consent}))
        resumed = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": consent}))
        self.assertEqual(first["runId"], resumed["runId"])
        self.assertTrue(resumed["resumed"])
        preview = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "journal-warnings"}))
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": first["runId"], "kind": "preview", "entry": preview})
        duplicate = payload(system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": first["runId"], "kind": "preview", "entry": preview}))
        self.assertTrue(duplicate["duplicate"])

    @patch.object(system_mcp, "start_job")
    def test_execution_retry_reuses_previous_result(self, start_job) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan", "consent": {}}))
        run_id = started["runId"]
        preview = payload(system_mcp.call("system_virtual_run", {"reportDirectory": self.root, "adapter": "journal-warnings"}))
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "preview", "entry": preview})
        fake = {**preview, "execution": "executed", "processStarted": True, "resultStatus": "complete", "exitCode": 0, "findings": [], "observations": [], "counts": {"findings": 0, "observations": 0}}
        start_job.return_value = fake
        first = payload(system_mcp.call("system_run", {"reportDirectory": self.root, "runId": run_id, "adapter": "journal-warnings"}))
        second = payload(system_mcp.call("system_run", {"reportDirectory": self.root, "runId": run_id, "adapter": "journal-warnings"}))
        self.assertEqual(first, second)
        start_job.assert_called_once()

    def test_ai_triage_batches_merge_and_accept_named_confidence(self) -> None:
        started = payload(system_mcp.call("system_start_run", {"reportDirectory": self.root, "mode": "scan-ai", "consent": {"aiTriage": True}}))
        run_id = started["runId"]
        scanner = {"adapter": "listeners", "command": {"argv": ["ss", "-H", "-lntup"], "currentDir": self.root}, "resultStatus": "complete", "exitCode": 0, "findings": [{"severity": "high", "title": "one"}, {"severity": "medium", "title": "two"}], "observations": []}
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "scanner", "entry": scanner})
        first = {"findingOffset": 0, "findingNotes": [{"findingIndex": 0, "classification": "needs_review", "confidence": "medium", "note": "check one"}]}
        second = {"findingOffset": 1, "findingNotes": [{"findingIndex": 0, "classification": "false_positive", "confidence": "high", "note": "check two"}]}
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "host_ai_triage", "entry": first})
        system_mcp.call("system_record_run", {"reportDirectory": self.root, "runId": run_id, "kind": "host_ai_triage", "entry": second})
        final = payload(system_mcp.call("system_finalize_run", {"reportDirectory": self.root, "runId": run_id}))
        document = Path(final["path"]).read_text(encoding="utf-8")
        self.assertIn("check one", document)
        self.assertIn("check two", document)

    def test_remote_finalize_is_mirrored_to_local_directory(self) -> None:
        response = {"result": {"isError": False, "content": [{"type": "text", "text": json.dumps({"reportId": "123", "path": "/remote/result.md", "reportText": "# remote report\n"})}]}}
        mirrored = system_mcp.mirror_remote_report(response, self.root)
        payload_value = json.loads(mirrored["content"][0]["text"])
        self.assertTrue(payload_value["storedLocally"])
        self.assertEqual(Path(payload_value["path"]).read_text(encoding="utf-8"), "# remote report\n")
        self.assertEqual(payload_value["remotePath"], "/remote/result.md")

    def test_trusted_ai_payload_declares_expanded_non_secret_mode(self) -> None:
        strict = payload(system_mcp.call("system_ai_triage_payload", {"findings": [{"title": "path"}]}))
        trusted = payload(system_mcp.call("system_ai_triage_payload", {"findings": [{"title": "path"}], "trustedAi": True}))
        self.assertEqual(strict["privacyMode"], "strict-redacted")
        self.assertEqual(trusted["privacyMode"], "trusted-ai")


if __name__ == "__main__":
    unittest.main()
