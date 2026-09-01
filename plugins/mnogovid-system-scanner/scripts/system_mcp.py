#!/usr/bin/env python3
"""Consent-gated, dependency-free Linux host security scan orchestrator.

The MCP server discovers available host-security tools, previews a fixed argv
for each adapter, and runs only allowlisted commands.  It deliberately has no
shell execution, package installation, remediation, packet-file output, or
automatic external port probing.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_OUTPUT = 256 * 1024
RUNS: dict[str, dict[str, Any]] = {}
REMOTE_DEPLOYMENTS: dict[str, dict[str, Any]] = {}
PROFILE_NAME = ".mnogovid-system-scanner.json"
REMOTE_RUNNER_DIR = "~/.local/share/mnogovid-system-scanner"
REMOTE_RUNNER_SCRIPT = REMOTE_RUNNER_DIR + "/system_mcp.py"
REMOTE_RUNNER_VERSION = REMOTE_RUNNER_DIR + "/version"
REMOTE_RUNNER_RELEASE = "2.0.2"
REMOTE_TIMEOUT = 3600

PACKAGE_MANAGER_TEMPLATES = {
    "apt-get": "sudo apt-get install <package>",
    "dnf": "sudo dnf install <package>",
    "yum": "sudo yum install <package>",
    "pacman": "sudo pacman -S <package>",
    "zypper": "sudo zypper install <package>",
    "apk": "sudo apk add <package>",
}
PACKAGE_HINTS = {
    "lynis": {"apt-get":"lynis","dnf":"lynis","pacman":"lynis"},
    "clamav": {"apt-get":"clamav","dnf":"clamav","pacman":"clamav"},
    "rkhunter": {"apt-get":"rkhunter","dnf":"rkhunter","pacman":"rkhunter"},
    "chkrootkit": {"apt-get":"chkrootkit","dnf":"chkrootkit","pacman":"chkrootkit"},
    "aide": {"apt-get":"aide","dnf":"aide","pacman":"aide"},
    "nmap-local": {"apt-get":"nmap","dnf":"nmap","pacman":"nmap"},
    "tshark-summary": {"apt-get":"tshark","dnf":"wireshark-cli","pacman":"wireshark-cli"},
    "trivy-image": {"apt-get":"trivy","dnf":"trivy","pacman":"trivy"},
    "grype-image": {"apt-get":"grype","dnf":"grype","pacman":"grype"},
    "dockle-image": {"apt-get":"dockle","dnf":"dockle","pacman":"dockle"},
    "docker-containers": {"apt-get":"docker.io","dnf":"docker","pacman":"docker"},
    "podman-containers": {"apt-get":"podman","dnf":"podman","pacman":"podman"},
    "nginx-config": {"apt-get":"nginx","dnf":"nginx","pacman":"nginx"},
    "mysql-status": {"apt-get":"mariadb-client","dnf":"mariadb","pacman":"mariadb-clients"},
    "postgres-status": {"apt-get":"postgresql-client","dnf":"postgresql","pacman":"postgresql"},
    "redis-info": {"apt-get":"redis-tools","dnf":"redis","pacman":"redis"},
    "mongodb-status": {"apt-get":"mongodb-mongosh","dnf":"mongodb-mongosh","pacman":"mongodb-mongosh"},
    "clickhouse-version": {"apt-get":"clickhouse-client","dnf":"clickhouse-client","pacman":"clickhouse-client"},
}


def _fixed(*argv: str) -> list[str]:
    return list(argv)


ADAPTERS: dict[str, dict[str, Any]] = {
    "lynis": {"category": "hardening", "exe": "lynis", "network": False, "traffic": False, "timeout": 900, "argv": lambda _: _fixed("audit", "system", "--no-colors")},
    "clamav": {"category": "malware", "exe": "clamscan", "network": False, "traffic": False, "timeout": 3600, "argv": lambda _: _fixed("--recursive", "--infected", "--no-summary", "--exclude-dir=^/proc", "--exclude-dir=^/sys", "--exclude-dir=^/dev", "/")},
    "rkhunter": {"category": "rootkit", "exe": "rkhunter", "network": False, "traffic": False, "timeout": 1800, "argv": lambda _: _fixed("--check", "--skip-keypress", "--report-warnings-only")},
    "chkrootkit": {"category": "rootkit", "exe": "chkrootkit", "network": False, "traffic": False, "timeout": 1800, "argv": lambda _: _fixed()},
    "aide": {"category": "integrity", "exe": "aide", "network": False, "traffic": False, "timeout": 1800, "argv": lambda _: _fixed("--check")},
    "debsecan": {"category": "vulnerabilities", "exe": "debsecan", "network": False, "traffic": False, "timeout": 300, "argv": lambda _: _fixed("--format", "detail")},
    "rpm-verify": {"category": "integrity", "exe": "rpm", "network": False, "traffic": False, "timeout": 900, "argv": lambda _: _fixed("-Va")},
    "osquery": {"category": "inventory", "exe": "osqueryi", "network": False, "traffic": False, "timeout": 300, "argv": lambda _: _fixed("--json", "SELECT p.pid,p.name,p.path,p.uid FROM processes p WHERE p.on_disk = 0 OR p.path = ''; ")},
    "listeners": {"category": "exposure", "exe": "ss", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("-H", "-lntup")},
    "nftables": {"category": "firewall", "exe": "nft", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("list", "ruleset")},
    "systemd-enabled": {"category": "persistence", "exe": "systemctl", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("list-unit-files", "--state=enabled", "--no-legend", "--no-pager")},
    "systemd-timers": {"category": "persistence", "exe": "systemctl", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("list-timers", "--all", "--no-legend", "--no-pager")},
    "iptables": {"category": "firewall", "exe": "iptables-save", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed()},
    "ufw": {"category": "firewall", "exe": "ufw", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("status", "verbose")},
    "audit-rules": {"category": "audit", "exe": "auditctl", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("-l")},
    "journal-warnings": {"category": "logs", "exe": "journalctl", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("--no-pager", "--since", "24 hours ago", "--priority", "warning", "--output", "short-iso", "--lines", "1000")},
    "kernel-modules": {"category": "kernel", "exe": "lsmod", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed()},
    "docker-containers": {"category": "containers", "exe": "docker", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("ps", "--all", "--no-trunc", "--format", "{{json .}}")},
    "docker-security-options": {"category": "container-hardening", "exe": "docker", "network": False, "traffic": False, "sensitiveOutput": True, "timeout": 60, "argv": lambda _: _fixed("info", "--format", "{{json .SecurityOptions}}")},
    "docker-inspect": {"category": "container-hardening", "exe": "docker", "network": False, "traffic": False, "sensitiveOutput": True, "timeout": 60, "argv": lambda args: _docker_inspect_args(args)},
    "podman-containers": {"category": "containers", "exe": "podman", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("ps", "--all", "--no-trunc", "--format", "json")},
    "debsums": {"category": "integrity", "exe": "debsums", "network": False, "traffic": False, "timeout": 1800, "argv": lambda _: _fixed("--changed")},
    "nginx-config": {"category": "web-hardening", "exe": "nginx", "network": False, "traffic": False, "timeout": 60, "argv": lambda _: _fixed("-t")},
    "mysql-status": {"category": "database-posture", "exe": "mysqladmin", "network": False, "traffic": False, "serviceProbe": True, "sensitiveOutput": True, "timeout": 15, "argv": lambda _: _fixed("--protocol=socket", "--connect-timeout=3", "status")},
    "postgres-status": {"category": "database-posture", "exe": "pg_isready", "network": False, "traffic": False, "serviceProbe": True, "sensitiveOutput": True, "timeout": 15, "argv": lambda _: _fixed("--timeout=3")},
    "redis-info": {"category": "database-posture", "exe": "redis-cli", "network": False, "traffic": False, "serviceProbe": True, "sensitiveOutput": True, "timeout": 15, "argv": lambda _: _fixed("--no-auth-warning", "INFO", "server")},
    "mongodb-status": {"category": "database-posture", "exe": "mongosh", "network": False, "traffic": False, "serviceProbe": True, "sensitiveOutput": True, "timeout": 15, "argv": lambda _: _fixed("--quiet", "--eval", "JSON.stringify(db.serverStatus({uptime:1,connections:1,security:1,transportSecurity:1}))")},
    "clickhouse-version": {"category": "database-posture", "exe": "clickhouse-client", "network": False, "traffic": False, "serviceProbe": True, "sensitiveOutput": True, "timeout": 15, "argv": lambda _: _fixed("--query", "SELECT version()")},
    "trivy-image": {"category": "container-vulnerabilities", "exe": "trivy", "network": True, "traffic": False, "sensitiveOutput": True, "timeout": 1800, "argv": lambda args: _image_args("image", ["--format", "json", "--scanners", "vuln"], args)},
    "grype-image": {"category": "container-vulnerabilities", "exe": "grype", "network": True, "traffic": False, "sensitiveOutput": True, "timeout": 1800, "argv": lambda args: _image_args("", ["-o", "json"], args)},
    "dockle-image": {"category": "container-hardening", "exe": "dockle", "network": False, "traffic": False, "sensitiveOutput": True, "timeout": 900, "argv": lambda args: _image_args("", ["--exit-code", "0"], args)},
    "nmap-local": {"category": "exposure", "exe": "nmap", "network": True, "traffic": False, "timeout": 900, "active": True, "argv": lambda args: _nmap_args(args)},
    "tshark-summary": {"category": "traffic", "exe": "tshark", "network": False, "traffic": True, "timeout": 360, "argv": lambda args: _tshark_args(args)},
}


def _nmap_args(args: dict[str, Any]) -> list[str]:
    target = args.get("target")
    if not isinstance(target, str):
        raise ValueError("nmap-local requires target as an IP address")
    try:
        ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("nmap-local target must be one literal IP address") from exc
    if args.get("authorizedTarget") is not True:
        raise ValueError("nmap-local requires authorizedTarget=true for the named IP")
    return ["-sV", "--version-light", "--top-ports", "100", "--reason", target]


def _tshark_args(args: dict[str, Any]) -> list[str]:
    interface = args.get("interface")
    duration = args.get("durationSeconds", 30)
    capture_filter = args.get("captureFilter")
    if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        raise ValueError("tshark-summary requires a valid interface name")
    if not isinstance(duration, int) or not 5 <= duration <= 300:
        raise ValueError("durationSeconds must be an integer from 5 through 300")
    argv = ["-n", "-i", interface, "-a", f"duration:{duration}", "-c", "10000", "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol", "-e", "frame.len", "-E", "separator=,", "-E", "quote=d"]
    if capture_filter is not None:
        if not isinstance(capture_filter, str) or not 1 <= len(capture_filter) <= 256:
            raise ValueError("captureFilter must be a non-empty string at most 256 characters")
        argv.extend(["-f", capture_filter])
    return argv


def _docker_inspect_args(args: dict[str, Any]) -> list[str]:
    container_id = args.get("containerId")
    if not isinstance(container_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container_id):
        raise ValueError("docker-inspect requires one Docker container ID or name")
    return ["inspect", "--type", "container", container_id]


def _image_args(subcommand: str, prefix: list[str], args: dict[str, Any]) -> list[str]:
    image = args.get("imageRef")
    if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}", image):
        raise ValueError("image scanner requires one Docker image reference")
    return ([subcommand] if subcommand else []) + prefix + [image]


TOOLS = [
    {"name": "system_catalog", "description": "List allowlisted Linux host security, exposure, and traffic-observation adapters.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"name": "system_doctor", "description": "Read local OS identity and check allowlisted executable availability. It does not execute a scanner.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}}, "required": ["reportDirectory"], "additionalProperties": False}},
    {"name": "system_bootstrap", "description": "Check the system-scanner profile and local toolchain before a scan. Set createProfile=true only after explicit user approval to create a missing profile; it does not run a scanner.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}, "createProfile": {"type": "boolean"}}, "required": ["reportDirectory"], "additionalProperties": False}},
    {"name": "system_remote_prepare", "description": "Read-only probe of one configured SSH alias: find Python and report whether the fixed Mnogovid remote runner is ready. It never deploys or scans.", "inputSchema": {"type": "object", "properties": {"sshAlias": {"type": "string"}}, "required": ["sshAlias"], "additionalProperties": False}},
    {"name": "system_remote_authorize_deploy", "description": "Create a short-lived, one-time deployment ticket after the user explicitly approves deploying or updating the runner on the named SSH host. It does not write remotely.", "inputSchema": {"type": "object", "properties": {"sshAlias": {"type": "string"}, "approveDeployment": {"type": "boolean"}}, "required": ["sshAlias", "approveDeployment"], "additionalProperties": False}},
    {"name": "system_remote_deploy_runner", "description": "Deploy or update the fixed remote runner under the remote user's ~/.local/share only with a valid one-time deployment ticket. It does not scan the host.", "inputSchema": {"type": "object", "properties": {"sshAlias": {"type": "string"}, "deploymentId": {"type": "string"}}, "required": ["sshAlias", "deploymentId"], "additionalProperties": False}},
    {"name": "system_remote_call", "description": "Forward one allowlisted system MCP operation through a prepared SSH alias. Remote scanner and consent enforcement remains inside the remote MCP server.", "inputSchema": {"type": "object", "properties": {"sshAlias": {"type": "string"}, "operation": {"enum": ["system_bootstrap", "system_doctor", "system_plan", "system_virtual_run", "system_run", "system_ingest", "system_start_run", "system_record_run", "system_finalize_run", "system_ai_triage_payload", "system_advisory_lookup"]}, "arguments": {"type": "object"}}, "required": ["sshAlias", "operation", "arguments"], "additionalProperties": False}},
    {"name": "system_plan", "description": "Create a non-executing plan for all available Linux host scanners and observation tools.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}}, "required": ["reportDirectory"], "additionalProperties": False}},
    {"name": "system_virtual_run", "description": "Preview one exact allowlisted command without starting it. nmap requires an explicitly authorized IP; image scanners need one image reference; docker-inspect needs one container ID or name.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}, "adapter": {"type": "string"}, "target": {"type": "string"}, "authorizedTarget": {"type": "boolean"}, "containerId": {"type": "string"}, "imageRef": {"type": "string"}, "interface": {"type": "string"}, "durationSeconds": {"type": "integer"}, "captureFilter": {"type": "string"}}, "required": ["reportDirectory", "adapter"], "additionalProperties": False}},
    {"name": "system_run", "description": "Execute one allowlisted local command without a shell. It requires a started lifecycle and identical preview; networked image scanners, active ports, traffic capture, and local service probes require matching lifecycle consent.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}, "runId": {"type": "string"}, "adapter": {"type": "string"}, "target": {"type": "string"}, "authorizedTarget": {"type": "boolean"}, "containerId": {"type": "string"}, "imageRef": {"type": "string"}, "interface": {"type": "string"}, "durationSeconds": {"type": "integer"}, "captureFilter": {"type": "string"}}, "required": ["reportDirectory", "runId", "adapter"], "additionalProperties": False}},
    {"name": "system_ingest", "description": "Normalize an existing private local JSON or SARIF host-security report inside the selected report directory without executing a program.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}, "report": {"type": "string"}, "format": {"enum": ["json", "sarif"]}, "adapter": {"type": "string"}}, "required": ["reportDirectory", "report", "format"], "additionalProperties": False}},
    {"name": "system_start_run", "description": "Start a durable, consent-owned system assessment lifecycle. No scanner is executed and no report is written.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}, "mode": {"enum": ["scan", "scan-ai", "scan-agent"]}, "consent": {"type": "object", "properties": {"profileWrite": {"type": "boolean"}, "network": {"type": "boolean"}, "activeNetwork": {"type": "boolean"}, "trafficCapture": {"type": "boolean"}, "serviceProbe": {"type": "boolean"}, "aiTriage": {"type": "boolean"}, "agentReview": {"type": "boolean"}}, "additionalProperties": False}}, "required": ["reportDirectory", "mode", "consent"], "additionalProperties": False}},
    {"name": "system_record_run", "description": "Append a preview, scanner result, skipped reason, host-AI triage, or independent review to a started system assessment.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}, "runId": {"type": "string"}, "kind": {"enum": ["scanner", "preview", "skipped", "host_ai_triage", "agent_review"]}, "entry": {"type": "object"}}, "required": ["reportDirectory", "runId", "kind", "entry"], "additionalProperties": False}},
    {"name": "system_finalize_run", "description": "Write the redacted Markdown report for a completed lifecycle under <reportDirectory>/.mnogovid/system-scanner/.", "inputSchema": {"type": "object", "properties": {"reportDirectory": {"type": "string"}, "runId": {"type": "string"}, "initialization": {"type": "object"}, "doctor": {"type": "object"}, "plan": {"type": "object"}, "hostAiTriage": {"type": "object"}, "agentReview": {"type": "object"}}, "required": ["reportDirectory", "runId"], "additionalProperties": False}},
    {"name": "system_ai_triage_payload", "description": "Produce a bounded redacted finding payload for host-model triage. It never contacts a model.", "inputSchema": {"type": "object", "properties": {"findings": {"type": "array"}}, "required": ["findings"], "additionalProperties": False}},
    {"name": "system_advisory_lookup", "description": "Query OSV for one installed package version only after explicit network approval. It never installs or changes packages.", "inputSchema": {"type": "object", "properties": {"ecosystem": {"type": "string"}, "package": {"type": "string"}, "version": {"type": "string"}, "allowNetwork": {"type": "boolean"}}, "required": ["ecosystem", "package", "version", "allowNetwork"], "additionalProperties": False}},
]


def report_directory(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("reportDirectory must be a non-empty directory path")
    raw = Path(value).expanduser()
    if raw.is_symlink():
        raise ValueError("reportDirectory must not be a symlink")
    path = raw.resolve()
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"reportDirectory is not a directory: {path}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("reportDirectory must be owned by this user and not group/world writable")
    return path


def ensure_private_directory(path: Path) -> None:
    """Create or validate a user-owned, non-symlinked report component."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"refusing non-directory or symlink report component: {path.name}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError(f"report component must be private and owned by this user: {path.name}")
    os.chmod(path, 0o700)


def run_directory(root: Path, run_id: str, create: bool) -> Path:
    reports = root / ".mnogovid"
    scanner_reports = reports / "system-scanner"
    if create:
        ensure_private_directory(reports)
        ensure_private_directory(scanner_reports)
        ensure_private_directory(scanner_reports / run_id)
    else:
        for item in (reports, scanner_reports, scanner_reports / run_id):
            if not item.exists():
                raise ValueError("unknown or expired runId")
            ensure_private_directory(item)
    return scanner_reports / run_id


def atomic_write(path: Path, document: str, replace: bool) -> None:
    if path.exists() or path.is_symlink():
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError(f"refusing non-regular or symlink output: {path.name}")
        if not replace:
            raise ValueError(f"refusing to overwrite existing output: {path.name}")
    temp = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(document)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def read_regular_file(path: Path, limit: int | None = None) -> str:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("refusing to read non-regular or symlink state file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        content = handle.read(limit + 1) if limit is not None else handle.read()
    if limit is not None and len(content.encode("utf-8")) > limit:
        raise ValueError("input exceeds the bounded report size limit")
    return content


def private_input_report(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("report must be a non-empty path inside reportDirectory")
    candidate = Path(value).expanduser()
    path = candidate if candidate.is_absolute() else root / candidate
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("report must be inside reportDirectory") from exc
    if not relative.parts or any(part in (".", "..") for part in relative.parts):
        raise ValueError("report must be a descendant file inside reportDirectory")
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("report path must not contain a symlink")
        final = index == len(relative.parts) - 1
        if final and not stat.S_ISREG(info.st_mode):
            raise ValueError("report must be a regular file")
        if not final and not stat.S_ISDIR(info.st_mode):
            raise ValueError("report path contains a non-directory component")
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("report and its path components must be private and owned by this user")
    return current


def read_os_release() -> dict[str, str]:
    data: dict[str, str] = {"kernel": platform.release(), "machine": platform.machine(), "system": platform.system()}
    path = Path("/etc/os-release")
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                data[key.lower()] = value.strip().strip('"')
    return data


def discover_host() -> dict[str, Any]:
    os_release = read_os_release()
    package_managers = [name for name in ("apt-get", "dnf", "yum", "pacman", "zypper", "apk", "rpm", "dpkg") if shutil.which(name)]
    runtimes = [name for name in ("docker", "podman", "containerd", "kubectl") if shutil.which(name)]
    surfaces = []
    if Path("/run/systemd/system").exists(): surfaces.append("systemd")
    cgroup_path = Path("/proc/1/cgroup")
    cgroup = cgroup_path.read_text(encoding="utf-8", errors="replace").lower() if cgroup_path.is_file() else ""
    if Path("/.dockerenv").exists() or "docker" in cgroup or "kubepods" in cgroup: surfaces.append("container")
    if runtimes: surfaces.append("container-runtime")
    if shutil.which("nft") or shutil.which("iptables-save") or shutil.which("ufw"): surfaces.append("firewall")
    if Path("/var/log/journal").exists(): surfaces.append("persistent-journal")
    return {"os": os_release, "packageManagers": package_managers, "containerRuntimes": runtimes, "surfaces": sorted(set(surfaces)), "kernel": {"release": platform.release(), "machine": platform.machine()}}


def recommend_host(found: dict[str, Any]) -> list[str]:
    adapters = ["lynis", "clamav", "rkhunter", "chkrootkit", "aide", "debsums", "debsecan", "rpm-verify", "osquery", "listeners", "nftables", "iptables", "ufw", "audit-rules", "journal-warnings", "kernel-modules", "systemd-enabled", "systemd-timers", "nginx-config", "mysql-status", "postgres-status", "redis-info", "mongodb-status", "clickhouse-version"]
    managers = set(found.get("packageManagers", []))
    if "rpm" not in managers: adapters.remove("rpm-verify")
    if "apt-get" not in managers and "dpkg" not in managers: adapters.remove("debsecan")
    if "docker" in found.get("containerRuntimes", []): adapters += ["docker-containers", "docker-security-options", "docker-inspect", "trivy-image", "grype-image", "dockle-image"]
    if "podman" in found.get("containerRuntimes", []): adapters.append("podman-containers")
    adapters += ["nmap-local", "tshark-summary"]
    return adapters


def installation_guide(found: dict[str, Any], runs: list[dict[str, Any]]) -> dict[str, Any]:
    managers = [name for name in found.get("packageManagers", []) if name in PACKAGE_MANAGER_TEMPLATES]
    missing = []
    for run in runs:
        if run["available"]: continue
        packages = {manager: PACKAGE_HINTS.get(run["adapter"], {}).get(manager) for manager in managers}
        missing.append({"adapter":run["adapter"],"executable":run["executable"],"candidatePackages":{key:value for key,value in packages.items() if value}})
    return {"packageManagers":[{"name":name,"commandTemplate":PACKAGE_MANAGER_TEMPLATES[name]} for name in managers],"missingAdapters":missing,"note":"Candidate package names vary by distribution release; verify the package name before installing. The scanner never installs utilities itself."}


def plan(_: Path) -> dict[str, Any]:
    found = discover_host()
    runs = []
    for ident in recommend_host(found):
        spec = ADAPTERS[ident]
        available = shutil.which(spec["exe"]) is not None
        runs.append({"adapter": ident, "category": spec["category"], "executable": spec["exe"], "available": available, "requiresActiveNetwork": spec.get("network", False), "requiresTrafficCapture": spec.get("traffic", False), "execution": "not_executed"})
    return {"host": found, "recommendedAdapters": recommend_host(found), "runs": runs, "installationGuide":installation_guide(found,runs), "processStarted": False, "networkUsed": False, "trafficCaptured": False}


def bootstrap(root: Path, create_profile: bool) -> dict[str, Any]:
    if not isinstance(create_profile, bool):
        raise ValueError("createProfile must be boolean when supplied")
    profile_path = root / PROFILE_NAME
    profile: dict[str, Any]
    if profile_path.exists() or profile_path.is_symlink():
        info = os.lstat(profile_path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("refusing non-regular or symlinked system-scanner profile")
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("system-scanner profile must be private and owned by this user")
        try:
            saved = json.loads(read_regular_file(profile_path, MAX_OUTPUT))
        except json.JSONDecodeError:
            saved = None
        valid = isinstance(saved, dict) and saved.get("schemaVersion") == 1 and saved.get("generatedBy") in {"mnogovid-system-scanner bootstrap", "mnogovid-system-scanner init"}
        profile = {"path": str(profile_path), "action": "verified" if valid else "invalid", "valid": valid}
    elif create_profile:
        discovered = plan(root)
        saved = {"schemaVersion": 1, "generatedBy": "mnogovid-system-scanner bootstrap", "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "recommendedAdapters": discovered["recommendedAdapters"], "availableAdapters": [item["adapter"] for item in discovered["runs"] if item["available"]], "notes": ["This profile records discovery only and grants no scanner permission.", "Every scanner still requires an explicit lifecycle preview and approval."]}
        atomic_write(profile_path, json.dumps(saved, ensure_ascii=False, indent=2) + "\n", replace=False)
        profile = {"path": str(profile_path), "action": "created", "valid": True}
    else:
        profile = {"path": str(profile_path), "action": "missing", "valid": False}
    discovered = plan(root)
    return {"profile": profile, "doctor": {**discovered, "missingExecutables": [item["executable"] for item in discovered["runs"] if not item["available"]]}, "processStarted": False}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): redact("[REDACTED]" if re.search(r"(token|secret|password|api.?key|private.?key)", str(k), re.I) else v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and re.search(r"(ghp_|sk-|AKIA|-----BEGIN|(?:token|secret|password|api[_-]?key|authorization|bearer|cookie|session)\s*[=:])", value, re.I):
        return "[REDACTED]"
    return value


def bounded_text(value: Any, limit: int = 500) -> str:
    return str(redact(value)).replace("\r", " ").replace("\n", " ")[:limit]


def safe_text(value: Any, limit: int = 500) -> str:
    text = bounded_text(value, limit)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|").replace("[", "\\[").replace("]", "\\]").replace("(", "\\(").replace(")", "\\)")


def safe_json(value: Any) -> str:
    return json.dumps(redact(value), ensure_ascii=True, indent=2).replace("`", "\\u0060").replace("<", "\\u003c").replace(">", "\\u003e")


def normalize_consent(value: Any) -> dict[str, bool]:
    keys = {"profileWrite", "network", "activeNetwork", "trafficCapture", "serviceProbe", "aiTriage", "agentReview"}
    if not isinstance(value, dict) or set(value) - keys:
        raise ValueError("consent may contain only known boolean permission fields")
    if any(not isinstance(item, bool) for item in value.values()):
        raise ValueError("every consent value must be boolean")
    return {key: value.get(key, False) for key in keys}


def normalize_entry(kind: str, entry: dict[str, Any], finding_count: int) -> dict[str, Any]:
    if kind == "skipped":
        if not isinstance(entry.get("adapter"), str) or not isinstance(entry.get("reason"), str):
            raise ValueError("skipped entry requires adapter and reason strings")
        return {"adapter": bounded_text(entry["adapter"], 80), "reason": bounded_text(entry["reason"])}
    if kind in ("preview", "scanner"):
        adapter = entry.get("adapter")
        if adapter not in ADAPTERS:
            raise ValueError(f"{kind} entry must name an allowlisted adapter")
        command_value = entry.get("command") if isinstance(entry.get("command"), dict) else {}
        argv = command_value.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and len(item) <= 512 for item in argv):
            raise ValueError(f"{kind} entry requires a bounded command argv")
        result: dict[str, Any] = {"adapter": adapter, "category": ADAPTERS[adapter]["category"], "command": {"argv": [bounded_text(item, 512) for item in argv], "currentDir": bounded_text(command_value.get("currentDir", ""), 512)}}
        if kind == "preview":
            result.update({"requiresNetwork": bool(entry.get("requiresNetwork")), "requiresActiveNetwork": bool(entry.get("requiresActiveNetwork")), "requiresTrafficCapture": bool(entry.get("requiresTrafficCapture")), "requiresServiceProbe": bool(entry.get("requiresServiceProbe")), "resultStatus": "not_executed"})
            return result
        if entry.get("resultStatus") not in ("complete", "failed", "incomplete") or not isinstance(entry.get("exitCode"), int):
            raise ValueError("scanner entry requires resultStatus and integer exitCode")
        findings = entry.get("findings", [])
        observations = entry.get("observations", [])
        if not isinstance(findings, list) or not isinstance(observations, list):
            raise ValueError("scanner findings and observations must be arrays")
        normalized_findings = []
        for item in findings[:200]:
            if not isinstance(item, dict): continue
            normalized_findings.append({"adapter": adapter, "ruleId": bounded_text(item.get("ruleId", item.get("id", "")), 160), "severity": bounded_text(item.get("severity", "review"), 40), "title": bounded_text(item.get("title", "")), "location": bounded_text(item.get("location", item.get("path", "")), 512), "line": item.get("line") if isinstance(item.get("line"), int) else None, "library": bounded_text(item.get("library", item.get("package", "")), 160), "installedVersion": bounded_text(item.get("installedVersion", item.get("version", "")), 160), "fixedVersion": bounded_text(item.get("fixedVersion", ""), 160)})
        result.update({"resultStatus": entry["resultStatus"], "exitCode": entry["exitCode"], "requiresNetwork": bool(entry.get("requiresNetwork")), "requiresActiveNetwork": bool(entry.get("requiresActiveNetwork")), "requiresTrafficCapture": bool(entry.get("requiresTrafficCapture")), "requiresServiceProbe": bool(entry.get("requiresServiceProbe")), "findings": normalized_findings, "observations": [bounded_text(item) for item in observations[:200] if isinstance(item, str)]})
        result["counts"] = {"findings": len(result["findings"]), "observations": len(result["observations"])}
        return result
    notes = entry.get("findingNotes")
    if not isinstance(notes, list) or len(notes) != finding_count:
        raise ValueError("triage entry requires exactly one findingNotes item for every recorded finding")
    normalized = []
    for expected, note in enumerate(notes):
        if not isinstance(note, dict) or note.get("findingIndex") != expected or note.get("classification") not in ("true_positive", "false_positive", "needs_review"):
            raise ValueError("triage notes must use ordered findingIndex and a known classification")
        confidence = note.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1 or not isinstance(note.get("note"), str):
            raise ValueError("triage notes require confidence from 0 through 1 and a text note")
        normalized.append({"findingIndex": expected, "classification": note["classification"], "confidence": confidence, "note": bounded_text(note["note"], 2000)})
    return {"findingNotes": normalized}


def command(ident: str, args: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    if ident not in ADAPTERS:
        raise ValueError(f"unknown adapter: {ident}")
    spec = ADAPTERS[ident]
    exe = shutil.which(spec["exe"]) or spec["exe"]
    return spec, [exe, *spec["argv"](args)]


def normalize_output(adapter: str, output: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Keep inventory separate from a security finding.

    A listening socket or enabled unit is evidence to review, not proof of a
    compromise.  Only adapter-specific warning signatures become findings.
    """
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    patterns: dict[str, re.Pattern[str]] = {
        "lynis": re.compile(r"\b(WARNING|SUGGESTION)\b", re.I),
        "clamav": re.compile(r"\bFOUND$", re.I),
        "rkhunter": re.compile(r"\b(Warning|Rootkit|Suspicious)\b", re.I),
        "chkrootkit": re.compile(r"\b(INFECTED|Vulnerable|Warning)\b", re.I),
        "aide": re.compile(r"^(?:added|removed|changed)\b|\b(?:Added|Removed|Changed)\b"),
        "debsecan": re.compile(r"\b(?:CVE|DSA|USN)-", re.I),
        "rpm-verify": re.compile(r"^[.A-Z?]{8,9}\s"),
        "osquery": re.compile(r".+"),
        "nmap-local": re.compile(r"\bopen\b", re.I),
        "debsums": re.compile(r"^\S+\s+\S+"),
        "journal-warnings": re.compile(r".+"),
    }
    matcher = patterns.get(adapter)
    matched = [line for line in lines if matcher and matcher.search(line)]
    findings = [{"adapter": adapter, "severity": "review", "title": line[:500]} for line in matched[:200]]
    observations = [line[:500] for line in lines[:200] if line not in matched]
    return findings, observations


def normalize_docker_inspect(output: str) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        raw = json.loads(output)
    except json.JSONDecodeError:
        return [], ["Docker inspect did not return JSON; review the redacted command diagnostic."]
    containers = raw if isinstance(raw, list) else [raw]
    findings: list[dict[str, Any]] = []
    observations: list[str] = []
    for container in containers[:1]:
        if not isinstance(container, dict): continue
        host = container.get("HostConfig") if isinstance(container.get("HostConfig"), dict) else {}
        config = container.get("Config") if isinstance(container.get("Config"), dict) else {}
        if host.get("Privileged") is True: findings.append({"adapter": "docker-inspect", "severity": "high", "title": "Container is privileged"})
        if host.get("NetworkMode") == "host": findings.append({"adapter": "docker-inspect", "severity": "high", "title": "Container uses host networking"})
        if host.get("PidMode") == "host" or host.get("IpcMode") == "host": findings.append({"adapter": "docker-inspect", "severity": "high", "title": "Container shares a host namespace"})
        caps = host.get("CapAdd")
        if isinstance(caps, list) and caps: findings.append({"adapter": "docker-inspect", "severity": "review", "title": "Container adds Linux capabilities beyond Docker defaults"})
        options = host.get("SecurityOpt")
        if isinstance(options, list) and any("unconfined" in str(option).lower() for option in options): findings.append({"adapter": "docker-inspect", "severity": "high", "title": "Container disables a confinement profile"})
        mounts = container.get("Mounts") if isinstance(container.get("Mounts"), list) else []
        if any(isinstance(mount, dict) and str(mount.get("Source")) == "/" for mount in mounts): findings.append({"adapter": "docker-inspect", "severity": "high", "title": "Container mounts the host root filesystem"})
        if any(isinstance(mount, dict) and str(mount.get("Destination")) == "/var/run/docker.sock" for mount in mounts): findings.append({"adapter": "docker-inspect", "severity": "high", "title": "Container receives the Docker socket"})
        user = config.get("User")
        if user in (None, "", "0", "root"): observations.append("Container process is configured to run as root or leaves the user unspecified")
    return findings[:200], observations[:200]


def normalize_docker_security_options(output: str) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        options = json.loads(output)
    except json.JSONDecodeError:
        return [], ["Docker security-option query did not return JSON; raw output was withheld."]
    if not isinstance(options, list):
        return [], ["Docker daemon returned a security-option response"]
    return [], [f"Docker daemon reports {len(options)} configured security options"]


def normalize_service_probe(adapter: str, output: str) -> tuple[list[dict[str, Any]], list[str]]:
    text = output.lower()
    if adapter == "postgres-status" and ("rejecting" in text or "no response" in text):
        return [{"adapter": adapter, "severity": "review", "title": "PostgreSQL is not accepting the local readiness probe"}], []
    if adapter == "nginx-config" and "test is successful" in text:
        return [], ["Nginx configuration syntax check completed successfully"]
    if adapter == "clickhouse-version" and output.strip():
        return [], ["ClickHouse local client returned a server version"]
    if adapter in {"mysql-status", "redis-info", "mongodb-status", "postgres-status"} and output.strip():
        return [], [f"{adapter} returned a local read-only status response"]
    return [], []


def normalize_image_scan(adapter: str, output: str) -> tuple[list[dict[str, Any]], list[str]]:
    if adapter == "dockle-image":
        findings = []
        for line in output.splitlines():
            match = re.match(r"^(FATAL|WARN)\s*-\s*([A-Z0-9-]+):\s*(.+)$", line.strip())
            if match:
                findings.append({"adapter": adapter, "ruleId": match.group(2), "severity": "high" if match.group(1) == "FATAL" else "review", "title": match.group(3)[:300]})
        return findings[:200], []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return [], ["Image scanner did not return parseable JSON; raw output was withheld."]
    findings: list[dict[str, Any]] = []
    if adapter == "trivy-image":
        results = data.get("Results", []) if isinstance(data, dict) else []
        for result in results if isinstance(results, list) else []:
            target = result.get("Target") if isinstance(result, dict) else None
            vulnerabilities = result.get("Vulnerabilities", []) if isinstance(result, dict) else []
            for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
                if isinstance(vulnerability, dict):
                    findings.append({"adapter": adapter, "ruleId": vulnerability.get("VulnerabilityID"), "severity": vulnerability.get("Severity") or "review", "title": vulnerability.get("Title") or vulnerability.get("PkgName") or vulnerability.get("VulnerabilityID"), "library": vulnerability.get("PkgName"), "installedVersion": vulnerability.get("InstalledVersion"), "fixedVersion": vulnerability.get("FixedVersion"), "location": target})
    elif adapter == "grype-image":
        matches = data.get("matches", []) if isinstance(data, dict) else []
        for match in matches if isinstance(matches, list) else []:
            if not isinstance(match, dict): continue
            vulnerability = match.get("vulnerability") if isinstance(match.get("vulnerability"), dict) else {}
            artifact = match.get("artifact") if isinstance(match.get("artifact"), dict) else {}
            fix = vulnerability.get("fix") if isinstance(vulnerability.get("fix"), dict) else {}
            findings.append({"adapter": adapter, "ruleId": vulnerability.get("id"), "severity": vulnerability.get("severity") or "review", "title": vulnerability.get("description") or vulnerability.get("id"), "library": artifact.get("name"), "installedVersion": artifact.get("version"), "fixedVersion": ", ".join(fix.get("versions", [])) if isinstance(fix.get("versions"), list) else None})
    return findings[:200], []


def parse_ingested_report(value: Any, adapter: str | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(value, dict) and isinstance(value.get("runs"), list):
        for run in value["runs"]:
            for result in run.get("results", []) if isinstance(run, dict) else []:
                if not isinstance(result, dict): continue
                location = ((result.get("locations") or [{}])[0].get("physicalLocation") or {}) if isinstance(result.get("locations"), list) else {}
                region = location.get("region") if isinstance(location, dict) else {}
                artifact = location.get("artifactLocation") if isinstance(location, dict) else {}
                findings.append({"adapter": adapter or "sarif", "ruleId": result.get("ruleId"), "severity": str(result.get("level") or "review").upper(), "title": result.get("message", {}).get("text", "") if isinstance(result.get("message"), dict) else "", "location": artifact.get("uri") if isinstance(artifact, dict) else None, "line": region.get("startLine") if isinstance(region, dict) else None})
    elif isinstance(value, dict) and isinstance(value.get("findings"), list):
        findings = [item for item in value["findings"] if isinstance(item, dict)][:200]
    elif isinstance(value, dict) and isinstance(value.get("matches"), list):
        for match in value["matches"][:200]:
            if not isinstance(match, dict): continue
            vulnerability = match.get("vulnerability") if isinstance(match.get("vulnerability"), dict) else {}
            artifact = match.get("artifact") if isinstance(match.get("artifact"), dict) else {}
            findings.append({"adapter": adapter or "report", "ruleId": vulnerability.get("id"), "severity": vulnerability.get("severity") or "review", "title": vulnerability.get("description") or vulnerability.get("id"), "library": artifact.get("name"), "installedVersion": artifact.get("version")})
    elif isinstance(value, list):
        findings = [item for item in value if isinstance(item, dict)][:200]
    return [{"adapter": bounded_text(item.get("adapter", adapter or "report"), 80), "ruleId": bounded_text(item.get("ruleId", item.get("id", "")), 160), "severity": bounded_text(item.get("severity", "review"), 40), "title": bounded_text(item.get("title", item.get("message", "Imported finding"))), "location": bounded_text(item.get("location", item.get("path", "")), 512), "line": item.get("line"), "library": bounded_text(item.get("library", item.get("package", "")), 160), "installedVersion": bounded_text(item.get("installedVersion", item.get("version", "")), 160), "fixedVersion": bounded_text(item.get("fixedVersion", ""), 160)} for item in findings]


def finding_value(finding: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = finding.get(name)
        if value not in (None, ""): return value
    return None


def finding_location_or_library(finding: dict[str, Any]) -> str:
    location = finding_value(finding, ("location", "path", "file", "uri"))
    line = finding_value(finding, ("line", "lineNumber", "startLine"))
    library = finding_value(finding, ("library", "package", "component"))
    parts = [f"{location}:{line}" if location and line else str(location) for _ in [0] if location]
    if library and str(library) != str(location): parts.append(str(library))
    return "; ".join(parts) if parts else "—"


def finding_title(finding: dict[str, Any]) -> str:
    identifier = finding_value(finding, ("ruleId", "id", "cve", "advisory"))
    title = finding_value(finding, ("title", "message"))
    return f"{identifier}: {title}" if identifier and title else str(title or identifier or "System scanner finding")


def scanner_recovery(run: dict[str, Any]) -> str:
    adapter = str(run.get("adapter") or "scanner")
    steps = {"clamav": "Update trusted ClamAV signatures outside this workflow, then preview and rerun the scan.", "aide": "Verify that AIDE has a trusted baseline; do not initialize one on a possibly compromised host.", "lynis": "Rerun the previewed Lynis audit with required read permissions and inspect its redacted diagnostic.", "nmap-local": "Confirm target ownership and lifecycle consent, then rerun only the previously previewed literal-IP probe.", "tshark-summary": "Confirm the interface and bounded duration, then rerun without saving packet content.", "debsecan": "Refresh the local distribution advisory data through normal system administration, then rerun and validate backport status."}
    diagnostic = bounded_text(run.get("stderrSnippet", ""), 500)
    return steps.get(adapter, "Rerun the identical previewed command after resolving the recorded diagnostic.") + (f" Diagnostic: {diagnostic}" if diagnostic else "")


def run_one(root: Path, args: dict[str, Any], virtual: bool) -> dict[str, Any]:
    ident = args.get("adapter")
    if not isinstance(ident, str):
        raise ValueError("adapter must be a string")
    spec, argv = command(ident, args)
    base = {"adapter": ident, "category": spec["category"], "host": read_os_release(), "requiresNetwork": spec.get("network", False), "requiresActiveNetwork": spec.get("active", False), "requiresTrafficCapture": spec.get("traffic", False), "requiresServiceProbe": spec.get("serviceProbe", False), "command": {"argv": argv, "currentDir": str(root)}}
    if virtual:
        return {**base, "execution": "virtual", "processStarted": False, "resultStatus": "not_executed", "findings": []}
    if shutil.which(spec["exe"]) is None:
        raise ValueError(f"scanner executable not found on PATH: {spec['exe']}")
    completed = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=spec["timeout"], check=False)
    output = (completed.stdout or "")[:MAX_OUTPUT]
    error = (completed.stderr or "")[:MAX_OUTPUT]
    if ident == "docker-inspect":
        findings, observations = normalize_docker_inspect(output)
    elif ident == "docker-security-options":
        findings, observations = normalize_docker_security_options(output)
    elif ident in {"trivy-image", "grype-image", "dockle-image"}:
        findings, observations = normalize_image_scan(ident, output)
    elif spec.get("serviceProbe") or ident == "nginx-config":
        findings, observations = normalize_service_probe(ident, output)
    else:
        findings, observations = normalize_output(ident, output)
    status = "complete" if completed.returncode == 0 or completed.returncode == 1 and findings else "incomplete" if completed.returncode == 1 else "failed"
    snippets = {"stdoutSnippet": output[:4000], "stderrSnippet": error[:4000]} if not spec.get("sensitiveOutput") else {"stdoutSnippet": "[WITHHELD: normalized security fields only]", "stderrSnippet": "[WITHHELD: normalized security fields only]"}
    return redact({**base, "execution": "executed", "processStarted": True, "resultStatus": status, "exitCode": completed.returncode, "findings": findings, "observations": observations, "counts": {"findings": len(findings), "observations": len(observations)}, **snippets})


def state_path(root: Path, run_id: Any) -> Path:
    if not isinstance(run_id, str) or not run_id.isdigit():
        raise ValueError("runId must be a Unix timestamp")
    return root / ".mnogovid" / "system-scanner" / run_id / "run-state.json"


def save_run(root: Path, run_id: str, run: dict[str, Any]) -> None:
    directory = run_directory(root, run_id, create=True)
    atomic_write(directory / "run-state.json", safe_json(run) + "\n", replace=True)


def started_run(root: Path, run_id: Any) -> dict[str, Any]:
    if isinstance(run_id, str) and run_id in RUNS:
        return RUNS[run_id]
    path = run_directory(root, str(run_id), create=False) / "run-state.json"
    run = json.loads(read_regular_file(path))
    if run.get("reportDirectory") != str(root):
        raise ValueError("runId belongs to a different report directory")
    RUNS[str(run_id)] = run
    return run


def render_report(root: Path, run: dict[str, Any], report_id: str) -> str:
    scanners = run["scannerResults"]
    findings = [finding for scanner in scanners for finding in scanner.get("findings", []) if isinstance(finding, dict)]
    notes = {item["findingIndex"]: item for item in (run.get("hostAiTriage") or {}).get("findingNotes", []) if isinstance(item, dict) and isinstance(item.get("findingIndex"), int)}
    completed = [item for item in scanners if item.get("resultStatus") == "complete"]
    incomplete = [item for item in scanners if item.get("resultStatus") == "incomplete"]
    failed = [item for item in scanners if item.get("resultStatus") == "failed"]
    classifications = [str(item.get("classification", "")).lower() for item in notes.values()]
    if any(item == "true_positive" for item in classifications):
        verdict, explanation = "ACTION REQUIRED", "At least one host finding was assessed as likely real; review it before remediation."
    elif findings or incomplete or failed or run["skippedScanners"]:
        verdict, explanation = "REVIEW REQUIRED", "Findings or incomplete coverage require human verification; this is not proof of compromise or cleanliness."
    else:
        verdict, explanation = "NO FINDINGS REPORTED", "Completed checks reported no normalized findings. Unobserved traffic and kernel-level stealth remain coverage limits."
    lines = ["# Mnogovid System Scanner report", "", "## Verdict", "", f"**{verdict}.** {explanation}", "", "| Report directory | Mode | Findings | Completed scanners | Incomplete / failed |", "| --- | --- | --- | --- | --- |", f"| {safe_text(root, 512)} | {safe_text(run['mode'], 40)} | {len(findings)} | {len(completed)} | {len(incomplete) + len(failed)} |", "", "## What needs attention", ""]
    if not findings:
        lines += ["No normalized findings were recorded. Review coverage gaps before treating the host as clean.", ""]
    for index, finding in enumerate(findings):
        note = notes.get(index)
        lines += [f"### {index + 1}. {safe_text(finding_title(finding))}", "", f"**Scanner:** {safe_text(finding.get('adapter', 'unknown'), 80)}  ", f"**Severity:** {safe_text(finding.get('severity', 'review'), 40)}  ", f"**Location / package:** {safe_text(finding_location_or_library(finding), 512)}  "]
        if finding.get("installedVersion"):
            lines.append(f"**Installed version:** {safe_text(finding.get('installedVersion'), 160)}  ")
        if finding.get("fixedVersion"):
            lines.append(f"**Fixed version:** {safe_text(finding.get('fixedVersion'), 160)}  ")
        if note:
            lines += [f"**AI assessment:** {safe_text(note.get('classification', 'needs_review'), 40)} (confidence: {note.get('confidence', 'not provided')})  ", f"**Why it matters:** {safe_text(note.get('note', 'No detailed note recorded.'), 2000)}", ""]
        else:
            lines += ["**Next step:** verify this host observation with a separate read-only check before treating it as malicious or benign.", ""]
    if incomplete or failed or run["skippedScanners"]:
        lines += ["## Coverage gaps", ""]
        for item in incomplete + failed:
            lines.append(f"- **{safe_text(item.get('adapter', 'unknown'), 80)}:** {safe_text(item.get('resultStatus', 'unknown'), 40)}; {safe_text(scanner_recovery(item), 1200)}")
        for item in run["skippedScanners"]:
            lines.append(f"- **{safe_text(item.get('adapter', 'unknown'), 80)}:** skipped; {safe_text(item.get('reason', 'not run'), 1200)}")
        lines.append("")
    lines += ["## Scan coverage", "", "| Scanner | Result | Findings | Observations | Access |", "| --- | --- | --- | --- | --- |"]
    for item in scanners:
        counts = item.get("counts") or {}
        access = "active network" if item.get("requiresActiveNetwork") else "network database" if item.get("requiresNetwork") else "traffic capture" if item.get("requiresTrafficCapture") else "local service probe" if item.get("requiresServiceProbe") else "local"
        lines.append(f"| {safe_text(item.get('adapter', 'unknown'), 80)} | {safe_text(item.get('resultStatus', 'unknown'), 40)} | {counts.get('findings', len(item.get('findings', [])))} | {counts.get('observations', len(item.get('observations', [])))} | {access} |")
    if not scanners:
        lines.append("| No scanner was run | not executed | 0 | 0 | local |")
    observations = [observation for scanner in scanners for observation in scanner.get("observations", []) if isinstance(observation, str)]
    if observations:
        lines += ["## Security-relevant observations", "", "These items are inventory or telemetry, not findings by themselves.", ""]
        lines += [f"- {safe_text(observation)}" for observation in observations[:200]]
        lines.append("")
    lines += ["", "## Scope and consent", "", "```json", safe_json(run["consent"]), "```", ""]
    if run.get("hostAiTriage"):
        lines += ["## Host AI triage (advisory)", "", "```json", safe_json(run["hostAiTriage"]), "```", ""]
    if run.get("agentReview"):
        lines += ["## Independent agent review (advisory)", "", "```json", safe_json(run["agentReview"]), "```", ""]
    lines += ["## Report details", "", "| Report ID | Generated | AI analysis | Independent review |", "| --- | --- | --- | --- |", f"| {report_id} | {datetime.now(timezone.utc).replace(microsecond=0).isoformat()} | {'included' if run.get('hostAiTriage') else 'not requested'} | {'included' if run.get('agentReview') else 'not requested'} |", ""]
    return "\n".join(lines)


def write_report(root: Path, run: dict[str, Any]) -> dict[str, Any]:
    report_id = str(time.time_ns())
    destination_root = run_directory(root, report_id, create=True)
    destination = destination_root / "result.md"
    document = render_report(root, run, report_id)
    truncated = len(document.encode("utf-8")) > MAX_OUTPUT
    if truncated:
        document = document.encode("utf-8")[:MAX_OUTPUT].decode("utf-8", "ignore") + "\n\n_Report truncated at storage limit._\n"
    atomic_write(destination, document, replace=False)
    return {"reportId": report_id, "path": str(destination), "redacted": True, "truncated": truncated}


def validate_ssh_alias(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise ValueError("sshAlias must be a configured SSH alias containing only letters, digits, dot, underscore, or hyphen")
    config = Path.home() / ".ssh" / "config"
    try:
        info = os.lstat(config)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("~/.ssh/config must be a regular file when using remote scanning")
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("~/.ssh/config must be private and owned by this user")
        text = read_regular_file(config, MAX_OUTPUT)
    except FileNotFoundError as exc:
        raise ValueError("remote scanning requires an explicit Host alias in ~/.ssh/config") from exc
    aliases = set()
    for line in text.splitlines():
        match = re.match(r"^\s*Host\s+(.+?)\s*(?:#.*)?$", line, re.I)
        if not match: continue
        for candidate in match.group(1).split():
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", candidate): aliases.add(candidate)
    if value not in aliases:
        raise ValueError("sshAlias must be an exact Host alias declared directly in ~/.ssh/config")
    return value


def ssh_argv(alias: str, remote_args: list[str]) -> list[str]:
    return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes", alias, *remote_args]


def ssh_run(alias: str, remote_args: list[str], *, input_text: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(ssh_argv(alias, remote_args), input=input_text, capture_output=True, text=True, timeout=timeout, check=False)


def remote_probe(alias: str) -> dict[str, Any]:
    python = ssh_run(alias, ["sh", "-lc", "command -v python3"], timeout=30)
    if python.returncode != 0 or not python.stdout.strip():
        raise ValueError("remote alias connected but python3 was not found; install Python 3 on the remote host")
    python_path = python.stdout.strip().splitlines()[-1]
    probe_code = "import json, os; root=os.path.expanduser('" + REMOTE_RUNNER_DIR + "'); print(json.dumps({'home':os.path.expanduser('~'),'runnerPath':os.path.join(root,'system_mcp.py'),'versionPath':os.path.join(root,'version'),'runnerExists':os.path.isfile(os.path.join(root,'system_mcp.py')),'version':open(os.path.join(root,'version')).read().strip() if os.path.isfile(os.path.join(root,'version')) else None}))"
    result = ssh_run(alias, [python_path, "-c", probe_code], timeout=30)
    if result.returncode != 0:
        raise ValueError("remote runner probe failed: " + bounded_text(result.stderr or result.stdout, 500))
    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("remote runner probe returned invalid JSON") from exc
    return {"sshAlias": alias, "pythonPath": python_path, **status}


def deploy_remote_runner(alias: str, python_path: str) -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    version = REMOTE_RUNNER_RELEASE
    payload = base64.b64encode(json.dumps({"script": source, "version": version}).encode()).decode()
    deploy_code = "import base64,json,os,pathlib,sys,tempfile; data=json.loads(base64.b64decode(sys.stdin.buffer.read())); root=pathlib.Path(os.path.expanduser('" + REMOTE_RUNNER_DIR + "')); root.mkdir(parents=True,exist_ok=True); os.chmod(root,0o700); tmp=root/'system_mcp.py.tmp'; tmp.write_text(data['script'],encoding='utf-8'); os.chmod(tmp,0o600); os.replace(tmp,root/'system_mcp.py'); (root/'version').write_text(data['version']+'\\n',encoding='utf-8'); os.chmod(root/'version',0o600)"
    result = ssh_run(alias, [python_path, "-c", deploy_code], input_text=payload, timeout=60)
    if result.returncode != 0:
        raise ValueError("remote runner deployment failed: " + bounded_text(result.stderr or result.stdout, 500))


def remote_deployment_ticket(alias: str, approved: Any) -> dict[str, Any]:
    if approved is not True:
        raise ValueError("remote runner deployment requires approveDeployment=true after explicit user approval")
    status = remote_probe(alias)
    deployment_id = secrets.token_hex(16)
    REMOTE_DEPLOYMENTS[deployment_id] = {"sshAlias": alias, "pythonPath": status["pythonPath"], "expiresAt": time.time() + 600}
    return {"deploymentId": deployment_id, "sshAlias": alias, "runnerExists": status["runnerExists"], "expiresInSeconds": 600, "remoteHome": status["home"]}


def consume_remote_deployment(alias: str, deployment_id: Any) -> dict[str, Any]:
    if not isinstance(deployment_id, str): raise ValueError("deploymentId must be a string")
    ticket = REMOTE_DEPLOYMENTS.pop(deployment_id, None)
    if not ticket or ticket["sshAlias"] != alias or ticket["expiresAt"] < time.time():
        raise ValueError("deployment ticket is missing, expired, or belongs to another SSH alias")
    deploy_remote_runner(alias, ticket["pythonPath"])
    status = remote_probe(alias)
    return {**status, "deployment": "updated"}


def remote_call(alias: str, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if operation not in {"system_bootstrap", "system_doctor", "system_plan", "system_virtual_run", "system_run", "system_ingest", "system_start_run", "system_record_run", "system_finalize_run", "system_ai_triage_payload", "system_advisory_lookup"}:
        raise ValueError("remote operation is not allowlisted")
    if not isinstance(arguments, dict):
        raise ValueError("remote operation arguments must be an object")
    status = remote_probe(alias)
    if not status.get("runnerExists") or status.get("version") != REMOTE_RUNNER_RELEASE:
        raise ValueError("remote runner is missing or outdated; obtain a one-time deployment ticket and call system_remote_deploy_runner after explicit deployment consent")
    launcher = "import os,runpy; runpy.run_path(os.path.expanduser('" + REMOTE_RUNNER_SCRIPT + "'),run_name='__main__')"
    request = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":operation,"arguments":arguments}}) + "\n"
    result = ssh_run(alias, [status["pythonPath"], "-c", launcher], input_text=request, timeout=REMOTE_TIMEOUT)
    if result.returncode != 0:
        raise ValueError("remote MCP call failed: " + bounded_text(result.stderr or result.stdout, 500))
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("remote MCP returned invalid JSON-RPC") from exc
    if "error" in response:
        raise ValueError("remote MCP protocol error: " + bounded_text(response["error"].get("message", "unknown"), 500))
    return response.get("result", {})


def content(value: Any, error: bool = False) -> dict[str, Any]:
    return {"isError": error, "content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}]}


def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    try:
        if name == "system_catalog":
            return content({"adapters": [{"id": key, "category": value["category"], "executable": value["exe"], "requiresNetwork": value.get("network", False), "requiresActiveNetwork": value.get("active", False), "requiresTrafficCapture": value.get("traffic", False), "requiresServiceProbe": value.get("serviceProbe", False)} for key, value in ADAPTERS.items()], "safety": "No remediation, installations, arbitrary commands, PCAP files, or unapproved network/service probes. Sensitive service and Docker output is normalized before it is returned."})
        if name == "system_remote_prepare":
            alias = validate_ssh_alias(args.get("sshAlias"))
            return content({**remote_probe(alias), "expectedVersion": REMOTE_RUNNER_RELEASE, "deployment": "not_requested"})
        if name == "system_remote_authorize_deploy":
            alias = validate_ssh_alias(args.get("sshAlias"))
            return content(remote_deployment_ticket(alias, args.get("approveDeployment")))
        if name == "system_remote_deploy_runner":
            alias = validate_ssh_alias(args.get("sshAlias"))
            return content(consume_remote_deployment(alias, args.get("deploymentId")))
        if name == "system_remote_call":
            alias = validate_ssh_alias(args.get("sshAlias"))
            return remote_call(alias, args.get("operation"), args.get("arguments"))
        if name in ("system_doctor", "system_plan"):
            root = report_directory(args.get("reportDirectory")); data = plan(root)
            if name == "system_doctor":
                data["missingExecutables"] = [item["executable"] for item in data["runs"] if not item["available"]]
            return content(data)
        if name == "system_bootstrap":
            root = report_directory(args.get("reportDirectory"))
            return content(bootstrap(root, args.get("createProfile", False)))
        if name == "system_virtual_run":
            root = report_directory(args.get("reportDirectory"))
            return content(run_one(root, args, True))
        if name == "system_run":
            root = report_directory(args.get("reportDirectory")); run = started_run(root, args.get("runId"))
            preview = run_one(root, args, True)
            if preview["requiresNetwork"] and not run["consent"]["network"]:
                raise ValueError("network consent was not recorded for this lifecycle")
            if preview["requiresActiveNetwork"] and not run["consent"]["activeNetwork"]:
                raise ValueError("active network consent was not recorded for this lifecycle")
            if preview["requiresTrafficCapture"] and not run["consent"]["trafficCapture"]:
                raise ValueError("traffic-capture consent was not recorded for this lifecycle")
            if preview["requiresServiceProbe"] and not run["consent"]["serviceProbe"]:
                raise ValueError("local service-probe consent was not recorded for this lifecycle")
            if not any(item.get("adapter") == preview["adapter"] and item.get("command", {}).get("argv") == preview["command"]["argv"] for item in run["virtualCommands"]):
                raise ValueError("record an identical system_virtual_run preview in this lifecycle before executing")
            return content(run_one(root, args, False))
        if name == "system_ingest":
            root = report_directory(args.get("reportDirectory"))
            report = private_input_report(root, args.get("report"))
            report_format = args.get("format")
            if report_format not in ("json", "sarif"):
                raise ValueError("format must be json or sarif")
            raw = json.loads(read_regular_file(report, MAX_OUTPUT))
            findings = parse_ingested_report(raw, args.get("adapter") if isinstance(args.get("adapter"), str) else None)
            return content({"sourcePath": str(report), "format": report_format, "reportOnly": True, "findings": redact(findings), "counts": {"findings": len(findings)}})
        if name == "system_start_run":
            root = report_directory(args.get("reportDirectory")); mode = args.get("mode"); consent = args.get("consent")
            if mode not in ("scan", "scan-ai", "scan-agent"):
                raise ValueError("mode and consent are required")
            consent = normalize_consent(consent)
            run_id = str(time.time_ns())
            run = {"reportDirectory": str(root), "mode": mode, "consent": consent, "startedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "scannerResults": [], "virtualCommands": [], "skippedScanners": [], "hostAiTriage": None, "agentReview": None}
            RUNS[run_id] = run; save_run(root, run_id, run)
            return content({"runId": run_id, "statePath": str(state_path(root, run_id)), "processStarted": False, "reportWritten": False})
        if name == "system_record_run":
            root = report_directory(args.get("reportDirectory")); run_id = args.get("runId"); run = started_run(root, run_id)
            kind, entry = args.get("kind"), args.get("entry")
            if kind not in ("scanner", "preview", "skipped", "host_ai_triage", "agent_review") or not isinstance(entry, dict):
                raise ValueError("kind and entry are required")
            finding_count = sum(len(item.get("findings", [])) for item in run["scannerResults"])
            normalized = normalize_entry(kind, entry, finding_count)
            if kind == "host_ai_triage": run["hostAiTriage"] = normalized
            elif kind == "agent_review": run["agentReview"] = normalized
            else:
                key = {"scanner": "scannerResults", "preview": "virtualCommands", "skipped": "skippedScanners"}[kind]
                run[key].append(normalized)
            save_run(root, str(run_id), run)
            return content({"runId": run_id, "recorded": kind})
        if name == "system_finalize_run":
            root = report_directory(args.get("reportDirectory")); run_id = args.get("runId"); run = started_run(root, run_id)
            finding_count = sum(len(item.get("findings", [])) for item in run["scannerResults"])
            if args.get("hostAiTriage") is not None:
                if not isinstance(args["hostAiTriage"], dict): raise ValueError("hostAiTriage must be an object")
                run["hostAiTriage"] = normalize_entry("host_ai_triage", args["hostAiTriage"], finding_count)
            if args.get("agentReview") is not None:
                if not isinstance(args["agentReview"], dict): raise ValueError("agentReview must be an object")
                run["agentReview"] = normalize_entry("agent_review", args["agentReview"], finding_count)
            if run["mode"] in ("scan-ai", "scan-agent") and run["consent"].get("aiTriage") is True and not run.get("hostAiTriage"):
                raise ValueError("record approved host AI triage before finalizing")
            if run["mode"] == "scan-agent" and run["consent"].get("agentReview") is True and not run.get("agentReview"):
                raise ValueError("record approved agent review before finalizing")
            result = write_report(root, run); state_path(root, run_id).unlink(missing_ok=True); RUNS.pop(str(run_id), None)
            return content({**result, "runId": run_id, "finalized": True})
        if name == "system_ai_triage_payload":
            findings = redact(args.get("findings"))
            if not isinstance(findings, list): raise ValueError("findings must be an array")
            return content({"findingLimit": min(len(findings), 40), "findings": findings[:40], "instruction": "Analyze only supplied redacted evidence. Return findingNotes in zero-based findingIndex order with classification (true_positive, false_positive, needs_review), confidence, and detailed evidence note. Do not request secrets or suggest automatic remediation."})
        if name == "system_advisory_lookup":
            if args.get("allowNetwork") is not True:
                raise ValueError("OSV advisory lookup requires allowNetwork=true")
            ecosystem, package_name, version = args.get("ecosystem"), args.get("package"), args.get("version")
            if not all(isinstance(value, str) and value for value in (ecosystem, package_name, version)):
                raise ValueError("ecosystem, package, and version must be non-empty strings")
            body = json.dumps({"package": {"ecosystem": ecosystem, "name": package_name}, "version": version}).encode()
            request = urllib.request.Request("https://api.osv.dev/v1/query", data=body, headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    payload = response.read(MAX_OUTPUT + 1)
                    if len(payload) > MAX_OUTPUT:
                        raise ValueError("OSV advisory response exceeds the bounded response limit")
                    raw = json.loads(payload.decode())
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                raise ValueError(f"OSV advisory lookup failed: {exc}")
            vulnerabilities = raw.get("vulns", []) if isinstance(raw, dict) else []
            return content({"source": "OSV", "networkUsed": True, "package": {"ecosystem": ecosystem, "name": package_name, "version": version}, "vulnerabilities": [{"id": item.get("id"), "summary": item.get("summary"), "modified": item.get("modified"), "aliases": item.get("aliases", []), "references": item.get("references", [])} for item in vulnerabilities[:50] if isinstance(item, dict)]})
        raise ValueError(f"unknown tool: {name}")
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        return content({"error": str(exc)}, True)


def main() -> int:
    for line in sys.stdin:
        try:
            request = json.loads(line); method, request_id = request.get("method"), request.get("id")
            if method == "initialize": result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "mnogovid-system-scanner", "version": "0.1.0"}}
            elif method == "tools/list": result = {"tools": TOOLS}
            elif method == "tools/call": result = call(request.get("params", {}).get("name", ""), request.get("params", {}).get("arguments", {}))
            elif request_id is None: continue
            else: raise ValueError(f"method not found: {method}")
            print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}, ensure_ascii=False), flush=True)
        except Exception as exc:
            print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
