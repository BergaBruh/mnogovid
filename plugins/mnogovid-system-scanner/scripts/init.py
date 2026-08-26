#!/usr/bin/env python3
"""Initialize an optional, non-destructive Mnogovid System Scanner profile."""
from __future__ import annotations

import argparse
import json
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path

from system_mcp import atomic_write, plan, report_directory

PROFILE_NAME = ".mnogovid-system-scanner.json"
PACKAGE_MANAGER_HINTS = (
    ("apt", "apt-get", "sudo apt-get install <package>"),
    ("dnf", "dnf", "sudo dnf install <package>"),
    ("yum", "yum", "sudo yum install <package>"),
    ("pacman", "pacman", "sudo pacman -S <package>"),
    ("zypper", "zypper", "sudo zypper install <package>"),
    ("apk", "apk", "sudo apk add <package>"),
)


def installation_guide(missing: list[str]) -> dict[str, object]:
    return {
        "message": "Install missing scanners only through your normal system administration process; this plugin never installs tools.",
        "platform": platform.platform(),
        "missingExecutables": missing,
        "packageManagers": [{"name": name, "executable": executable, "commandTemplate": command} for name, executable, command in PACKAGE_MANAGER_HINTS if shutil.which(executable)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect available Linux host-security scanners without running them.")
    parser.add_argument("report_directory", nargs="?", default=".", help="existing directory where optional profile and reports live")
    parser.add_argument("--write", action="store_true", help=f"create {PROFILE_NAME} if absent")
    parser.add_argument("--force", action="store_true", help="replace an existing profile; requires --write")
    parser.add_argument("--allow-active-network", action="store_true", help="record a preference for later explicitly approved Nmap probes")
    parser.add_argument("--allow-network", action="store_true", help="record a preference for later explicitly approved vulnerability-database use")
    parser.add_argument("--allow-service-probe", action="store_true", help="record a preference for later explicitly approved local service status probes")
    parser.add_argument("--allow-traffic-capture", action="store_true", help="record a preference for later explicitly approved bounded packet summaries")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args()
    if args.force and not args.write:
        parser.error("--force requires --write")
    root = report_directory(args.report_directory)
    result = plan(root)
    result["missingExecutables"] = [item["executable"] for item in result["runs"] if not item["available"]]
    result["installationGuide"] = installation_guide(result["missingExecutables"])
    profile_path = root / PROFILE_NAME
    exists = profile_path.exists() or profile_path.is_symlink()
    if exists and profile_path.is_symlink():
        parser.error(f"refusing to write through symlinked profile: {profile_path}")
    if args.write and (not exists or args.force):
        profile = {
            "schemaVersion": 1,
            "generatedBy": "mnogovid-system-scanner init",
            "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "allowActiveNetwork": args.allow_active_network,
            "allowNetwork": args.allow_network,
            "allowTrafficCapture": args.allow_traffic_capture,
            "allowServiceProbe": args.allow_service_probe,
            "availableAdapters": [item["adapter"] for item in result["runs"] if item["available"]],
            "recommendedAdapters": result["recommendedAdapters"],
            "installationGuide": result["installationGuide"],
            "notes": ["This file does not run scanners or grant per-command consent.", "Active probing and traffic capture still require an explicit tool call and user approval."],
        }
        atomic_write(profile_path, json.dumps(profile, ensure_ascii=False, indent=2) + "\n", replace=args.force)
        result["profile"] = {"path": str(profile_path), "action": "replaced" if exists else "created"}
    elif args.write:
        result["profile"] = {"path": str(profile_path), "action": "unchanged", "reason": "already exists"}
    else:
        result["profile"] = {"path": str(profile_path), "action": "not_written"}
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        host_os = result["host"].get("os", {})
        print(f"Host: {host_os.get('pretty_name', host_os.get('system', 'unknown'))}")
        for item in result["runs"]:
            print(f"- {item['adapter']}: {item['executable']} ({'available' if item['available'] else 'missing'})")
        for manager in result["installationGuide"]["packageManagers"]:
            print(f"- Installation template ({manager['name']}): {manager['commandTemplate']}")
        print(f"Profile: {result['profile']['action']} ({profile_path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
