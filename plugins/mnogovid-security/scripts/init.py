#!/usr/bin/env python3
"""Initialize a non-destructive Mnogovid Security project profile.

The script only inspects the target directory by default.  Pass ``--write`` to
create the missing ``.mnogovid-security.json`` profile; an existing profile is
never changed unless ``--force`` is supplied as well.  ``--allow-network`` is
recorded as a preference for later scanner runs and never opens a connection.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from security_mcp import ADAPTERS, discover, recommend


PROFILE_NAME = ".mnogovid-security.json"
PACKAGE_MANAGER_HINTS = (
    ("apt", "apt-get", "sudo apt-get install <package>"),
    ("dnf", "dnf", "sudo dnf install <package>"),
    ("yum", "yum", "sudo yum install <package>"),
    ("pacman", "pacman", "sudo pacman -S <package>"),
    ("zypper", "zypper", "sudo zypper install <package>"),
    ("Homebrew", "brew", "brew install <package>"),
    ("winget", "winget", "winget install <package>"),
    ("Chocolatey", "choco", "choco install <package>"),
    ("Scoop", "scoop", "scoop install <package>"),
    ("pipx", "pipx", "pipx install <package>"),
    ("Cargo", "cargo", "cargo install <package>"),
    ("Go", "go", "go install <module>@latest"),
    ("npm", "npm", "npm install --global <package>"),
)


def installation_guide(missing: list[str]) -> dict[str, object]:
    managers = [
        {"name": name, "executable": executable, "commandTemplate": command}
        for name, executable, command in PACKAGE_MANAGER_HINTS
        if shutil.which(executable) is not None
    ]
    return {
        "message": "If you want to add more tools, follow the instructions for a package manager available on this system.",
        "platform": platform.platform(),
        "missingExecutables": missing,
        "packageManagers": managers,
        "note": "Replace <package> or <module> with the scanner's verified package or module name before installing.",
    }


def build_result(project: Path) -> dict[str, object]:
    found = discover(project)
    recommended = recommend(found)
    checks = [
        {
            "adapter": adapter,
            "executable": ADAPTERS[adapter]["exe"],
            "available": shutil.which(ADAPTERS[adapter]["exe"]) is not None,
            "requiresNetwork": ADAPTERS[adapter]["network"],
        }
        for adapter in recommended
    ]
    missing = sorted({str(item["executable"]) for item in checks if not item["available"]})
    return {
        "project": str(project),
        "detected": {
            "ecosystems": found["ecosystems"],
            "languages": found["languages"],
            "surfaces": found["surfaces"],
        },
        "checks": checks,
        "availableAdapters": [item["adapter"] for item in checks if item["available"]],
        "missingExecutables": missing,
        "installationGuide": installation_guide(missing),
    }


def profile(result: dict[str, object], allow_network: bool) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "generatedBy": "mnogovid-security init",
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "recommendedAdapters": [item["adapter"] for item in result["checks"]],
        "availableAdapters": result["availableAdapters"],
        "allowNetwork": allow_network,
        "installationGuide": result["installationGuide"],
        "notes": [
            "Review recommendedAdapters before running scanners.",
            "Network-dependent scanners still require explicit host approval.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check project-relevant security scanners and optionally create a local profile."
    )
    parser.add_argument("project", nargs="?", default=".", help="project directory (default: current directory)")
    parser.add_argument("--write", action="store_true", help=f"create {PROFILE_NAME} if it is missing")
    parser.add_argument("--force", action="store_true", help=f"replace an existing {PROFILE_NAME}; requires --write")
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="record approval for network-dependent scanner runs; this command does not use the network",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args()
    if args.force and not args.write:
        parser.error("--force requires --write")

    project = Path(args.project).expanduser().resolve()
    if not project.is_dir():
        parser.error(f"project is not a directory: {project}")

    result = build_result(project)
    destination = project / PROFILE_NAME
    existed = destination.exists()
    if args.write and (not existed or args.force):
        destination.write_text(json.dumps(profile(result, args.allow_network), indent=2) + "\n", encoding="utf-8")
        result["profile"] = {"path": str(destination), "action": "replaced" if existed else "created"}
    elif args.write:
        result["profile"] = {"path": str(destination), "action": "unchanged", "reason": "already exists"}
    else:
        result["profile"] = {"path": str(destination), "action": "not_written"}
    result["allowNetwork"] = args.allow_network

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Project: {project}")
        for item in result["checks"]:
            status = "available" if item["available"] else "missing"
            print(f"- {item['adapter']}: {item['executable']} ({status})")
        if result["missingExecutables"]:
            print("Missing programs: " + ", ".join(result["missingExecutables"]))
        guide = result["installationGuide"]
        print("If you want to add more tools, follow the instructions for this system:")
        print(f"- Platform: {guide['platform']}")
        for manager in guide["packageManagers"]:
            print(f"- {manager['name']}: {manager['commandTemplate']}")
        if not guide["packageManagers"]:
            print("- No supported package manager was detected; use the scanner's official installation instructions.")
        print(f"Profile: {result['profile']['action']} ({destination})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
