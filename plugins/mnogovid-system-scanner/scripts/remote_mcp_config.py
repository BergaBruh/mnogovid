#!/usr/bin/env python3
"""Render a safe static Codex MCP stanza for one SSH alias.

The script prints TOML; it deliberately never edits ~/.codex/config.toml and
never contacts the remote host. The SSH alias must already exist locally.
"""
from __future__ import annotations

import argparse
import json
import re
import sys


def validate_alias(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise ValueError("SSH alias must contain only letters, digits, dot, underscore, or hyphen")
    return value


def validate_remote_script(value: str) -> str:
    if not value.startswith("/") or ".." in value.split("/") or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value):
        raise ValueError("remote script must be an absolute path without '..' or whitespace")
    return value


def render(alias: str, remote_script: str) -> str:
    alias = validate_alias(alias)
    remote_script = validate_remote_script(remote_script)
    server_name = "mnogovid_system_" + re.sub(r"[^A-Za-z0-9_]", "_", alias)
    arguments = ["-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes", alias, "/usr/bin/python3", remote_script]
    return "\n".join([f"[mcp_servers.{server_name}]", 'command = "ssh"', "args = [" + ", ".join(json.dumps(item) for item in arguments) + "]", ""]) 


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a static SSH-stdio MCP config stanza.")
    parser.add_argument("ssh_alias", help="existing safe SSH alias from ~/.ssh/config")
    parser.add_argument("--remote-script", default="/opt/mnogovid-system-scanner/scripts/system_mcp.py")
    args = parser.parse_args()
    try:
        sys.stdout.write(render(args.ssh_alias, args.remote_script))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
