from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "security_mcp.py"
SPEC = importlib.util.spec_from_file_location("security_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
security_mcp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_mcp)


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class SecurityMcpBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name

    def tearDown(self) -> None:
        security_mcp.RUNS.clear()
        self.temp.cleanup()

    def test_bootstrap_creates_profile_only_after_explicit_request(self) -> None:
        first = payload(security_mcp.call("security_bootstrap", {"workspace": self.root}))
        self.assertEqual(first["profile"]["action"], "missing")
        self.assertFalse(Path(first["profile"]["path"]).exists())
        created = payload(security_mcp.call("security_bootstrap", {"workspace": self.root, "createProfile": True}))
        self.assertEqual(created["profile"]["action"], "created")
        verified = payload(security_mcp.call("security_bootstrap", {"workspace": self.root}))
        self.assertEqual(verified["profile"]["action"], "verified")
        self.assertFalse(verified["processStarted"])

    def test_bootstrap_refuses_a_symlinked_profile(self) -> None:
        profile = Path(self.root) / ".mnogovid-code-scanner.json"
        profile.symlink_to(Path(self.root) / "outside")
        result = security_mcp.call("security_bootstrap", {"workspace": self.root})
        self.assertTrue(result["isError"])
        self.assertIn("symlinked", payload(result)["error"])

    def test_unified_command_and_default_prompt_are_present(self) -> None:
        plugin_root = Path(__file__).resolve().parents[1]
        command = (plugin_root / "commands" / "security-scan.md").read_text(encoding="utf-8")
        manifest = json.loads((plugin_root / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertIn("security_bootstrap", command)
        self.assertIn("Adapters + AI triage", command)
        self.assertFalse((plugin_root / "commands" / "security-scan-ai.md").exists())
        self.assertFalse((plugin_root / "commands" / "security-scan-agent.md").exists())
        self.assertIn("onboarding", manifest["interface"]["defaultPrompt"])

    def test_execution_requires_lifecycle_network_consent_and_matching_preview(self) -> None:
        started = payload(security_mcp.call("security_start_run", {"workspace": self.root, "mode": "scan", "consent": {"network": False}}))
        preview = payload(security_mcp.call("security_virtual_run", {"workspace": self.root, "adapter": "semgrep"}))
        security_mcp.call("security_record_run", {"workspace": self.root, "runId": started["runId"], "kind": "preview", "entry": preview})
        result = security_mcp.call("security_run", {"workspace": self.root, "runId": started["runId"], "adapter": "semgrep"})
        self.assertTrue(result["isError"])
        self.assertIn("network consent", payload(result)["error"])
        result = security_mcp.call("security_run", {"workspace": self.root, "runId": started["runId"], "adapter": "gitleaks"})
        self.assertTrue(result["isError"])
        self.assertIn("identical", payload(result)["error"])


if __name__ == "__main__":
    unittest.main()
