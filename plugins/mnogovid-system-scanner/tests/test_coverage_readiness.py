import unittest
from pathlib import Path
from unittest.mock import patch

from test_system_mcp import system_mcp


class CoverageReadinessTests(unittest.TestCase):
    def test_plan_distinguishes_missing_sudo_from_missing_executable(self):
        found = {"packageManagers": ["apt-get"], "containerRuntimes": [], "serviceHints": []}
        with patch.object(system_mcp, "discover_host", return_value=found), \
             patch.object(system_mcp, "recommend_host", return_value=["clamav"]), \
             patch.object(system_mcp, "trusted_executable", side_effect=lambda name: None if name == "sudo" else "/usr/bin/clamscan"):
            result = system_mcp.plan(Path("/tmp"))
        missing = result["installationGuide"]["missingAdapters"][0]
        self.assertEqual(missing["group"], "malware")
        self.assertTrue(missing["executableAvailable"])
        self.assertFalse(result["runs"][0]["available"])

    def test_report_groups_gaps_and_preserves_unknown_adapters(self):
        run = {"scannerResults": [{"adapter": "clamav", "resultStatus": "failed", "stderrSnippet": "missing signatures"}],
               "skippedScanners": [{"adapter": "mysql-status", "reason": "scope denied"}, {"adapter": "custom", "reason": "not available"}],
               "mode": "scan", "scopeGroups": ["malware"]}
        report = system_mcp.render_report(Path("/tmp"), run, "test")
        self.assertIn("### Malware and rootkits", report)
        self.assertIn("### Nginx and database service posture", report)
        self.assertIn("### Other", report)
        self.assertIn("scope denied", report)
        self.assertIn("missing signatures", report)

    def test_tshark_recovery_discloses_temporary_capture(self):
        self.assertIn("temporary packet capture", system_mcp.scanner_recovery({"adapter": "tshark-summary"}))

    def test_command_offers_safe_setup_before_scan_on_both_clients(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / "commands/system-scan.md", root / "adapters/opencode/.opencode/commands/system-scan.md"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("Before scanning, if malware or integrity is selected", text)
            self.assertIn("https://docs.clamav.net/manual/Usage/SignatureManagement.html", text)
            self.assertIn("https://aide.github.io/doc/", text)
            self.assertIn("https://github.com/Cisco-Talos/clamav", text)
            self.assertIn("https://github.com/aide/aide", text)
            self.assertIn("https://clamav-mirror.ru/ is a user-suggested third-party mirror", text)
            self.assertIn("initialize a baseline on a potentially compromised host", text)


if __name__ == "__main__":
    unittest.main()
