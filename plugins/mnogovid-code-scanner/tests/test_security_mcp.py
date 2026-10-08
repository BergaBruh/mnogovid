from __future__ import annotations

import importlib.util
import json
import subprocess
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
        self.assertIn("installationGuide", verified["doctor"])

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

    def test_npm_mcp_binary_proxies_to_the_python_server(self) -> None:
        plugin_root = Path(__file__).resolve().parents[1]
        package = json.loads((plugin_root / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["name"], "@bergabruh/code-scanner")
        self.assertEqual(package["bin"]["mnogovid-code-scanner"], "./bin/mnogovid-code-scanner.mjs")
        self.assertIn("bin/*.mjs", package["files"])
        self.assertIn("scripts/*.py", package["files"])
        entrypoint = plugin_root / "bin" / "mnogovid-code-scanner.mjs"
        self.assertTrue(entrypoint.is_file())
        entrypoint_text = entrypoint.read_text(encoding="utf-8")
        self.assertIn("python3", entrypoint_text)
        self.assertIn("security_mcp.py", entrypoint_text)
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        completed = subprocess.run(["node", str(entrypoint)], input=json.dumps(request) + "\n", text=True, capture_output=True, timeout=5, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        response = json.loads(completed.stdout)
        self.assertEqual(response["id"], 1)
        self.assertIn("tools", response["result"])

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

    def test_trusted_ai_payload_is_explicit_and_still_secret_scrubbed(self) -> None:
        strict = payload(security_mcp.call("security_ai_triage_payload", {"findings": [{"title": "path", "token": "do-not-leak"}]}))
        trusted = payload(security_mcp.call("security_ai_triage_payload", {"findings": [{"title": "path", "token": "do-not-leak"}], "trustedAi": True}))
        self.assertEqual(strict["privacyMode"], "strict-redacted")
        self.assertEqual(trusted["privacyMode"], "trusted-ai")
        self.assertNotIn("do-not-leak", json.dumps(trusted))


    def test_verdict_contract_and_aliases(self) -> None:
        for raw, canon in (("true_positive", "confirmed"), ("needs_review", "needs_validation"), ("false_positive", "rejected")):
            self.assertEqual(security_mcp.verdict_note({"classification": raw})["verdict"], canon)
        self.assertEqual(security_mcp.verdict_note({"verdict": "bogus"}), {})
        with self.assertRaises(ValueError): security_mcp.verdict_note({"verdict": "confirmed"})
        with self.assertRaises(ValueError): security_mcp.verdict_note({"verdict": "needs_validation", "blocker": "b"})
        with self.assertRaises(ValueError): security_mcp.verdict_note({"verdict": "rejected"})
        with self.assertRaises(ValueError): security_mcp.verdict_note({"verdict": "rejected", "reason": "r", "severity": "low"})
        ok = security_mcp.verdict_note({"verdict": "confirmed", "evidenceQuote": "q", "severity": "high"})
        self.assertEqual(ok["classification"], "true_positive")

    def test_fingerprint_stable(self) -> None:
        a = {"adapter": "x", "title": "T"}
        self.assertEqual(security_mcp.finding_fingerprint(a), security_mcp.finding_fingerprint({**a, "findingId": "9"}))
        self.assertNotEqual(security_mcp.finding_fingerprint(a), security_mcp.finding_fingerprint({**a, "title": "U"}))

    def test_secret_paths_scrubbed_and_withheld_even_when_trusted(self) -> None:
        for text in ("/h/.ssh/id_rsa", "/r/.netrc", "a/.npmrc", ".pypirc", ".dockercfg", "id_ed25519"):
            self.assertTrue(security_mcp.is_secret_path(text))
            self.assertIn("[REDACTED-PATH]", security_mcp.redact(text))
        self.assertFalse(security_mcp.is_secret_path("/etc/sshd_config"))
        out = payload(security_mcp.call("security_ai_triage_payload", {"findings": [{"title": "x", "location": "/h/.ssh/id_rsa"}, {"title": "ok", "location": "a.py"}], "trustedAi": True}))
        self.assertEqual(out["findings"][0]["withheld"], "secret-bearing path")
        self.assertNotIn("title", out["findings"][0])
        self.assertEqual(out["findings"][1]["title"], "ok")

    def test_reviewer_payload_has_no_host_verdict(self) -> None:
        host = {"title": "x", "verdict": "confirmed", "classification": "true_positive", "confidence": 0.9, "note": "host rationale", "rationale": "r", "verdictSource": "host_ai_triage", "hostAiTriage": {}}
        out = json.dumps(payload(security_mcp.call("security_ai_triage_payload", {"findings": [host]})))
        for k in ("verdict", "classification", "confidence", "host rationale", "verdictSource", "hostAiTriage"):
            self.assertNotIn(k, out.replace("Return a JSON object", "").split('"instruction"')[0])
        clean = payload(security_mcp.call("security_ai_triage_payload", {"findings": [{"title": "x"}]}))
        self.assertEqual(payload(security_mcp.call("security_ai_triage_payload", {"findings": [host]}))["findings"][0]["fingerprint"], clean["findings"][0]["fingerprint"])

    def test_agent_review_follows_verdict_contract(self) -> None:
        run = {"scannerResults": [{"findings": [{"title": "a"}]}]}
        v = security_mcp.validate_host_ai_triage
        with self.assertRaises(ValueError) as ctx: v(run, {"findingNotes": []}, "agent review")
        self.assertIn("agent review", str(ctx.exception))
        for bad in ({"verdict": "confirmed"}, {"verdict": "needs_validation", "blocker": "b"}, {"verdict": "rejected"}):
            with self.assertRaises(ValueError): v(run, {"findingNotes": [{"findingIndex": 0, "note": "n", **bad}]}, "agent review")
        ok = v(run, {"findingNotes": [{"findingIndex": 0, "note": "n", "verdict": "rejected", "reason": "r"}]}, "agent review")
        self.assertEqual(ok["findingNotes"][0]["verdict"], "rejected")

    def test_triage_pagination(self) -> None:
        items = [{"title": str(i)} for i in range(45)]
        first = payload(security_mcp.call("security_ai_triage_payload", {"findings": items}))
        self.assertEqual((first["findingLimit"], first["nextOffset"]), (40, 40))
        second = payload(security_mcp.call("security_ai_triage_payload", {"findings": items, "findingOffset": 40}))
        self.assertEqual((second["findingLimit"], second["nextOffset"]), (5, None))
        self.assertTrue(second["findings"][0]["findingId"])
        self.assertTrue(security_mcp.call("security_ai_triage_payload", {"findings": items, "findingOffset": -1})["isError"])

    def test_ignore_extended_without_lockfiles(self) -> None:
        for name in ("dist", ".next", ".tox", "site-packages", "__snapshots__", "testdata"):
            self.assertIn(name, security_mcp.IGNORE)
        self.assertNotIn("package-lock.json", security_mcp.IGNORE)
        Path(self.root, "a.min.js").write_text("1")
        Path(self.root, "package.json").write_text("{}")
        found = security_mcp.discover(Path(self.root))
        self.assertNotIn("javascript", found["languages"])
        Path(self.root, "b.js").write_text("1")
        self.assertIn("javascript", security_mcp.discover(Path(self.root))["languages"])

    def test_verify_location(self) -> None:
        root = Path(self.root).resolve()
        (root / "a.py").write_text("x=1\ny=2\n")
        v = security_mcp.verify_location
        self.assertIsNone(v(root, {"title": "t"}))
        self.assertEqual(v(root, {"path": "a.py", "line": 2}), "verified")
        self.assertEqual(v(root, {"path": "a.py", "line": 99}), "location_unverified")
        self.assertEqual(v(root, {"path": "missing.py"}), "location_unverified")
        self.assertEqual(v(root, {"path": "../../etc/passwd"}), "location_unverified")

    def run_cycle(self, notes, findings=None):
        root = Path(self.root).resolve()
        (root / "a.py").write_text("x=1\n")
        rid = payload(security_mcp.call("security_start_run", {"workspace": str(root), "mode": "scan-ai", "consent": {"aiTriage": True}}))["runId"]
        entry = {"adapter": "bandit", "resultStatus": "complete", "findings": findings or [{"title": "t", "path": "a.py", "line": 1}, {"title": "gone", "path": "nope.py", "line": 1}]}
        security_mcp.call("security_record_run", {"workspace": str(root), "runId": rid, "kind": "scanner", "entry": entry})
        return root, rid, security_mcp.call("security_record_run", {"workspace": str(root), "runId": rid, "kind": "host_ai_triage", "entry": {"findingNotes": notes}})

    def test_confirmed_on_unverified_location_rejected(self) -> None:
        bad = [{"findingIndex": i, "verdict": "confirmed", "evidenceQuote": "q", "note": "n"} for i in (0, 1)]
        _, _, result = self.run_cycle(bad)
        self.assertTrue(result["isError"])
        self.assertIn("unverified", payload(result)["error"])

    def test_findings_json_coverage_prior_and_source_ref(self) -> None:
        good = [{"findingIndex": 0, "verdict": "confirmed", "severity": "high", "evidenceQuote": "x=1", "note": "n"},
                {"findingIndex": 1, "verdict": "needs_validation", "blocker": "b", "validationPlan": "p", "note": "n"}]
        root, rid, result = self.run_cycle(good)
        self.assertFalse(result["isError"])
        done = payload(security_mcp.call("security_finalize_run", {"workspace": str(root), "runId": rid}))
        doc = json.loads(Path(done["findingsPath"]).read_text())
        by_title = {r["title"]: r for r in doc["findings"]}
        self.assertEqual(by_title["t"]["verdict"], "confirmed")
        self.assertEqual(by_title["t"]["severity"], "high")
        self.assertNotIn("severity", by_title["gone"])
        self.assertTrue(by_title["t"]["findingId"])
        self.assertTrue(doc["coverage"]["partial"])
        self.assertIn("sourceRef", doc)
        self.assertIn("Coverage statement", Path(done["path"]).read_text())
        prior = payload(security_mcp.call("security_prior_runs", {"workspace": str(root)}))
        self.assertEqual(prior["priorCount"], 2)
        self.assertIn("security_prior_runs", [t["name"] for t in security_mcp.TOOLS])

    def test_prior_rejected_suppresses_only_identical_fingerprint(self) -> None:
        report = {"scannerResults": [{"adapter": "a", "findings": [{"adapter": "a", "title": "same"}, {"adapter": "a", "title": "changed"}]}]}
        fp = security_mcp.finding_fingerprint({"adapter": "a", "title": "same"})
        doc = security_mcp.build_findings_document(report, "2", {}, {fp: {"verdict": "rejected", "reportId": "1"}})
        by = {r["title"]: r for r in doc["findings"]}
        self.assertTrue(by["same"].get("suppressedByPrior"))
        self.assertNotIn("priorVerdict", by["changed"])

    def test_source_ref_and_gitignore_warning(self) -> None:
        root = Path(self.root).resolve()
        self.assertEqual(security_mcp.source_ref(root), {"commit": None, "dirty": None})
        g = lambda *a: subprocess.run(["git", "-C", str(root), *a], capture_output=True)
        g("init", "-q"); g("config", "user.email", "a@b"); g("config", "user.name", "n")
        (root / "f").write_text("1"); g("add", "."); g("commit", "-qm", "i")
        self.assertEqual(security_mcp.source_ref(root)["dirty"], False)
        self.assertIn("not git-ignored", security_mcp.gitignore_warning(root))
        (root / ".gitignore").write_text(".mnogovid/\n")
        self.assertIsNone(security_mcp.gitignore_warning(root))

    def test_gitleaks_argv_and_report_parsing(self) -> None:
        argv = security_mcp.command(Path(self.root).resolve(), "gitleaks")[1]
        self.assertEqual(argv[argv.index("--report-path") + 1], "-")
        self.assertIn("--redact", argv)
        report = [{"RuleID": "github-pat", "Description": "leak", "File": "app.py", "StartLine": 1, "Secret": "REDACTED"}]
        found = security_mcp.parse_report(report, "gitleaks")
        self.assertEqual([(f["ruleId"], f["location"], f["line"]) for f in found], [("github-pat", "app.py", 1)])
        self.assertNotIn("Secret", found[0])

    def test_scan_agent_cannot_finalize_without_approved_agent_review(self) -> None:
        root = str(Path(self.root).resolve())
        rid = payload(security_mcp.call("security_start_run", {"workspace": root, "mode": "scan-agent", "consent": {"aiTriage": True, "agentReview": True}}))["runId"]
        rec = lambda kind, entry: security_mcp.call("security_record_run", {"workspace": root, "runId": rid, "kind": kind, "entry": entry})
        rec("scanner", {"adapter": "bandit", "resultStatus": "complete", "findings": [{"title": "t"}]})
        rec("host_ai_triage", {"findingNotes": [{"findingIndex": 0, "note": "n", "verdict": "rejected", "reason": "r"}]})
        result = security_mcp.call("security_finalize_run", {"workspace": root, "runId": rid})
        self.assertTrue(result["isError"])
        self.assertIn("agent review", payload(result)["error"])


if __name__ == "__main__":
    unittest.main()
