#!/usr/bin/env python3
"""Dependency-free MCP security scanner orchestrator.

This is deliberately independent from Mnogovid/Rust. It discovers a workspace,
plans allowlisted scanner commands, executes them without a shell only after a
host-approved tool call, normalizes common report formats, and creates a
bounded/redacted payload for the host model's AI triage.
"""
from __future__ import annotations

import json, os, re, shutil, subprocess, sys, time, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_OUTPUT = 256 * 1024
RUNS: dict[str, dict[str, Any]] = {}
IGNORE = {".git", "node_modules", "target", ".venv", "__pycache__", "vendor", ".mnogovid"}
ADAPTERS: dict[str, dict[str, Any]] = {
    "semgrep": {"category":"sast","exe":"semgrep","network":True,"cmd":lambda p:["--json","--config","auto",str(p)]},
    "gosec": {"category":"sast","exe":"gosec","network":False,"cmd":lambda p:["-fmt=json","./..."],"cwd":True},
    "bandit": {"category":"sast","exe":"bandit","network":False,"cmd":lambda p:["-f","json","-r",str(p)]},
    "brakeman": {"category":"sast","exe":"brakeman","network":False,"cmd":lambda p:["-f","json","-p",str(p)]},
    "gitleaks": {"category":"secrets","exe":"gitleaks","network":False,"cmd":lambda p:["detect","--source",str(p),"--report-format","json","--no-banner"]},
    "trufflehog": {"category":"secrets","exe":"trufflehog","network":True,"cmd":lambda p:["filesystem",str(p),"--json"]},
    "detect-secrets": {"category":"secrets","exe":"detect-secrets","network":False,"cmd":lambda p:["scan",str(p)]},
    "trivy-fs": {"category":"sca","exe":"trivy","network":True,"cmd":lambda p:["fs","--format","json",str(p)]},
    "osv-scanner": {"category":"sca","exe":"osv-scanner","network":True,"cmd":lambda p:["scan","source","--format","json",str(p)]},
    "grype": {"category":"sca","exe":"grype","network":True,"cmd":lambda p:[f"dir:{p}","-o","json"]},
    "syft": {"category":"sbom","exe":"syft","network":False,"cmd":lambda p:[f"dir:{p}","-o","json"]},
    "cargo-audit": {"category":"sca","exe":"cargo-audit","network":True,"cmd":lambda p:["audit","--json"],"cwd":True},
    "cargo-deny": {"category":"sca","exe":"cargo-deny","network":True,"cmd":lambda p:["check","advisories","--format","json"],"cwd":True},
    "pip-audit": {"category":"sca","exe":"pip-audit","network":True,"cmd":lambda p:["-f","json"] ,"cwd":True},
    "npm-audit": {"category":"sca","exe":"npm","network":True,"cmd":lambda p:["audit","--json"],"cwd":True},
    "pnpm-audit": {"category":"sca","exe":"pnpm","network":True,"cmd":lambda p:["audit","--json"],"cwd":True},
    "yarn-audit": {"category":"sca","exe":"yarn","network":True,"cmd":lambda p:["audit","--json"],"cwd":True},
    "govulncheck": {"category":"sca","exe":"govulncheck","network":True,"cmd":lambda p:["./..."],"cwd":True},
    "bundler-audit": {"category":"sca","exe":"bundle-audit","network":True,"cmd":lambda p:["check","--format","json"],"cwd":True},
    "composer-audit": {"category":"sca","exe":"composer","network":True,"cmd":lambda p:["audit","--format=json"],"cwd":True},
    "checkov": {"category":"iac","exe":"checkov","network":False,"cmd":lambda p:["-d",str(p),"-o","json"]},
    "kics": {"category":"iac","exe":"kics","network":False,"cmd":lambda p:["scan","-p",str(p),"--output-path","-"]},
}
TOOLS = [
 {"name":"security_catalog","description":"List independent scanner adapters, categories, executables, and advisory/web data requirements.","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},
 {"name":"security_doctor","description":"Discover languages, manifests, infrastructure files, recommended scanners, and installed executables. Does not execute a scanner.","inputSchema":{"type":"object","properties":{"workspace":{"type":"string"}},"required":["workspace"],"additionalProperties":False}},
 {"name":"security_plan","description":"Create a non-executing workspace scan plan from detected files and available scanner programs.","inputSchema":{"type":"object","properties":{"workspace":{"type":"string"}},"required":["workspace"],"additionalProperties":False}},
 {"name":"security_virtual_run","description":"Preview one allowlisted scanner command without executing it.","inputSchema":{"type":"object","properties":{"workspace":{"type":"string"},"adapter":{"type":"string"},"allowNetwork":{"type":"boolean"}},"required":["workspace","adapter"],"additionalProperties":False}},
 {"name":"security_run","description":"Execute one allowlisted scanner without a shell. Requires an explicit host-approved tool call; network-dependent scanners require allowNetwork=true.","inputSchema":{"type":"object","properties":{"workspace":{"type":"string"},"adapter":{"type":"string"},"allowNetwork":{"type":"boolean"}},"required":["workspace","adapter"],"additionalProperties":False}},
 {"name":"security_ingest","description":"Normalize an existing local JSON, JSON-lines, or SARIF report without executing any program.","inputSchema":{"type":"object","properties":{"report":{"type":"string"},"format":{"enum":["json","sarif"]},"adapter":{"type":"string"}},"required":["report","format"],"additionalProperties":False}},
 {"name":"security_start_run","description":"Create an in-memory, schema-owned scan lifecycle. Record only the user approvals supplied by the host; it does not execute or write anything.","inputSchema":{"type":"object","properties":{"workspace":{"type":"string"},"mode":{"enum":["scan","scan-ai","scan-agent"]},"consent":{"type":"object","properties":{"profileWrite":{"type":"boolean"},"network":{"type":"boolean"},"aiTriage":{"type":"boolean"},"agentReview":{"type":"boolean"}},"additionalProperties":False}},"required":["workspace","mode","consent"],"additionalProperties":False}},
 {"name":"security_record_run","description":"Append one completed scanner result, virtual preview, or skipped-scanner reason to a durable started scan lifecycle. It does not execute a process.","inputSchema":{"type":"object","properties":{"workspace":{"type":"string"},"runId":{"type":"string"},"kind":{"enum":["scanner","preview","skipped"]},"entry":{"type":"object"}},"required":["workspace","runId","kind","entry"],"additionalProperties":False}},
 {"name":"security_finalize_run","description":"Finalize a durable started scan lifecycle and store its schema-owned redacted Markdown report. The result is <workspace>/.mnogovid/code-scanner/<unixtime>/result.md.","inputSchema":{"type":"object","properties":{"workspace":{"type":"string"},"runId":{"type":"string"},"initialization":{"type":"object"},"doctor":{"type":"object"},"plan":{"type":"object"},"aiTriage":{"type":"object"},"agentReview":{"type":"object"}},"required":["workspace","runId"],"additionalProperties":False}},
 {"name":"security_advisory_lookup","description":"Query the OSV vulnerability advisory website for one package version. It makes an HTTPS request only when allowNetwork=true.","inputSchema":{"type":"object","properties":{"ecosystem":{"type":"string"},"package":{"type":"string"},"version":{"type":"string"},"allowNetwork":{"type":"boolean"}},"required":["ecosystem","package","version"],"additionalProperties":False}},
 {"name":"security_ai_triage_payload","description":"Prepare bounded, secret-redacted findings for host-model AI triage. It does not contact any model or website itself.","inputSchema":{"type":"object","properties":{"findings":{"type":"array"},"remediation":{"type":"boolean"}},"required":["findings"],"additionalProperties":False}},
]

def workspace(value: Any) -> Path:
    if not isinstance(value,str) or not value: raise ValueError("workspace must be a non-empty string")
    path=Path(value).expanduser().resolve()
    if not path.is_dir(): raise ValueError(f"workspace is not a directory: {path}")
    return path

def discover(root: Path) -> dict[str, Any]:
    manifests=[]; languages=set(); surfaces=set(); visited=0
    map_lang={".rs":"rust",".py":"python",".go":"go",".js":"javascript",".ts":"typescript",".java":"java",".rb":"ruby",".php":"php",".cs":"csharp",".cpp":"cpp",".c":"cpp"}
    markers={"Cargo.toml":"cargo","package.json":"npm","pnpm-lock.yaml":"pnpm","yarn.lock":"yarn","pyproject.toml":"pypi","requirements.txt":"pypi","go.mod":"go","Gemfile.lock":"rubygems","composer.lock":"composer","pom.xml":"maven","build.gradle":"gradle","packages.lock.json":"nuget"}
    for base,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in IGNORE]
        for name in files:
            visited+=1; path=Path(base,name); rel=str(path.relative_to(root))
            if name in markers: manifests.append({"path":rel,"ecosystem":markers[name]})
            if name.startswith("Dockerfile"): surfaces.add("containers")
            if path.suffix==".tf": surfaces.add("terraform")
            if any(x in rel.lower() for x in ("k8s/","kubernetes/","helm/")) and path.suffix in (".yml",".yaml"): surfaces.add("kubernetes")
            if path.suffix in map_lang: languages.add(map_lang[path.suffix])
    ecosystems=sorted({x["ecosystem"] for x in manifests})
    return {"workspacePath":str(root),"manifests":manifests,"ecosystems":ecosystems,"languages":sorted(languages),"surfaces":sorted(surfaces),"visitedEntries":visited}

def recommend(found: dict[str,Any]) -> list[str]:
    eco=set(found["ecosystems"]); lang=set(found["languages"]); surf=set(found["surfaces"]); out=["gitleaks"]
    if lang: out.append("semgrep")
    if "rust" in lang: out += ["cargo-audit","cargo-deny"]
    if "python" in lang: out += ["bandit","pip-audit"]
    if "go" in lang: out += ["gosec","govulncheck"]
    if "ruby" in lang: out += ["brakeman","bundler-audit"]
    if "npm" in eco or "pnpm" in eco or "yarn" in eco: out.append("npm-audit")
    if "composer" in eco: out.append("composer-audit")
    if surf: out += ["checkov","kics","trivy-fs"]
    if eco: out += ["osv-scanner","grype","syft"]
    return list(dict.fromkeys(out))

def plan(root: Path) -> dict[str,Any]:
    found=discover(root); ids=recommend(found)
    runs=[]
    for ident in ids:
        item=ADAPTERS[ident]; exe=shutil.which(item["exe"])
        runs.append({"adapter":ident,"category":item["category"],"executable":item["exe"],"available":bool(exe),"requiresNetwork":item["network"],"execution":"not_executed"})
    return {**found,"recommendedAdapters":ids,"runs":runs,"networkUsed":False,"processStarted":False}

def command(root: Path, ident: str) -> tuple[dict[str,Any],list[str],str]:
    if ident not in ADAPTERS: raise ValueError(f"unknown adapter: {ident}")
    spec=ADAPTERS[ident]; args=spec["cmd"](root); exe=shutil.which(spec["exe"])
    return spec, [exe or spec["exe"],*args], str(root if spec.get("cwd") else root)

def redact(value: Any) -> Any:
    if isinstance(value,dict): return {str(k):redact("[REDACTED]" if re.search(r"(token|secret|password|api.?key|private.?key)",str(k),re.I) else v) for k,v in value.items()}
    if isinstance(value,list): return [redact(v) for v in value]
    if isinstance(value,str) and re.search(r"(ghp_|sk-|AKIA|-----BEGIN)",value): return "[REDACTED]"
    return value

def markdown_cell(value: Any) -> str:
    if value is None: return "—"
    if isinstance(value,bool): return "yes" if value else "no"
    if isinstance(value,(dict,list)): return "See details below"
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")

def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    if not rows: return ["No data recorded.", ""]
    return [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        *["| " + " | ".join(markdown_cell(cell) for cell in row) + " |" for row in rows],
        "",
    ]

def markdown_value(title: str, value: Any, level: int = 2) -> list[str]:
    lines = ["#" * level + " " + title, ""]
    if isinstance(value,dict):
        scalars = [(str(key), item) for key,item in value.items() if not isinstance(item,(dict,list))]
        if scalars: lines += markdown_table(["Field","Value"], scalars)
        for key,item in value.items():
            if isinstance(item,(dict,list)): lines += markdown_value(str(key),item,level+1)
    elif isinstance(value,list) and all(isinstance(item,dict) for item in value):
        keys = list(dict.fromkeys(str(key) for item in value for key in item if not isinstance(item[key],(dict,list))))[:8]
        lines += markdown_table(keys, [[item.get(key) for key in keys] for item in value]) if keys else ["No scalar fields recorded.", ""]
    elif isinstance(value,list):
        lines += [f"- {markdown_cell(item)}" for item in value] or ["No data recorded."]
        lines.append("")
    else: lines += [markdown_cell(value), ""]
    return lines

def scanner_results(report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = report.get("scannerResults", report.get("results", []))
    return [item for item in candidates if isinstance(item,dict)] if isinstance(candidates,list) else []

def findings_from(report: dict[str, Any], runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = [item for item in report.get("findings",[]) if isinstance(item,dict)] if isinstance(report.get("findings"),list) else []
    for run in runs:
        for finding in run.get("findings",[]) if isinstance(run.get("findings"),list) else []:
            if isinstance(finding,dict): findings.append({"adapter":run.get("adapter"),**finding})
    return findings[:200]

def finding_value(finding: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = finding.get(name)
        if value not in (None,""): return value
    for container in ("package","dependency","artifact","component"):
        nested = finding.get(container)
        if isinstance(nested,dict):
            value = finding_value(nested,names)
            if value not in (None,""): return value
    return None

def finding_location_or_library(finding: dict[str, Any]) -> str:
    location = finding_value(finding,("location","path","file","uri"))
    line = finding_value(finding,("line","lineNumber","startLine"))
    library = finding_value(finding,("library","packageName","name","componentName"))
    parts = []
    if location: parts.append(f"{location}:{line}" if line else str(location))
    if library and str(library) != str(location): parts.append(str(library))
    return "; ".join(parts) if parts else "—"

def vulnerability_row(finding: dict[str, Any]) -> list[Any]:
    return [
        finding_value(finding,("vulnerability","ruleId","id","cve","advisory","title")),
        finding_value(finding,("severity","level","risk")),
        finding_value(finding,("affectedVersion","installedVersion","currentVersion","version")),
        finding_value(finding,("fixedVersion","fixedIn","fixVersion","fixed_version")),
        finding_location_or_library(finding),
    ]

def render_report(root: Path, mode: str, report_id: str, generated: str, report: dict[str, Any]) -> str:
    lines = ["# Mnogovid Security Report", "", "## Overview", ""]
    lines += markdown_table(["Field","Value"], [["Report ID",report_id],["Workspace",root],["Mode",mode],["Generated at",generated]])
    runs = scanner_results(report); findings = findings_from(report,runs)
    lines += ["## Scanner runs", ""]
    run_rows = []
    for run in runs:
        count = (run.get("counts") or {}).get("findings")
        if count is None: count = len(run.get("findings",[])) if isinstance(run.get("findings"),list) else 0
        run_rows.append([run.get("adapter"),run.get("resultStatus"),count,run.get("exitCode"),run.get("requiresNetwork")])
    lines += markdown_table(["Scanner","Status","Findings","Exit code","Network"],run_rows)
    if runs or findings:
        lines += ["## Results by scanner", ""]
        adapters = list(dict.fromkeys([str(run.get("adapter") or "unknown") for run in runs] + [str(item.get("adapter") or "unknown") for item in findings]))
        for adapter in adapters:
            scanner_findings = [item for item in findings if str(item.get("adapter") or "unknown") == adapter]
            lines += [f"### {adapter}", ""]
            rows = [vulnerability_row(item) for item in scanner_findings] or [["No vulnerabilities found.","—","—","—","—"]]
            lines += markdown_table(["Vulnerability","Severity","Affected version","Fixed version","Lines / libraries"],rows)
    if findings:
        severity: dict[str,int] = {}
        for item in findings:
            label = str(item.get("severity") or "UNKNOWN").upper().replace('"', "'")
            severity[label] = severity.get(label,0) + 1
        lines += ["## Findings by severity", "", "```mermaid", "pie showData", "    title Findings by severity"]
        lines += [f'    "{label}" : {count}' for label,count in sorted(severity.items())]
        lines += ["```", ""]
    else: lines += ["## Findings", "", "No findings were recorded.", ""]
    reserved = {"scannerResults","results","findings","hostAiTriage","agentReview"}
    for key,value in report.items():
        if key not in reserved: lines += markdown_value(str(key),value)
    if "hostAiTriage" in report: lines += markdown_value("Host AI triage",report["hostAiTriage"])
    if "agentReview" in report: lines += markdown_value("Independent agent review",report["agentReview"])
    return "\n".join(lines).rstrip() + "\n"

def write_report(root: Path, mode: str, report: dict[str, Any]) -> dict[str, Any]:
    reports = root / ".mnogovid"
    scanner_reports = reports / "code-scanner"
    if reports.exists() and reports.is_symlink(): raise ValueError("refusing to write reports through a symlinked .mnogovid directory")
    if scanner_reports.exists() and scanner_reports.is_symlink(): raise ValueError("refusing to write reports through a symlinked code-scanner directory")
    report_id = str(time.time_ns()); destination = scanner_reports / report_id / "result.md"
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    document = render_report(root,mode,report_id,generated,redact(report))
    truncated = len(document.encode("utf-8")) > MAX_OUTPUT
    if truncated: document = document.encode("utf-8")[:MAX_OUTPUT].decode("utf-8","ignore") + "\n\n_Report truncated at the storage limit._\n"
    destination.parent.mkdir(parents=True, exist_ok=False)
    destination.write_text(document,encoding="utf-8")
    return {"reportId":report_id,"path":str(destination),"redacted":True,"truncated":truncated}

def state_path(root: Path, run_id: Any) -> Path:
    if not isinstance(run_id,str) or not run_id.isdigit(): raise ValueError("runId must be a Unix timestamp")
    return root / ".mnogovid" / "code-scanner" / run_id / "run-state.json"

def save_run(root: Path, run_id: str, run: dict[str, Any]) -> None:
    path=state_path(root,run_id); path.parent.mkdir(parents=True,exist_ok=True)
    stored={**run,"workspace":str(root)}; temp=path.with_suffix(".tmp")
    temp.write_text(json.dumps(redact(stored),ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); temp.replace(path)

def started_run(root: Path, run_id: Any) -> dict[str, Any]:
    if isinstance(run_id,str) and run_id in RUNS: return RUNS[run_id]
    path=state_path(root,run_id)
    if not path.is_file(): raise ValueError("unknown or expired runId")
    run=json.loads(path.read_text(encoding="utf-8"))
    if run.get("workspace") != str(root): raise ValueError("runId belongs to a different workspace")
    RUNS[str(run_id)]=run; return run

def parse_report(value: Any, adapter: str|None=None) -> list[dict[str,Any]]:
    findings=[]
    if isinstance(value,dict) and isinstance(value.get("runs"),list):
        for run in value["runs"]:
            for result in run.get("results",[]) or []:
                loc=((result.get("locations") or [{}])[0].get("physicalLocation") or {})
                findings.append({"adapter":adapter,"ruleId":result.get("ruleId"),"severity":((result.get("level") or "unknown").upper()),"title":result.get("message",{}).get("text","") if isinstance(result.get("message"),dict) else "","location":loc.get("artifactLocation",{}).get("uri"),"line":(loc.get("region",{}) or {}).get("startLine")})
    elif isinstance(value,dict) and isinstance(value.get("results"),list):
        for result in value["results"][:200]: findings.append({"adapter":adapter,"ruleId":result.get("check_id") or result.get("rule_id"),"severity":result.get("extra",{}).get("severity") if isinstance(result.get("extra"),dict) else None,"title":result.get("extra",{}).get("message","") if isinstance(result.get("extra"),dict) else str(result)[:300],"location":result.get("path"),"line":result.get("start",{}).get("line") if isinstance(result.get("start"),dict) else None})
    elif isinstance(value,list):
        for item in value[:200]: findings.append({"adapter":adapter,"severity":item.get("Severity") or item.get("severity") if isinstance(item,dict) else "unknown","title":str(item)[:500]})
    return redact(findings)

def run_one(root:Path, ident:str, allow:bool, virtual:bool) -> dict[str,Any]:
    spec,argv,cwd=command(root,ident)
    result={"adapter":ident,"category":spec["category"],"workspacePath":str(root),"requiresNetwork":spec["network"],"networkRequested":allow,"networkEnforced":False,"command":{"argv":argv,"currentDir":cwd}}
    if virtual: return {**result,"execution":"virtual","processStarted":False,"resultStatus":"not_executed","findings":[]}
    if spec["network"] and not allow: raise ValueError(f"adapter '{ident}' requires network; set allowNetwork=true")
    if not shutil.which(spec["exe"]): raise ValueError(f"scanner executable not found on PATH: {spec['exe']}")
    completed=subprocess.run(argv,cwd=cwd,capture_output=True,text=True,timeout=300,check=False)
    text=(completed.stdout or "")[:MAX_OUTPUT]; err=(completed.stderr or "")[:MAX_OUTPUT]
    parsed=None
    try: parsed=json.loads(text)
    except json.JSONDecodeError:
        try: parsed=[json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
        except json.JSONDecodeError: pass
    findings=parse_report(parsed,ident) if parsed is not None else []
    secret=spec["category"]=="secrets"
    return {**result,"execution":"executed","processStarted":True,"resultStatus":"complete" if completed.returncode in (0,1) else "failed","exitCode":completed.returncode,"parsedJson":parsed is not None,"findings":findings,"counts":{"findings":len(findings)},"stdoutSnippet":"" if secret else redact(text[:4000]),"stderrSnippet":"" if secret else redact(err[:4000])}

def content(value:Any,error:bool=False)->dict[str,Any]: return {"isError":error,"content":[{"type":"text","text":json.dumps(value,ensure_ascii=False)}]}
def call(name:str,args:dict[str,Any])->dict[str,Any]:
    try:
        if name=="security_catalog": return content({"adapters":[{"id":k,"category":v["category"],"executable":v["exe"],"requiresNetwork":v["network"]} for k,v in ADAPTERS.items()],"webSources":["OSV","NVD","GitHub Advisory Database","vendor advisory databases"],"ai":"Use security_ai_triage_payload with the host model after explicit approval."})
        if name=="security_doctor":
            root=workspace(args.get("workspace")); data=plan(root); return content({**data,"missingExecutables":[r["executable"] for r in data["runs"] if not r["available"]]})
        if name=="security_plan": return content(plan(workspace(args.get("workspace"))))
        if name=="security_start_run":
            root=workspace(args.get("workspace")); mode=args.get("mode"); consent=args.get("consent")
            if mode not in ("scan","scan-ai","scan-agent") or not isinstance(consent,dict): raise ValueError("mode and consent are required")
            run_id=str(time.time_ns())
            RUNS[run_id]={"workspace":str(root),"mode":mode,"consent":redact(consent),"startedAt":datetime.now(timezone.utc).replace(microsecond=0).isoformat(),"scannerResults":[],"virtualCommands":[],"skippedScanners":[]}
            save_run(root,run_id,RUNS[run_id]); return content({"runId":run_id,"workspace":str(root),"statePath":str(state_path(root,run_id)),"mode":mode,"consent":RUNS[run_id]["consent"],"processStarted":False,"reportWritten":False})
        if name=="security_record_run":
            root=workspace(args.get("workspace")); run_id=args.get("runId"); run=started_run(root,run_id); kind=args.get("kind"); entry=args.get("entry")
            if kind not in ("scanner","preview","skipped") or not isinstance(entry,dict): raise ValueError("kind and entry are required")
            key={"scanner":"scannerResults","preview":"virtualCommands","skipped":"skippedScanners"}[kind]
            run[key].append(redact(entry)); save_run(root,str(run_id),run); return content({"runId":run_id,"recorded":kind,"count":len(run[key])})
        if name=="security_finalize_run":
            root=workspace(args.get("workspace")); run_id=args.get("runId"); run=started_run(root,run_id)
            report={"runId":run_id,"startedAt":run["startedAt"],"consent":run["consent"],"scannerResults":run["scannerResults"],"virtualCommands":run["virtualCommands"],"skippedScanners":run["skippedScanners"]}
            for key in ("initialization","doctor","plan","aiTriage","agentReview"):
                value=args.get(key)
                if value is not None:
                    if not isinstance(value,dict): raise ValueError(f"{key} must be an object")
                    report[key]=value
            result=write_report(root,run["mode"],report); state_path(root,run_id).unlink(); del RUNS[run_id]
            return content({**result,"runId":run_id,"finalized":True})
        if name in ("security_virtual_run","security_run"):
            root=workspace(args.get("workspace")); ident=args.get("adapter")
            if not isinstance(ident,str): raise ValueError("adapter must be a string")
            return content(run_one(root,ident,args.get("allowNetwork") is True,name=="security_virtual_run"))
        if name=="security_ingest":
            report=Path(str(args.get("report",""))).expanduser().resolve(); fmt=args.get("format")
            if not report.is_file() or fmt not in ("json","sarif"): raise ValueError("report must be an existing file and format must be json or sarif")
            raw=json.loads(report.read_text()); findings=parse_report(raw,args.get("adapter")); return content({"sourcePath":str(report),"format":fmt,"reportOnly":True,"findings":findings,"counts":{"findings":len(findings)}})
        if name=="security_advisory_lookup":
            if args.get("allowNetwork") is not True: raise ValueError("OSV lookup requires allowNetwork=true")
            ecosystem,package_name,version=(args.get("ecosystem"),args.get("package"),args.get("version"))
            if not all(isinstance(v,str) and v for v in (ecosystem,package_name,version)): raise ValueError("ecosystem, package, and version must be non-empty strings")
            body=json.dumps({"package":{"ecosystem":ecosystem,"name":package_name},"version":version}).encode()
            request=urllib.request.Request("https://api.osv.dev/v1/query",data=body,headers={"Content-Type":"application/json"},method="POST")
            try:
                with urllib.request.urlopen(request,timeout=15) as response: raw=json.loads(response.read().decode())
            except (urllib.error.URLError,TimeoutError,json.JSONDecodeError) as exc: raise ValueError(f"OSV advisory lookup failed: {exc}")
            vulns=raw.get("vulns",[]) if isinstance(raw,dict) else []
            return content({"source":"OSV","networkUsed":True,"package":{"ecosystem":ecosystem,"name":package_name,"version":version},"vulnerabilities":[{"id":v.get("id"),"summary":v.get("summary"),"modified":v.get("modified"),"aliases":v.get("aliases",[]),"references":v.get("references",[])} for v in vulns[:50]]})
        if name=="security_ai_triage_payload":
            items=redact(args.get("findings"));
            if not isinstance(items,list): raise ValueError("findings must be an array")
            return content({"mode":"remediation" if args.get("remediation") else "triage","findingLimit":min(len(items),40),"findings":items[:40],"instruction":"Classify each finding as true_positive, false_positive, or needs_review; cite only supplied evidence. Propose patches only when remediation was explicitly requested."})
        raise ValueError(f"unknown tool: {name}")
    except (ValueError,OSError,subprocess.TimeoutExpired) as exc: return content({"error":str(exc)},True)

def main()->int:
    for line in sys.stdin:
        try:
            req=json.loads(line); method=req.get("method"); rid=req.get("id")
            if method=="initialize": out={"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"mnogovid-security","version":"0.1.0"}}
            elif method=="tools/list": out={"tools":TOOLS}
            elif method=="tools/call": out=call(req.get("params",{}).get("name",""),req.get("params",{}).get("arguments",{}))
            elif rid is None: continue
            else: raise ValueError(f"method not found: {method}")
            print(json.dumps({"jsonrpc":"2.0","id":rid,"result":out},ensure_ascii=False),flush=True)
        except Exception as exc: print(json.dumps({"jsonrpc":"2.0","id":None,"error":{"code":-32603,"message":str(exc)}}),flush=True)
    return 0
if __name__=="__main__": raise SystemExit(main())
