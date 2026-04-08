"""
A4: DEPENDENCY AUDITOR — Supply Chain Security Agent

Identifies vulnerable, outdated, or malicious third-party dependencies.

Hybrid approach:
  1. Detects the package ecosystem from the recon report
  2. Runs ecosystem-specific audit tools (npm audit, pip-audit, etc.)
  3. Feeds raw tool output + recon context to the LLM
  4. LLM correlates vulnerabilities with actual codebase usage

Inputs:  recon_report.json + repo access
Outputs: findings_dependencies.json
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from agents.base import BaseAgent
from models.schemas import EngagementConfig
from utils.runners.base import BaseRunner, RunResult

logger = logging.getLogger("nomad.agents.deps")

PROMPT_FILE = Path(__file__).parent / "prompts" / "dependency_audit.md"


# ── Ecosystem Detection ──────────────────────────────────────────────────────

ECOSYSTEM_MARKERS = {
    "npm": ["package.json"],
    "pip": ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg"],
    "go": ["go.mod"],
    "cargo": ["Cargo.toml"],
    "maven": ["pom.xml"],
    "gradle": ["build.gradle", "build.gradle.kts"],
    "gem": ["Gemfile"],
    "composer": ["composer.json"],
    "nuget": ["*.csproj"],  # handled specially
}


def detect_ecosystems(repo_path: str) -> list[str]:
    """Detect which package ecosystems are present in the repo."""
    repo = Path(repo_path)
    found = []

    for eco, markers in ECOSYSTEM_MARKERS.items():
        for marker in markers:
            if marker.startswith("*"):
                # Glob pattern
                if list(repo.rglob(marker)):
                    found.append(eco)
                    break
            else:
                if (repo / marker).exists():
                    found.append(eco)
                    break

    return found


# ── Tool Runner Helpers ──────────────────────────────────────────────────────

class ToolResult:
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.available = False
        self.ran = False
        self.raw_output = ""
        self.findings_raw = 0
        self.error = ""
        self.parsed: list[dict] = []

    def to_dict(self) -> dict:
        return {
            "ran": self.ran,
            "available": self.available,
            "findings_raw": self.findings_raw,
            "findings_confirmed": 0,
            "findings_false_positive": 0,
            "error": self.error if not self.ran else "",
        }


def run_npm_audit(repo_path: str, timeout: int = 120) -> ToolResult:
    """Run npm audit on a Node.js project."""
    result = ToolResult("npm_audit")

    if not shutil.which("npm"):
        result.error = "npm not found in PATH"
        logger.warning(f"[npm_audit] {result.error}")
        return result

    result.available = True

    # Check for package-lock.json (required by npm audit)
    if not (Path(repo_path) / "package-lock.json").exists():
        result.error = "No package-lock.json found — npm audit requires a lockfile"
        logger.warning(f"[npm_audit] {result.error}")
        return result

    try:
        proc = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result.ran = True
        raw = proc.stdout.strip()
        result.raw_output = raw

        if raw:
            try:
                data = json.loads(raw)
                vulns = data.get("vulnerabilities", {})
                result.findings_raw = len(vulns)
                result.parsed = [
                    {"name": name, **info}
                    for name, info in vulns.items()
                ]
            except json.JSONDecodeError:
                result.raw_output = raw[:5000]

        logger.info(f"[npm_audit] Found {result.findings_raw} vulnerabilities")

    except subprocess.TimeoutExpired:
        result.error = f"Timed out after {timeout}s"
        logger.warning(f"[npm_audit] {result.error}")
    except Exception as e:
        result.error = str(e)
        logger.error(f"[npm_audit] Error: {e}")

    return result


def run_pip_audit(repo_path: str, timeout: int = 120) -> ToolResult:
    """Run pip-audit on a Python project."""
    result = ToolResult("pip_audit")

    if not shutil.which("pip-audit"):
        result.error = "pip-audit not found in PATH. Install: pipx install pip-audit"
        logger.warning(f"[pip_audit] {result.error}")
        return result

    result.available = True

    # Find requirements file
    req_file = None
    for candidate in ["requirements.txt", "requirements/base.txt", "requirements/prod.txt"]:
        if (Path(repo_path) / candidate).exists():
            req_file = candidate
            break

    args = ["pip-audit", "--format", "json", "--output", "-"]
    if req_file:
        args.extend(["-r", req_file])

    try:
        proc = subprocess.run(
            args,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result.ran = True
        raw = proc.stdout.strip()
        result.raw_output = raw

        if raw:
            try:
                data = json.loads(raw)
                deps = data.get("dependencies", [])
                vulns = [d for d in deps if d.get("vulns")]
                result.findings_raw = sum(len(d.get("vulns", [])) for d in vulns)
                result.parsed = vulns
            except json.JSONDecodeError:
                result.raw_output = raw[:5000]

        logger.info(f"[pip_audit] Found {result.findings_raw} vulnerabilities")

    except subprocess.TimeoutExpired:
        result.error = f"Timed out after {timeout}s"
        logger.warning(f"[pip_audit] {result.error}")
    except Exception as e:
        result.error = str(e)
        logger.error(f"[pip_audit] Error: {e}")

    return result


def run_cargo_audit(repo_path: str, timeout: int =1200) -> ToolResult:
    """Run cargo-audit on a Rust project."""
    result = ToolResult("cargo_audit")

    if not shutil.which("cargo-audit"):
        result.error = "cargo-audit not found. Install: cargo install cargo-audit"
        logger.warning(f"[cargo_audit] {result.error}")
        return result

    result.available = True

    try:
        proc = subprocess.run(
            ["cargo-audit", "audit", "--json"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result.ran = True
        raw = proc.stdout.strip()
        result.raw_output = raw

        if raw:
            try:
                data = json.loads(raw)
                vulns = data.get("vulnerabilities", {}).get("list", [])
                result.findings_raw = len(vulns)
                result.parsed = vulns
            except json.JSONDecodeError:
                result.raw_output = raw[:5000]

        logger.info(f"[cargo_audit] Found {result.findings_raw} vulnerabilities")

    except subprocess.TimeoutExpired:
        result.error = f"Timed out after {timeout}s"
    except Exception as e:
        result.error = str(e)
        logger.error(f"[cargo_audit] Error: {e}")

    return result


def run_osv_scanner(repo_path: str, timeout: int = 120) -> ToolResult:
    """Run osv-scanner (ecosystem-agnostic, covers Go, Maven, etc.)."""
    result = ToolResult("osv_scanner")

    if not shutil.which("osv-scanner"):
        result.error = "osv-scanner not found. Install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest"
        logger.warning(f"[osv_scanner] {result.error}")
        return result

    result.available = True

    try:
        proc = subprocess.run(
            ["osv-scanner", "--json", "-r", repo_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result.ran = True
        raw = proc.stdout.strip()
        result.raw_output = raw

        if raw:
            try:
                data = json.loads(raw)
                vulns = data.get("results", [])
                total = sum(len(r.get("packages", [{}])[0].get("vulnerabilities", []))
                           for r in vulns if r.get("packages"))
                result.findings_raw = total
                result.parsed = vulns
            except json.JSONDecodeError:
                result.raw_output = raw[:5000]

        logger.info(f"[osv_scanner] Found {result.findings_raw} vulnerabilities")

    except subprocess.TimeoutExpired:
        result.error = f"Timed out after {timeout}s"
    except Exception as e:
        result.error = str(e)
        logger.error(f"[osv_scanner] Error: {e}")

    return result


# Tool selection per ecosystem
ECOSYSTEM_TOOLS = {
    "npm": [run_npm_audit],
    "pip": [run_pip_audit],
    "cargo": [run_cargo_audit],
    "go": [run_osv_scanner],
    "maven": [run_osv_scanner],
    "gradle": [run_osv_scanner],
    "gem": [run_osv_scanner],
    "composer": [run_osv_scanner],
    "nuget": [run_osv_scanner],
}


def format_tool_results_for_prompt(tool_results: list[ToolResult], max_findings: int = 40) -> str:
    """Format all tool results for LLM prompt injection."""
    sections = []

    for tr in tool_results:
        if not tr.ran:
            if tr.error:
                sections.append(f"**{tr.tool_name}**: Not available — {tr.error}")
            continue

        if tr.findings_raw == 0:
            sections.append(f"**{tr.tool_name}**: Ran successfully, 0 vulnerabilities found.")
            continue

        lines = [f"**{tr.tool_name}**: {tr.findings_raw} raw findings:\n"]

        for i, f in enumerate(tr.parsed[:max_findings]):
            # Format depends on tool
            if tr.tool_name == "npm_audit":
                name = f.get("name", "unknown")
                severity = f.get("severity", "unknown")
                via = f.get("via", [])
                # 'via' can be strings or objects
                cves = []
                for v in via:
                    if isinstance(v, dict):
                        url = v.get("url", "")
                        cves.append(url)
                    elif isinstance(v, str):
                        cves.append(v)
                fix = f.get("fixAvailable", "unknown")
                lines.append(f"  [{i+1}] {name} | severity={severity} | fix={fix} | refs={', '.join(cves[:3])}")

            elif tr.tool_name == "pip_audit":
                name = f.get("name", "unknown")
                version = f.get("version", "?")
                for vuln in f.get("vulns", []):
                    vid = vuln.get("id", "?")
                    fix_vers = ", ".join(vuln.get("fix_versions", []))
                    lines.append(f"  [{i+1}] {name}@{version} | {vid} | fix={fix_vers}")

            else:
                # Generic format for osv-scanner, cargo-audit, etc.
                lines.append(f"  [{i+1}] {json.dumps(f)[:200]}")

        if tr.findings_raw > max_findings:
            lines.append(f"  ... and {tr.findings_raw - max_findings} more")

        sections.append("\n".join(lines))

    return "\n\n".join(sections) if sections else "No audit tools were available."


# ── A4 Agent ─────────────────────────────────────────────────────────────────

class DependencyAuditAgent(BaseAgent):
    name = "a4_deps"
    description = "Dependency auditing — identifies vulnerable and outdated third-party packages"
    tools = "read_only"
    max_turns = 40
    timeout = 600

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        super().__init__(config, output_dir, runner)
        self.tool_results: list[ToolResult] = []
        self.ecosystems: list[str] = []

    def run(self, context: Optional[dict] = None) -> 'AgentRun':
        """Override to run audit tools before LLM."""
        if context is None:
            context = {}

        recon = context.get("recon_report", {})

        # Detect ecosystems
        self.ecosystems = detect_ecosystems(self.config.repo_path)
        if not self.ecosystems:
            # Fallback: try to infer from recon tech_stack
            ts = recon.get("tech_stack", {})
            pkg_mgr = ts.get("package_manager", "").lower()
            if pkg_mgr in ECOSYSTEM_TOOLS:
                self.ecosystems = [pkg_mgr]
            elif any("node" in r.lower() or "express" in r.lower() or "react" in r.lower()
                     for r in ts.get("frameworks", []) + ts.get("languages", [])):
                self.ecosystems = ["npm"]
            elif "python" in " ".join(ts.get("languages", [])).lower():
                self.ecosystems = ["pip"]

        logger.info(f"[a4_deps] Detected ecosystems: {self.ecosystems or ['none detected']}")

        # Run appropriate audit tools
        logger.info("[a4_deps] Running dependency audit tools...")
        for eco in self.ecosystems:
            tool_funcs = ECOSYSTEM_TOOLS.get(eco, [run_osv_scanner])
            for tool_func in tool_funcs:
                result = tool_func(self.config.repo_path)
                self.tool_results.append(result)

        # If no ecosystem-specific tools ran, try osv-scanner as fallback
        if not any(tr.ran for tr in self.tool_results):
            if not any(tr.tool_name == "osv_scanner" for tr in self.tool_results):
                logger.info("[a4_deps] Trying osv-scanner as fallback...")
                osv = run_osv_scanner(self.config.repo_path)
                self.tool_results.append(osv)

        tools_ran = [f"{tr.tool_name} ({tr.findings_raw} raw)" for tr in self.tool_results if tr.ran]
        if tools_ran:
            logger.info(f"[a4_deps] Tools completed: {', '.join(tools_ran)}")
        else:
            logger.warning("[a4_deps] No audit tools available — LLM-only mode")

        return super().run(context)

    def get_system_prompt(self) -> str:
        return PROMPT_FILE.read_text()

    def get_task_prompt(self, context: Optional[dict] = None) -> str:
        if context is None:
            context = {}

        recon = context.get("recon_report", {})
        sections = []

        # Recon context
        sections.append(self._build_recon_context(recon))

        # Ecosystem info
        sections.append(f"## DETECTED ECOSYSTEMS\n\n{', '.join(self.ecosystems) or 'None detected — review manifest files manually'}")

        # Tool results
        tool_output = format_tool_results_for_prompt(self.tool_results)
        sections.append(f"## AUDIT TOOL RESULTS\n\n{tool_output}")

        # Task
        sections.append(
            "## YOUR TASK\n\n"
            "1. Read the manifest and lockfiles to understand all dependencies.\n"
            "2. Validate each tool finding — confirm the package and version are actually installed.\n"
            "3. For each vulnerability, check if the vulnerable code path is actually used in this application.\n"
            "4. Check for outdated, unmaintained, or deprecated packages beyond what CVE databases report.\n"
            "5. Assess the version pinning strategy and lockfile hygiene.\n\n"
            "Respond with ONLY the JSON object as specified in your instructions.\n"
            "No markdown, no prose — just valid JSON starting with { and ending with }."
        )

        return "\n\n".join(sections)

    def _build_recon_context(self, recon: dict) -> str:
        """Build relevant recon context for dependency analysis."""
        parts = ["## RECON CONTEXT\n"]

        ts = recon.get("tech_stack", {})
        if ts:
            parts.append(f"**Languages:** {', '.join(ts.get('languages', []))}")
            parts.append(f"**Frameworks:** {', '.join(ts.get('frameworks', []))}")
            parts.append(f"**Databases:** {', '.join(ts.get('databases', []))}")
            parts.append(f"**Package manager:** {ts.get('package_manager', 'unknown')}")

        tpi = recon.get("third_party_integrations", [])
        if tpi:
            parts.append("**Third-party integrations:**")
            for t in tpi:
                sdk = t.get("sdk", "")
                parts.append(f"  - {t.get('service', '?')}: {sdk}")

        return "\n".join(parts)

    def parse_output(self, result: RunResult) -> Optional[dict]:
        data = result.parsed_json

        if data is None:
            logger.error("No JSON could be extracted from dependency audit output")
            return None

        if not isinstance(data, dict):
            logger.error(f"Expected dict, got {type(data).__name__}")
            return None

        # Ensure findings key
        if "findings" not in data:
            for alt in ("vulnerabilities", "dependencies", "issues", "results"):
                if alt in data and isinstance(data[alt], list):
                    data["findings"] = data.pop(alt)
                    break
            else:
                data["findings"] = []

        data["findings"] = self._validate_findings(data.get("findings", []))
        data["tool_results"] = self._build_tool_results(data.get("tool_results", {}))
        data.setdefault("dependency_overview", {})
        data["summary"] = self._build_summary(data["findings"], data.get("summary", {}))

        count = len(data["findings"])
        by_sev = data["summary"].get("by_severity", {})
        logger.info(
            f"Dependency audit complete: {count} findings "
            f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
            f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)})"
        )

        return data

    def _validate_findings(self, findings: list) -> list:
        """Validate and normalize dependency findings."""
        valid = []
        seen_ids = set()

        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                continue
            if not f.get("title") and not f.get("package_name"):
                continue

            fid = f.get("id", "")
            if not fid or fid in seen_ids:
                fid = f"DEP-{i + 1:03d}"
            seen_ids.add(fid)

            severity = f.get("severity", "medium").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

            confidence = f.get("confidence", "medium").lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"

            cwe_id = f.get("cwe_id", 0)
            if isinstance(cwe_id, str):
                cwe_id = int(cwe_id.replace("CWE-", "").replace("cwe-", "")) if cwe_id.replace("CWE-", "").replace("cwe-", "").isdigit() else 0

            cvss = f.get("cvss_score", 0.0)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 0.0

            valid.append({
                "id": fid,
                "title": f.get("title", f"Vulnerability in {f.get('package_name', 'unknown')}"),
                "package_name": f.get("package_name", ""),
                "package_version": f.get("package_version", ""),
                "ecosystem": f.get("ecosystem", ""),
                "is_direct": f.get("is_direct", True),
                "severity": severity,
                "confidence": confidence,
                "cve_ids": f.get("cve_ids", []),
                "cvss_score": cvss,
                "cvss_vector": f.get("cvss_vector", ""),
                "cwe_id": cwe_id,
                "cwe_name": f.get("cwe_name", ""),
                "vulnerable_range": f.get("vulnerable_range", ""),
                "fix_version": f.get("fix_version", ""),
                "transitive_chain": f.get("transitive_chain", ""),
                "usage_in_codebase": f.get("usage_in_codebase", ""),
                "description": f.get("description", ""),
                "remediation": f.get("remediation", ""),
                "detection_source": f.get("detection_source", "manual"),
            })

        return valid

    def _build_tool_results(self, llm_results: dict) -> dict:
        """Build tool_results from actual tool runs."""
        results = {}
        for tr in self.tool_results:
            llm_tr = llm_results.get(tr.tool_name, {})
            results[tr.tool_name] = {
                "ran": tr.ran,
                "available": tr.available,
                "findings_raw": tr.findings_raw,
                "findings_confirmed": llm_tr.get("findings_confirmed", 0),
                "findings_false_positive": llm_tr.get("findings_false_positive", 0),
                "error": tr.error,
            }
        return results

    def _build_summary(self, findings: list, existing: dict) -> dict:
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        files = set()

        for f in findings:
            by_severity[f.get("severity", "medium")] = by_severity.get(f.get("severity", "medium"), 0) + 1

        existing_files = existing.get("files_analyzed", [])
        if isinstance(existing_files, list):
            files.update(existing_files)

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "packages_analyzed": existing.get("packages_analyzed", 0),
            "files_analyzed": sorted(files),
            "scope_notes": existing.get("scope_notes", f"Dependency audit for: {', '.join(self.ecosystems)}"),
        }

    def _count_findings(self, parsed: dict) -> int:
        return len(parsed.get("findings", []))
