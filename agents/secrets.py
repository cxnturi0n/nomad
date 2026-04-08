"""
A3: SECRETS SCANNER — Hybrid Tool + LLM Agent

Detects hardcoded secrets, leaked credentials, API keys, tokens,
and sensitive data in source code.

Hybrid approach:
  1. Runs TruffleHog (entropy + pattern detection) as a subprocess
  2. Runs Semgrep (AST-aware pattern matching) as a subprocess
  3. Feeds raw tool output + recon context to the LLM
  4. LLM validates, deduplicates, enriches, and contextualizes findings

Inputs:  recon_report.json + repo access
Outputs: findings_secrets.json
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

logger = logging.getLogger("nomad.agents.secrets")

PROMPT_FILE = Path(__file__).parent / "prompts" / "secrets.md"


# ── Tool Runner Helpers ──────────────────────────────────────────────────────

class ToolResult:
    """Result from a CLI security tool."""
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.available = False
        self.ran = False
        self.raw_output = ""
        self.findings_raw = 0
        self.error = ""
        self.parsed: list[dict] = []

    def to_summary(self) -> dict:
        return {
            "ran": self.ran,
            "available": self.available,
            "findings_raw": self.findings_raw,
            "findings_confirmed": 0,  # filled later by LLM
            "findings_false_positive": 0,
            "error": self.error if not self.ran else "",
        }


def run_trufflehog(repo_path: str, timeout: int = 120) -> ToolResult:
    """Run TruffleHog v3 on the repository."""
    result = ToolResult("trufflehog")

    if not shutil.which("trufflehog"):
        result.error = "trufflehog not found in PATH. Install: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh"
        logger.warning(f"[trufflehog] {result.error}")
        return result

    result.available = True

    try:
        proc = subprocess.run(
            [
                "trufflehog", "filesystem",
                repo_path,
                "--json",
                "--no-update",
                "--only-verified",  # include unverified too
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result.ran = True
        raw = proc.stdout.strip()
        result.raw_output = raw

        # TruffleHog outputs one JSON object per line (JSONL)
        if raw:
            for line in raw.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    result.parsed.append(finding)
                except json.JSONDecodeError:
                    continue

        result.findings_raw = len(result.parsed)
        logger.info(f"[trufflehog] Found {result.findings_raw} raw findings")

        if proc.stderr.strip():
            logger.debug(f"[trufflehog] stderr: {proc.stderr.strip()[:500]}")

    except subprocess.TimeoutExpired:
        result.error = f"Timed out after {timeout}s"
        logger.warning(f"[trufflehog] {result.error}")
    except Exception as e:
        result.error = str(e)
        logger.error(f"[trufflehog] Error: {e}")

    return result


def run_semgrep(repo_path: str, timeout: int = 300) -> ToolResult:
    """Run Semgrep with comprehensive security rulesets."""
    result = ToolResult("semgrep")

    if not shutil.which("semgrep"):
        result.error = "semgrep not found in PATH. Install: pip install semgrep"
        logger.warning(f"[semgrep] {result.error}")
        return result

    result.available = True

    try:
        proc = subprocess.run(
            [
                "semgrep", "scan",
                "--config", "p/secrets",
                "--config", "p/security-audit",
                "--config", "p/owasp-top-ten",
                "--config", "p/command-injection",
                "--config", "p/sql-injection",
                "--config", "p/xss",
                "--config", "p/insecure-transport",
                "--config", "p/jwt",
                "--config", "p/default",
                "--json",
                "--quiet",
                "--no-git-ignore",  # scan everything
                "--timeout", "30",  # per-rule timeout
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result.ran = True
        raw = proc.stdout.strip()
        result.raw_output = raw

        # Semgrep outputs a single JSON object with a "results" array
        if raw:
            try:
                data = json.loads(raw)
                findings = data.get("results", [])
                result.parsed = findings
                result.findings_raw = len(findings)
            except json.JSONDecodeError:
                logger.warning("[semgrep] Could not parse JSON output")
                result.raw_output = raw[:5000]  # truncate for prompt injection

        logger.info(f"[semgrep] Found {result.findings_raw} raw findings")

        if proc.returncode not in (0, 1):  # 1 = findings found (normal)
            stderr = proc.stderr.strip()
            if stderr:
                logger.debug(f"[semgrep] stderr: {stderr[:500]}")

    except subprocess.TimeoutExpired:
        result.error = f"Timed out after {timeout}s"
        logger.warning(f"[semgrep] {result.error}")
    except Exception as e:
        result.error = str(e)
        logger.error(f"[semgrep] Error: {e}")

    return result


def format_trufflehog_for_prompt(findings: list[dict], max_findings: int = 30) -> str:
    """Format TruffleHog findings for LLM prompt injection."""
    if not findings:
        return "No findings from TruffleHog."

    lines = [f"TruffleHog found {len(findings)} raw results:\n"]
    for i, f in enumerate(findings[:max_findings]):
        source = f.get("SourceMetadata", {}).get("Data", {})
        # Try filesystem metadata first
        fs = source.get("Filesystem", {})
        file_path = fs.get("file", "unknown")
        line = fs.get("line", "?")

        detector = f.get("DetectorName", f.get("DetectorType", "unknown"))
        verified = f.get("Verified", False)
        raw_val = f.get("Raw", "")
        # Redact the secret for the prompt
        preview = raw_val[:8] + "...REDACTED" if len(raw_val) > 8 else "REDACTED"

        lines.append(
            f"  [{i+1}] Detector={detector} | File={file_path}:{line} | "
            f"Verified={verified} | Preview={preview}"
        )

    if len(findings) > max_findings:
        lines.append(f"  ... and {len(findings) - max_findings} more")

    return "\n".join(lines)


def format_semgrep_for_prompt(findings: list[dict], max_findings: int = 30) -> str:
    """Format Semgrep findings for LLM prompt injection."""
    if not findings:
        return "No findings from Semgrep."

    lines = [f"Semgrep found {len(findings)} raw results:\n"]
    for i, f in enumerate(findings[:max_findings]):
        rule_id = f.get("check_id", "unknown")
        path = f.get("path", "unknown")
        start_line = f.get("start", {}).get("line", "?")
        end_line = f.get("end", {}).get("line", "?")
        message = f.get("extra", {}).get("message", "")[:200]
        severity = f.get("extra", {}).get("severity", "unknown")
        # Get the matched code, redact if it looks like a secret
        matched = f.get("extra", {}).get("lines", "")[:150]

        lines.append(
            f"  [{i+1}] Rule={rule_id} | {path}:{start_line}-{end_line} | "
            f"Severity={severity}\n"
            f"       Message: {message}\n"
            f"       Code: {matched}"
        )

    if len(findings) > max_findings:
        lines.append(f"  ... and {len(findings) - max_findings} more")

    return "\n".join(lines)


# ── A3 Agent ─────────────────────────────────────────────────────────────────

class SecretsAgent(BaseAgent):
    name = "a3_secrets"
    description = "Secrets scanning — detects hardcoded credentials, API keys, tokens"
    tools = "read_only"
    max_turns = 50
    timeout = 600

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        super().__init__(config, output_dir, runner)
        self.trufflehog_result: Optional[ToolResult] = None
        self.semgrep_result: Optional[ToolResult] = None

    def run(self, context: Optional[dict] = None) -> 'AgentRun':
        """
        Override base run to inject tool results before calling the LLM.
        """
        # Phase 1: Run CLI tools BEFORE the LLM
        logger.info("[a3_secrets] Running pre-scan tools...")

        self.trufflehog_result = run_trufflehog(self.config.repo_path)
        self.semgrep_result = run_semgrep(self.config.repo_path)

        tools_ran = []
        if self.trufflehog_result.ran:
            tools_ran.append(f"trufflehog ({self.trufflehog_result.findings_raw} raw)")
        if self.semgrep_result.ran:
            tools_ran.append(f"semgrep ({self.semgrep_result.findings_raw} raw)")

        if tools_ran:
            logger.info(f"[a3_secrets] Tools completed: {', '.join(tools_ran)}")
        else:
            logger.warning("[a3_secrets] No scanning tools available — LLM-only mode")

        # Phase 2: Run the LLM agent with tool results in context
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

        # Tool results
        if self.trufflehog_result:
            sections.append("## TRUFFLEHOG RESULTS\n\n" +
                          format_trufflehog_for_prompt(self.trufflehog_result.parsed))
            if self.trufflehog_result.error:
                sections.append(f"TruffleHog error: {self.trufflehog_result.error}")

        if self.semgrep_result:
            sections.append("## SEMGREP RESULTS\n\n" +
                          format_semgrep_for_prompt(self.semgrep_result.parsed))
            if self.semgrep_result.error:
                sections.append(f"Semgrep error: {self.semgrep_result.error}")

        if not (self.trufflehog_result and self.trufflehog_result.ran) and \
           not (self.semgrep_result and self.semgrep_result.ran):
            sections.append(
                "## NO TOOL OUTPUT AVAILABLE\n\n"
                "Neither TruffleHog nor Semgrep were available. "
                "Perform a thorough manual scan of ALL files for hardcoded secrets, "
                "API keys, tokens, passwords, private keys, and connection strings."
            )

        # Task
        sections.append(
            "## YOUR TASK\n\n"
            "1. Validate each tool finding by reading the actual source file.\n"
            "2. Mark false positives (test data, placeholders, documentation examples).\n"
            "3. Manually scan configuration files, environment files, and source code for secrets the tools may have missed.\n"
            "4. For each confirmed secret, classify its type, service, severity, and assess if it's likely active.\n"
            "5. Provide remediation for every confirmed finding.\n\n"
            "Respond with ONLY the JSON object as specified in your instructions.\n"
            "No markdown, no prose — just valid JSON starting with { and ending with }."
        )

        return "\n\n".join(sections)

    def _build_recon_context(self, recon: dict) -> str:
        """Build relevant recon context for secrets scanning."""
        parts = ["## RECON CONTEXT\n"]

        ts = recon.get("tech_stack", {})
        if ts:
            parts.append(f"**Tech:** {', '.join(ts.get('languages', []))} | "
                        f"{', '.join(ts.get('frameworks', []))}")

        # Critical config files
        cf = recon.get("critical_files", {})
        if isinstance(cf, dict):
            config_files = cf.get("config", [])
            if config_files:
                parts.append(f"**Config files:** {', '.join(config_files)}")

        # Third party integrations (likely need API keys)
        tpi = recon.get("third_party_integrations", [])
        if tpi:
            services = [t.get("service", "?") for t in tpi]
            parts.append(f"**Third-party services (check for leaked keys):** {', '.join(services)}")

        # Security observations about secrets
        obs = recon.get("security_observations", [])
        secret_obs = [o for o in obs if any(kw in o.lower() for kw in
                     ("credential", "secret", "password", "key", "token", "hardcoded", "plaintext"))]
        if secret_obs:
            parts.append("**Recon observations related to secrets:**")
            for o in secret_obs:
                parts.append(f"  - {o}")

        return "\n".join(parts)

    def parse_output(self, result: RunResult) -> Optional[dict]:
        data = result.parsed_json

        if data is None:
            logger.error("No JSON could be extracted from secrets scanner output")
            return None

        if not isinstance(data, dict):
            logger.error(f"Expected dict, got {type(data).__name__}")
            return None

        # Ensure findings key exists
        if "findings" not in data:
            for alt in ("secrets", "results", "issues"):
                if alt in data and isinstance(data[alt], list):
                    data["findings"] = data.pop(alt)
                    break
            else:
                data["findings"] = []

        # Validate findings
        data["findings"] = self._validate_findings(data.get("findings", []))

        # Inject actual tool results into tool_results section
        data["tool_results"] = self._build_tool_results(data.get("tool_results", {}))

        # Build/fix summary
        data["summary"] = self._build_summary(data["findings"], data.get("summary", {}))

        count = len(data["findings"])
        by_sev = data["summary"].get("by_severity", {})
        logger.info(
            f"Secrets scan complete: {count} findings "
            f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
            f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)})"
        )

        return data

    def _validate_findings(self, findings: list) -> list:
        """Validate and normalize each secret finding."""
        valid = []
        seen_ids = set()

        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                continue
            if not f.get("title") and not f.get("description"):
                continue

            fid = f.get("id", "")
            if not fid or fid in seen_ids:
                fid = f"SEC-{i + 1:03d}"
            seen_ids.add(fid)

            severity = f.get("severity", "medium").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

            confidence = f.get("confidence", "medium").lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"

            cwe_id = f.get("cwe_id", 798)
            if isinstance(cwe_id, str):
                cwe_id = int(cwe_id.replace("CWE-", "").replace("cwe-", "")) if cwe_id.replace("CWE-", "").replace("cwe-", "").isdigit() else 798

            valid.append({
                "id": fid,
                "title": f.get("title", "Untitled secret finding"),
                "type": f.get("type", "unknown"),
                "service": f.get("service", "unknown"),
                "severity": severity,
                "confidence": confidence,
                "file": f.get("file", ""),
                "line_start": f.get("line_start", f.get("line", None)),
                "line_end": f.get("line_end", f.get("line", None)),
                "secret_preview": f.get("secret_preview", "REDACTED"),
                "full_context": f.get("full_context", ""),
                "description": f.get("description", ""),
                "active": f.get("active", "unknown"),
                "scope": f.get("scope", "unknown"),
                "detection_source": f.get("detection_source", "manual"),
                "remediation": f.get("remediation", ""),
                "cwe_id": cwe_id,
                "cwe_name": f.get("cwe_name", "Use of Hard-coded Credentials"),
            })

        return valid

    def _build_tool_results(self, llm_tool_results: dict) -> dict:
        """Build tool_results from actual tool runs, merging LLM's confirmation counts."""
        results = {}

        if self.trufflehog_result:
            tr = self.trufflehog_result
            llm_tr = llm_tool_results.get("trufflehog", {})
            results["trufflehog"] = {
                "ran": tr.ran,
                "available": tr.available,
                "findings_raw": tr.findings_raw,
                "findings_confirmed": llm_tr.get("findings_confirmed", 0),
                "findings_false_positive": llm_tr.get("findings_false_positive", 0),
                "error": tr.error,
            }
        else:
            results["trufflehog"] = {"ran": False, "available": False, "findings_raw": 0}

        if self.semgrep_result:
            sr = self.semgrep_result
            llm_sr = llm_tool_results.get("semgrep", {})
            results["semgrep"] = {
                "ran": sr.ran,
                "available": sr.available,
                "findings_raw": sr.findings_raw,
                "findings_confirmed": llm_sr.get("findings_confirmed", 0),
                "findings_false_positive": llm_sr.get("findings_false_positive", 0),
                "error": sr.error,
            }
        else:
            results["semgrep"] = {"ran": False, "available": False, "findings_raw": 0}

        return results

    def _build_summary(self, findings: list, existing: dict) -> dict:
        """Build consistent summary from actual findings."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_type = {}
        by_service = {}
        files = set()

        for f in findings:
            sev = f.get("severity", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1

            sec_type = f.get("type", "unknown")
            by_type[sec_type] = by_type.get(sec_type, 0) + 1

            service = f.get("service", "unknown")
            by_service[service] = by_service.get(service, 0) + 1

            if f.get("file"):
                files.add(f["file"])

        existing_files = existing.get("files_analyzed", [])
        if isinstance(existing_files, list):
            files.update(existing_files)

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "by_service": by_service,
            "files_analyzed": sorted(files),
            "scope_notes": existing.get("scope_notes", "Secrets scan with tool-assisted and manual review"),
        }

    def _count_findings(self, parsed: dict) -> int:
        return len(parsed.get("findings", []))