"""
A2: STATIC ANALYSIS — Vulnerability Hunter Agent

The core bug-finding agent. Reads source code against the recon map
and hunts for security vulnerabilities across all OWASP categories.

Inputs:  recon_report.json + repo access
Outputs: findings_static.json

Supports scoped execution — the orchestrator can run multiple instances
of this agent, each scoped to a different module or vulnerability class.
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

logger = logging.getLogger("nomad.agents.static_analysis")

PROMPT_FILE = Path(__file__).parent / "prompts" / "static_analysis.md"

# Semgrep SAST is run once per repo and cached (A2 may instantiate per-partition).
_SEMGREP_SAST_CACHE: dict[str, list] = {}

_SAST_CONFIGS = [
    "p/security-audit", "p/owasp-top-ten", "p/command-injection",
    "p/sql-injection", "p/xss", "p/insecure-transport", "p/default",
]

# JSON Schema for `claude --json-schema` (structured output pilot). Shaped to the
# CLI's strict semantics — every property listed in `required`, additionalProperties
# false — but kept non-lossy: fields the model can't fill get "" / null / [] rather
# than forcing it to drop the finding, and a free-text `notes` acts as an escape
# hatch for anything that doesn't fit a field. parse_output() normalizes the rest
# (cwe string→int, bad enums→medium), so this only guarantees SHAPE, not values.
STATIC_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings", "summary"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "title", "cwe_id", "cwe_name", "severity", "confidence",
                    "file", "line_start", "line_end", "code_snippet",
                    "description", "attack_scenario", "remediation",
                    "references", "notes",
                ],
                "properties": {
                    "title": {"type": "string"},
                    "cwe_id": {"type": "string"},          # "CWE-89" or "" — parser coerces to int
                    "cwe_name": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "file": {"type": "string"},
                    "line_start": {"type": ["integer", "null"]},
                    "line_end": {"type": ["integer", "null"]},
                    "code_snippet": {"type": "string"},
                    "description": {"type": "string"},
                    "attack_scenario": {"type": "string"},
                    "remediation": {"type": "string"},
                    "references": {"type": "array", "items": {"type": "string"}},
                    "notes": {"type": "string"},           # escape hatch for anything off-schema
                },
            },
        },
        "summary": {
            "type": "object",
            "additionalProperties": False,
            "required": ["files_analyzed", "scope_notes"],
            "properties": {
                "files_analyzed": {"type": "array", "items": {"type": "string"}},
                "scope_notes": {"type": "string"},
            },
        },
    },
}


def run_semgrep_sast(repo_path: str, timeout: int = 300) -> list:
    """Run Semgrep SAST rulesets once; return raw results (or [] if unavailable)."""
    if not shutil.which("semgrep"):
        logger.info("[a2_static] semgrep not installed — skipping SAST pre-scan")
        return []
    cmd = ["semgrep", "scan"]
    for c in _SAST_CONFIGS:
        cmd += ["--config", c]
    cmd += ["--json", "--quiet", "--no-git-ignore", "--timeout", "30", repo_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = proc.stdout.strip()
        if not raw:
            return []
        findings = json.loads(raw).get("results", [])
        logger.info(f"[a2_static] semgrep SAST pre-scan: {len(findings)} raw findings")
        return findings
    except subprocess.TimeoutExpired:
        logger.warning(f"[a2_static] semgrep SAST timed out after {timeout}s")
        return []
    except Exception as e:
        logger.warning(f"[a2_static] semgrep SAST failed: {e}")
        return []


class StaticAnalysisAgent(BaseAgent):
    name = "a2_static_analysis"
    description = "Static source code analysis — hunts for security vulnerabilities"
    tools = "read_only"
    max_turns = 75  # may need many turns for thorough analysis
    timeout = 6000   # 100 min — deep analysis of large modules can take a long time
    output_schema = STATIC_OUTPUT_SCHEMA  # pilot agent for --structured-output

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner,
                 scope_name: str = "full"):
        super().__init__(config, output_dir, runner)
        self.scope_name = scope_name
        # Override name for scoped runs so output files don't collide
        if scope_name != "full":
            self.name = f"a2_static_{scope_name}"

    def get_system_prompt(self) -> str:
        return PROMPT_FILE.read_text()

    def get_task_prompt(self, context: Optional[dict] = None) -> str:
        if context is None:
            context = {}

        recon = context.get("recon_report", {})
        partition = context.get("partition", {})
        max_findings = context.get("max_findings", 25)

        # Build a focused context injection from the recon report
        recon_summary = self._build_recon_context(recon, partition)
        semgrep_section = self._build_semgrep_context(partition)

        prompt = f"""Perform a security-focused static analysis of the source code in the current working directory.

## RECON CONTEXT (from the reconnaissance agent)

{recon_summary}
{semgrep_section}
## YOUR TASK

1. Read the source files listed in the recon context above, starting with the highest-risk ones.
2. For each entry point and data flow, trace user input from source to sink.
3. Check every vulnerability class from your checklist.
4. Report only confirmed vulnerabilities you can back with actual code.

## OUTPUT CONSTRAINTS

- Report a MAXIMUM of {max_findings} findings, strictly prioritized by severity (critical first, then high, then medium, then low).
- If you find more than {max_findings}, report ONLY the top {max_findings}.
- Keep code_snippet to 1-2 lines maximum — the relevant line only.
- Keep description under 100 words.
- Keep remediation under 80 words — show the fix pattern ONCE, do not repeat for every instance.
- Keep attack_scenario under 60 words.
- If the SAME vulnerability pattern appears in multiple files, report it ONCE and list all affected files in the description.

Respond with ONLY the JSON object as specified in your instructions.
No markdown, no prose — just valid JSON starting with {{ and ending with }}."""

        return prompt

    def _build_recon_context(self, recon: dict, partition: dict) -> str:
        """
        Build a focused summary of the recon report for injection into the task prompt.
        If a partition is provided, filter to only that scope.
        """
        sections = []

        # Tech stack
        ts = recon.get("tech_stack", {})
        if ts:
            langs = ", ".join(ts.get("languages", []))
            fws = ", ".join(ts.get("frameworks", []))
            dbs = ", ".join(ts.get("databases", []))
            sections.append(f"**Tech Stack:** {langs} | {fws} | {dbs}")

        # Entry points — these are the primary attack surface
        eps = recon.get("entry_points", [])
        if partition and partition.get("paths"):
            # Filter entry points to this partition's scope
            scope_paths = partition["paths"]
            eps = [ep for ep in eps if self._in_scope(ep.get("file", ""), scope_paths)]

        if eps:
            ep_lines = []
            for ep in eps:
                auth = "NO AUTH" if not ep.get("auth_required") else "auth required"
                ep_lines.append(
                    f"  - {ep.get('method', '?')} {ep.get('path', '?')} "
                    f"→ {ep.get('file', '?')}:{ep.get('line', '?')} "
                    f"[{auth}] {ep.get('description', '')}"
                )
            sections.append("**Entry Points (attack surface):**\n" + "\n".join(ep_lines))

        # Data flows — pre-identified dangerous paths
        dfs = recon.get("data_flows", [])
        if dfs:
            df_lines = []
            for df in dfs:
                df_lines.append(
                    f"  - {df.get('name', 'unnamed')}\n"
                    f"    Input: {df.get('input_source', '?')}\n"
                    f"    Validation: {df.get('validation', '?')}\n"
                    f"    Processing: {df.get('processing', '?')}\n"
                    f"    Sink: {df.get('storage', '?')}\n"
                    f"    Sanitization: {df.get('sanitization_notes', '?')}"
                )
            sections.append("**Data Flows (trace these for vulnerabilities):**\n" + "\n".join(df_lines))

        # Auth info
        auth = recon.get("auth", {})
        if auth:
            mechs = ", ".join(auth.get("mechanisms", []))
            notes = auth.get("notes", "")
            sections.append(f"**Authentication:** {mechs}\n  Notes: {notes}")

        # Critical files to review
        cf = recon.get("critical_files", {})
        if isinstance(cf, dict):
            all_files = []
            for category, files in cf.items():
                if isinstance(files, list) and files:
                    all_files.extend(f"{f} [{category}]" for f in files)
            if partition and partition.get("paths"):
                scope_paths = partition["paths"]
                all_files = [f for f in all_files if self._in_scope(f.split(" [")[0], scope_paths)]
            if all_files:
                sections.append("**Critical Files to Review:**\n  " + "\n  ".join(all_files))

        # Security observations from recon
        obs = recon.get("security_observations", [])
        if obs:
            sections.append(
                "**Security Observations from Recon (investigate these):**\n  - "
                + "\n  - ".join(obs[:15])  # cap at 15 to avoid prompt bloat
            )

        # Scope info
        if partition:
            scope_name = partition.get("scope_name", "full")
            scope_paths = partition.get("paths", ["."])
            sections.append(
                f"**Analysis Scope:** {scope_name}\n"
                f"  Focus on files in: {', '.join(scope_paths)}"
            )

        return "\n\n".join(sections) if sections else "No recon data available. Analyze all source files in the repository."

    def _in_scope(self, filepath: str, scope_paths: list[str]) -> bool:
        """Check if a file path falls within any of the scope paths."""
        if not scope_paths or scope_paths == ["."]:
            return True
        return any(filepath.startswith(p) for p in scope_paths)

    def _semgrep_findings(self) -> list:
        """Semgrep SAST results for this repo (run once, cached across partitions)."""
        repo = self.config.repo_path
        if repo not in _SEMGREP_SAST_CACHE:
            _SEMGREP_SAST_CACHE[repo] = run_semgrep_sast(repo)
        return _SEMGREP_SAST_CACHE[repo]

    def _build_semgrep_context(self, partition: dict) -> str:
        """Inject Semgrep SAST findings (filtered to this partition) as leads to validate."""
        findings = self._semgrep_findings()
        if not findings:
            return ""

        repo = self.config.repo_path.rstrip("/")

        def _rel(p: str) -> str:
            p = p or ""
            if p.startswith(repo):
                p = p[len(repo):].lstrip("/")
            return p

        scope_paths = partition.get("paths", []) if partition else []
        if scope_paths and scope_paths != ["."]:
            findings = [f for f in findings if self._in_scope(_rel(f.get("path", "")), scope_paths)]
        if not findings:
            return ""

        from agents.secrets import format_semgrep_for_prompt
        body = format_semgrep_for_prompt(findings, max_findings=40)
        return (
            "\n## SEMGREP SAST PRE-SCAN (tool leads — VALIDATE, do not trust blindly)\n\n"
            f"{body}\n\n"
            "Confirm each by reading the code, discard false positives, and add anything Semgrep missed.\n"
        )

    def parse_output(self, result: RunResult) -> Optional[dict]:
        data = result.parsed_json

        if data is None:
            logger.error("No JSON could be extracted from static analysis output")
            return None

        if not isinstance(data, dict):
            logger.error(f"Expected dict, got {type(data).__name__}")
            return None

        # Check for expected keys
        if "findings" not in data:
            # Try to rescue: maybe the whole response is a findings array
            if isinstance(data, list):
                data = {"findings": data, "summary": {}}
            else:
                # Look for findings under alternative keys
                for alt_key in ("vulnerabilities", "issues", "results", "bugs"):
                    if alt_key in data and isinstance(data[alt_key], list):
                        data["findings"] = data.pop(alt_key)
                        break
                else:
                    logger.warning("No 'findings' key found in output, wrapping entire response")
                    data = {"findings": [], "summary": {}, "_raw": data}

        # Validate and clean findings
        data["findings"] = self._validate_findings(data.get("findings", []))

        # Ensure summary exists and is consistent
        data["summary"] = self._build_summary(data["findings"], data.get("summary", {}))

        finding_count = len(data["findings"])
        by_sev = data["summary"].get("by_severity", {})
        logger.info(
            f"Static analysis complete: {finding_count} findings "
            f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
            f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)})"
        )

        return data

    def _validate_findings(self, findings: list) -> list:
        """Validate and normalize each finding."""
        valid = []
        seen_ids = set()

        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                continue

            # Must have at minimum: title and either description or code_snippet
            if not f.get("title") and not f.get("description"):
                logger.debug(f"Dropping finding without title or description: {f}")
                continue

            # Assign ID if missing or duplicate
            fid = f.get("id", "")
            if not fid or fid in seen_ids:
                fid = f"VULN-{i + 1:03d}"
            seen_ids.add(fid)

            # Normalize severity
            severity = f.get("severity", "medium").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

            # Normalize confidence
            confidence = f.get("confidence", "medium").lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"

            # Normalize CWE
            cwe_id = f.get("cwe_id", 0)
            if isinstance(cwe_id, str):
                # Handle "CWE-89" format
                cwe_id = int(cwe_id.replace("CWE-", "").replace("cwe-", "")) if cwe_id.replace("CWE-", "").replace("cwe-", "").isdigit() else 0

            # Fold the structured-mode `notes` escape hatch into description so
            # off-schema detail the model parked there is never silently lost.
            description = f.get("description", "")
            notes = f.get("notes", "")
            if isinstance(notes, str) and notes.strip():
                description = f"{description}\n\n[notes] {notes}".strip() if description else notes.strip()

            valid.append({
                "id": fid,
                "title": f.get("title", "Untitled finding"),
                "cwe_id": cwe_id,
                "cwe_name": f.get("cwe_name", ""),
                "severity": severity,
                "confidence": confidence,
                "file": f.get("file", ""),
                "line_start": f.get("line_start", f.get("line", None)),
                "line_end": f.get("line_end", f.get("line", None)),
                "code_snippet": f.get("code_snippet", ""),
                "description": description,
                "attack_scenario": f.get("attack_scenario", ""),
                "remediation": f.get("remediation", ""),
                "references": f.get("references", []),
            })

        return valid

    def _build_summary(self, findings: list, existing_summary: dict) -> dict:
        """Build or fix the summary to be consistent with actual findings."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        files_seen = set()

        for f in findings:
            sev = f.get("severity", "medium")
            conf = f.get("confidence", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_confidence[conf] = by_confidence.get(conf, 0) + 1
            if f.get("file"):
                files_seen.add(f["file"])

        # Merge files_analyzed from existing summary (agent may have read more files than had findings)
        existing_files = existing_summary.get("files_analyzed", [])
        if isinstance(existing_files, list):
            files_seen.update(existing_files)

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_confidence": by_confidence,
            "files_analyzed": sorted(files_seen),
            "scope_notes": existing_summary.get("scope_notes", f"Scope: {self.scope_name}"),
        }

    def _count_findings(self, parsed: dict) -> int:
        return len(parsed.get("findings", []))