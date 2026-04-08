"""
A6: TRIAGE & DEDUPLICATION — Finding Consolidation Agent

Takes all findings from A2 (static), A3 (secrets), A4 (deps) and produces
a single, clean, prioritized vulnerability list with:
  - Duplicates merged
  - Attack chains identified
  - CVSS 3.1 scores assigned
  - Findings sorted by priority

This is a pure LLM agent — no CLI tools. The value is in reasoning about
which findings overlap, which form chains, and how to score them.

Inputs:  findings from A2, A3, A4 + recon_report
Outputs: findings_triaged.json
"""

import json
import logging
from pathlib import Path
from typing import Optional

from agents.base import BaseAgent
from models.schemas import EngagementConfig
from utils.runners.base import BaseRunner, RunResult

logger = logging.getLogger("nomad.agents.triage")

PROMPT_FILE = Path(__file__).parent / "prompts" / "triage.md"


class TriageAgent(BaseAgent):
    name = "a6_triage"
    description = "Triage & deduplication — merges, correlates, and CVSS-scores all findings"
    tools = "read_only"  # may need to re-read source to verify
    max_turns = 50
    timeout = 6000

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        super().__init__(config, output_dir, runner)

    def get_system_prompt(self) -> str:
        return PROMPT_FILE.read_text()

    def get_task_prompt(self, context: Optional[dict] = None) -> str:
        if context is None:
            context = {}

        recon = context.get("recon_report", {})
        static_findings = context.get("static_findings", {})
        secrets_findings = context.get("secrets_findings", {})
        deps_findings = context.get("deps_findings", {})
        severity_threshold = context.get("severity_threshold", "low")

        sections = []

        # Brief recon context
        sections.append(self._build_recon_summary(recon))

        # Inject all upstream findings
        sections.append(self._format_agent_findings(
            "A2 STATIC ANALYSIS FINDINGS", static_findings))
        sections.append(self._format_agent_findings(
            "A3 SECRETS SCANNER FINDINGS", secrets_findings))
        sections.append(self._format_agent_findings(
            "A4 DEPENDENCY AUDIT FINDINGS", deps_findings))

        # Count totals
        total = (
            len(static_findings.get("findings", []))
            + len(secrets_findings.get("findings", []))
            + len(deps_findings.get("findings", []))
        )

        # Task
        sections.append(
            f"## YOUR TASK\n\n"
            f"You have {total} total findings from 3 agents.\n\n"
            f"1. Deduplicate: merge findings that describe the same underlying issue.\n"
            f"2. Identify attack chains: findings that combine for greater impact.\n"
            f"3. Assign CVSS 3.1 base scores with full vector strings to every finding.\n"
            f"4. Sort by priority: chains first, then CVSS descending.\n"
            f"5. Filter out findings below severity threshold: {severity_threshold}.\n\n"
            f"Respond with ONLY the JSON object as specified in your instructions.\n"
            f"No markdown, no prose — just valid JSON starting with {{ and ending with }}."
        )

        return "\n\n".join(sections)

    def _build_recon_summary(self, recon: dict) -> str:
        """Minimal recon context for triage decisions."""
        ts = recon.get("tech_stack", {})
        auth = recon.get("auth", {})
        stats = recon.get("repo_stats", {})

        parts = ["## APPLICATION CONTEXT\n"]
        if ts:
            parts.append(f"**Stack:** {', '.join(ts.get('frameworks', []))} | {', '.join(ts.get('languages', []))}")
        if auth:
            mechs = ", ".join(auth.get("mechanisms", []))
            parts.append(f"**Auth:** {mechs}")
        if stats:
            parts.append(f"**Size:** {stats.get('total_loc', '?')} LOC")

        return "\n".join(parts)

    def _format_agent_findings(self, header: str, agent_output: dict) -> str:
        """Format an agent's findings for prompt injection."""
        findings = agent_output.get("findings", [])

        if not findings:
            return f"## {header}\n\nNo findings."

        lines = [f"## {header}\n\n{len(findings)} finding(s):\n"]

        for f in findings:
            fid = f.get("id", "?")
            title = f.get("title", "Untitled")
            severity = f.get("severity", "?")
            confidence = f.get("confidence", "?")
            file_loc = f.get("file", "")
            line = f.get("line_start", f.get("line", ""))
            desc = f.get("description", "")[:300]
            attack = f.get("attack_scenario", "")[:200]
            remediation = f.get("remediation", "")[:200]

            # Include fields specific to different agent types
            extras = []
            if f.get("cwe_id"):
                extras.append(f"CWE-{f['cwe_id']}")
            if f.get("code_snippet"):
                extras.append(f"Code: {f['code_snippet'][:100]}")
            if f.get("package_name"):
                extras.append(f"Package: {f['package_name']}@{f.get('package_version', '?')}")
            if f.get("type"):
                extras.append(f"Type: {f['type']}")
            if f.get("detection_source"):
                extras.append(f"Source: {f['detection_source']}")
            if f.get("cve_ids"):
                extras.append(f"CVEs: {', '.join(f['cve_ids'][:3])}")

            extra_str = " | ".join(extras)

            lines.append(
                f"### {fid}: {title}\n"
                f"  Severity: {severity} | Confidence: {confidence} | "
                f"File: {file_loc}:{line}\n"
                f"  {extra_str}\n"
                f"  Description: {desc}\n"
                f"  Attack: {attack}\n"
                f"  Remediation: {remediation}\n"
            )

        return "\n".join(lines)

    def parse_output(self, result: RunResult) -> Optional[dict]:
        data = result.parsed_json

        if data is None:
            logger.error("No JSON could be extracted from triage output")
            return None

        if not isinstance(data, dict):
            logger.error(f"Expected dict, got {type(data).__name__}")
            return None

        # Ensure required keys
        if "findings" not in data:
            for alt in ("triaged_findings", "results", "vulnerabilities"):
                if alt in data and isinstance(data[alt], list):
                    data["findings"] = data.pop(alt)
                    break
            else:
                data["findings"] = []

        data["findings"] = self._validate_findings(data.get("findings", []))
        data.setdefault("attack_chains", [])
        data["attack_chains"] = self._validate_chains(data["attack_chains"])
        data.setdefault("dedup_log", [])
        data["summary"] = self._build_summary(data)

        count = len(data["findings"])
        chains = len(data["attack_chains"])
        deduped = len(data["dedup_log"])
        by_sev = data["summary"].get("by_severity", {})
        logger.info(
            f"Triage complete: {count} findings, {chains} attack chains, "
            f"{deduped} merges "
            f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
            f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)})"
        )

        return data

    def _validate_findings(self, findings: list) -> list:
        """Validate and normalize triaged findings."""
        valid = []
        seen_ids = set()

        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                continue
            if not f.get("title"):
                continue

            fid = f.get("id", "")
            if not fid or fid in seen_ids:
                fid = f"TRIAGE-{i + 1:03d}"
            seen_ids.add(fid)

            severity = f.get("severity", "medium").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

            confidence = f.get("confidence", "medium").lower()
            if confidence not in ("high", "medium", "low"):
                confidence = "medium"

            cvss = f.get("cvss_score", 0.0)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 0.0

            cwe_id = f.get("cwe_id", 0)
            if isinstance(cwe_id, str):
                cwe_id = int(cwe_id.replace("CWE-", "").replace("cwe-", "")) if cwe_id.replace("CWE-", "").replace("cwe-", "").isdigit() else 0

            valid.append({
                "id": fid,
                "title": f.get("title", ""),
                "severity": severity,
                "confidence": confidence,
                "cvss_score": cvss,
                "cvss_vector": f.get("cvss_vector", ""),
                "cwe_id": cwe_id,
                "cwe_name": f.get("cwe_name", ""),
                "file": f.get("file", ""),
                "line_start": f.get("line_start", None),
                "line_end": f.get("line_end", None),
                "description": f.get("description", ""),
                "attack_scenario": f.get("attack_scenario", ""),
                "remediation": f.get("remediation", ""),
                "detection_sources": f.get("detection_sources", []),
                "original_ids": f.get("original_ids", []),
                "attack_chain": f.get("attack_chain", None),
                "references": f.get("references", []),
            })

        # Sort: chains first, then CVSS descending, then confidence
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        valid.sort(key=lambda f: (
            0 if f.get("attack_chain") else 1,
            -f.get("cvss_score", 0),
            confidence_order.get(f.get("confidence", "medium"), 1),
        ))

        return valid

    def _validate_chains(self, chains: list) -> list:
        """Validate attack chain entries."""
        valid = []
        for i, c in enumerate(chains):
            if not isinstance(c, dict):
                continue
            if not c.get("title"):
                continue

            cid = c.get("id", f"CHAIN-{i + 1:03d}")
            cvss = c.get("cvss_score", 0.0)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 0.0

            valid.append({
                "id": cid,
                "title": c.get("title", ""),
                "severity": c.get("severity", "critical"),
                "cvss_score": cvss,
                "description": c.get("description", ""),
                "finding_ids": c.get("finding_ids", []),
                "combined_impact": c.get("combined_impact", ""),
            })
        return valid

    def _build_summary(self, data: dict) -> dict:
        """Build consistent summary."""
        findings = data.get("findings", [])
        dedup_log = data.get("dedup_log", [])
        chains = data.get("attack_chains", [])
        existing = data.get("summary", {})

        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_confidence = {"high": 0, "medium": 0, "low": 0}

        for f in findings:
            sev = f.get("severity", "medium")
            conf = f.get("confidence", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_confidence[conf] = by_confidence.get(conf, 0) + 1

        # Count total inputs from dedup log
        total_input = existing.get("total_input_findings", 0)
        if not total_input:
            # Estimate from original_ids
            all_originals = set()
            for f in findings:
                all_originals.update(f.get("original_ids", []))
            # Plus findings without original_ids (not merged)
            unmerged = len([f for f in findings if not f.get("original_ids")])
            total_input = len(all_originals) + unmerged

        return {
            "total_input_findings": total_input,
            "duplicates_removed": max(0, total_input - len(findings)),
            "total_output_findings": len(findings),
            "attack_chains_identified": len(chains),
            "by_severity": by_severity,
            "by_confidence": by_confidence,
        }

    def _count_findings(self, parsed: dict) -> int:
        return len(parsed.get("findings", []))
