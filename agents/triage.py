"""
A6: TRIAGE & DEDUPLICATION — Finding Consolidation Agent

Takes all findings from A2 (static), A3 (secrets), A4 (deps) and produces
a single, clean, prioritized vulnerability list with:
  - Duplicates merged
  - Attack chains identified
  - CVSS 3.1 scores assigned
  - Findings sorted by priority

Supports batching: if total findings exceed BATCH_SIZE, splits into
batches, triages each, then merges results.

Inputs:  findings from A2, A3, A4 + recon_report
Outputs: findings_triaged.json
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

from agents.base import BaseAgent
from models.schemas import EngagementConfig, AgentRun, AgentStatus
from utils.runners.base import BaseRunner, RunResult

logger = logging.getLogger("nomad.agents.triage")

PROMPT_FILE = Path(__file__).parent / "prompts" / "triage.md"

BATCH_SIZE = 40  # max findings per triage call


class TriageAgent(BaseAgent):
    name = "a6_triage"
    description = "Triage & deduplication — merges, correlates, and CVSS-scores all findings"
    tools = "read_only"
    max_turns = 600
    timeout = 6000  # 15 min

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        super().__init__(config, output_dir, runner)

    def run(self, context: Optional[dict] = None) -> AgentRun:
        """Override to handle batching for large finding sets."""
        if context is None:
            context = {}

        # Collect all findings
        all_findings = []
        for key in ("static_findings", "secrets_findings", "deps_findings"):
            agent_data = context.get(key, {})
            for f in agent_data.get("findings", []):
                f["_source_agent"] = key.replace("_findings", "")
                all_findings.append(f)

        total = len(all_findings)
        logger.info(f"[a6_triage] Total findings to triage: {total}")

        if total <= BATCH_SIZE:
            # Single pass — fits in one call
            return super().run(context)

        # Batching needed
        logger.info(f"[a6_triage] Batching: {total} findings into {(total + BATCH_SIZE - 1) // BATCH_SIZE} batches of {BATCH_SIZE}")
        return self._run_batched(context, all_findings)

    def _run_batched(self, context: dict, all_findings: list) -> AgentRun:
        """Run triage in batches, then merge."""
        run = AgentRun(
            agent_name=self.name,
            status=AgentStatus.RUNNING,
            output_file=str(self.output_file),
        )
        start = time.time()

        batch_results = []
        recon = context.get("recon_report", {})
        severity_threshold = context.get("severity_threshold", "low")

        # Split into batches
        batches = [all_findings[i:i + BATCH_SIZE] for i in range(0, len(all_findings), BATCH_SIZE)]

        for batch_idx, batch in enumerate(batches):
            logger.info(f"[a6_triage] Processing batch {batch_idx + 1}/{len(batches)} ({len(batch)} findings)...")

            # Build batch context
            batch_context = {
                "recon_report": recon,
                "static_findings": {"findings": [f for f in batch if f.get("_source_agent") == "static"]},
                "secrets_findings": {"findings": [f for f in batch if f.get("_source_agent") == "secrets"]},
                "deps_findings": {"findings": [f for f in batch if f.get("_source_agent") == "deps"]},
                "severity_threshold": severity_threshold,
            }

            system_prompt = self.get_system_prompt()
            if self.config.caveman:
                from agents.base import CAVEMAN_DIRECTIVE
                system_prompt += CAVEMAN_DIRECTIVE
            task_prompt = self.get_task_prompt(batch_context)

            result = self.runner.run(
                system_prompt=system_prompt,
                task_prompt=task_prompt,
                working_dir=self.config.repo_path,
                tools=self.tools,
                max_turns=self.max_turns,
                timeout=self.timeout,
                verbose=self.config.verbose,
            )

            if result.success and result.parsed_json:
                parsed = self.parse_output(result)
                if parsed:
                    batch_results.append(parsed)
                    logger.info(
                        f"[a6_triage] Batch {batch_idx + 1}: "
                        f"{len(parsed.get('findings', []))} findings, "
                        f"{len(parsed.get('attack_chains', []))} chains"
                    )
                else:
                    logger.warning(f"[a6_triage] Batch {batch_idx + 1} parse failed")
            else:
                logger.warning(f"[a6_triage] Batch {batch_idx + 1} failed: {result.error}")

        run.duration_seconds = time.time() - start

        if not batch_results:
            run.status = AgentStatus.FAILED
            run.error = "All triage batches failed"
            return run

        # Merge all batch results
        merged = self._merge_batches(batch_results, len(all_findings))

        # Save
        self.output_file.write_text(json.dumps(merged, indent=2, default=str))
        run.status = AgentStatus.COMPLETED
        run.finding_count = len(merged.get("findings", []))

        logger.info(
            f"[a6_triage] Batched triage complete: {run.finding_count} findings from "
            f"{len(batch_results)} batches in {run.duration_seconds:.1f}s"
        )

        return run

    def _merge_batches(self, batch_results: list[dict], total_input: int) -> dict:
        """Merge results from multiple triage batches."""
        all_findings = []
        all_chains = []
        all_dedup = []
        counter = 0

        for batch in batch_results:
            for f in batch.get("findings", []):
                counter += 1
                f["id"] = f"TRIAGE-{counter:03d}"
                all_findings.append(f)
            all_chains.extend(batch.get("attack_chains", []))
            all_dedup.extend(batch.get("dedup_log", []))

        # Re-sort: chains first, then CVSS descending
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        all_findings.sort(key=lambda f: (
            0 if f.get("attack_chain") else 1,
            -f.get("cvss_score", 0),
            confidence_order.get(f.get("confidence", "medium"), 1),
        ))

        # Re-number after sort
        for i, f in enumerate(all_findings):
            f["id"] = f"TRIAGE-{i + 1:03d}"

        # Build summary
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            by_severity[f.get("severity", "medium")] = by_severity.get(f.get("severity", "medium"), 0) + 1
            by_confidence[f.get("confidence", "medium")] = by_confidence.get(f.get("confidence", "medium"), 0) + 1

        return {
            "findings": all_findings,
            "attack_chains": all_chains,
            "dedup_log": all_dedup,
            "summary": {
                "total_input_findings": total_input,
                "duplicates_removed": max(0, total_input - len(all_findings)),
                "total_output_findings": len(all_findings),
                "attack_chains_identified": len(all_chains),
                "by_severity": by_severity,
                "by_confidence": by_confidence,
                "batches_used": len(batch_results),
            },
        }

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

        # Inject all upstream findings — COMPACT format
        sections.append(self._format_findings_compact(
            "A2 STATIC ANALYSIS FINDINGS", static_findings))
        sections.append(self._format_findings_compact(
            "A3 SECRETS SCANNER FINDINGS", secrets_findings))
        sections.append(self._format_findings_compact(
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
            f"You have {total} total findings from upstream agents.\n\n"
            f"1. Deduplicate: merge findings that describe the same underlying issue.\n"
            f"2. Identify attack chains: findings that combine for greater impact.\n"
            f"3. Assign CVSS 3.1 base scores with full vector strings to every finding.\n"
            f"4. Sort by priority: chains first, then CVSS descending.\n"
            f"5. Filter out findings below severity threshold: {severity_threshold}.\n"
            f"6. Output MAXIMUM 30 triaged findings.\n\n"
            f"Respond with ONLY the JSON object as specified in your instructions.\n"
            f"No markdown, no prose — just valid JSON starting with {{ and ending with }}."
        )

        return "\n\n".join(sections)

    def _build_recon_summary(self, recon: dict) -> str:
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

    def _format_findings_compact(self, header: str, agent_output: dict) -> str:
        """
        Format findings in COMPACT mode — one line per finding.
        This dramatically reduces prompt size vs the full format.
        """
        findings = agent_output.get("findings", [])

        if not findings:
            return f"## {header}\n\nNo findings."

        lines = [f"## {header} ({len(findings)} findings)\n"]
        lines.append("Format: [ID] SEVERITY | CONFIDENCE | CWE | file:line | title | description_summary\n")

        for f in findings:
            fid = f.get("id", "?")
            sev = f.get("severity", "?").upper()[:4]
            conf = f.get("confidence", "?")[0].upper()
            cwe = f.get("cwe_id", "")
            cwe_str = f"CWE-{cwe}" if cwe else "no-CWE"
            file_loc = f.get("file", "?")
            line = f.get("line_start", f.get("line", ""))
            title = f.get("title", "Untitled")[:80]
            desc = f.get("description", "")[:120].replace("\n", " ")

            # Type-specific extras
            extra = ""
            if f.get("package_name"):
                extra = f" | pkg={f['package_name']}@{f.get('package_version', '?')}"
            elif f.get("type"):
                extra = f" | type={f['type']}"

            lines.append(
                f"[{fid}] {sev} | {conf} | {cwe_str} | {file_loc}:{line} | "
                f"{title} | {desc}{extra}"
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

            # Clean _source_agent tag if present
            f.pop("_source_agent", None)

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

        total_input = existing.get("total_input_findings", 0)
        if not total_input:
            all_originals = set()
            for f in findings:
                all_originals.update(f.get("original_ids", []))
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