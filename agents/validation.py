"""
A7: VALIDATION — Exploit Confirmation Agent

Actively confirms vulnerabilities by executing adaptive PoC exploits.
Uses fingerprint data from the fingerprint agent to select optimal
payloads and bypass techniques.

REQUIRES:
  --validate flag (opt-in only)
  --base-url (target application URL)
  Optionally: --creds, --tokens, --safe-only

Inputs:  triaged findings + fingerprint data + base URL + credentials
Outputs: findings_validated.json
"""

import json
import logging
from pathlib import Path
from typing import Optional

from agents.base import BaseAgent
from models.schemas import EngagementConfig
from utils.runners.base import BaseRunner, RunResult

logger = logging.getLogger("nomad.agents.validation")

PROMPT_FILE = Path(__file__).parent / "prompts" / "validation.md"

MAX_FINDINGS_TO_VALIDATE = 20  # only validate top critical+high


def _safe_list(val, max_items: int = 0) -> list:
    """Coerce any value to a list safely. Handles dict, str, None."""
    if val is None:
        return []
    if isinstance(val, dict):
        # Use keys for header-like dicts, values would lose the header name
        return list(val.keys())
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return val[:max_items] if max_items > 0 else val
    return []


def _safe_join(val, sep: str = ", ", max_items: int = 8) -> str:
    """Safely join a value that might be list, dict, or str."""
    items = _safe_list(val)
    items = [str(i) for i in items[:max_items]]
    return sep.join(items) if items else "none"


class ValidationAgent(BaseAgent):
    name = "a7_validation"
    description = "Exploit validation — confirms vulnerabilities with adaptive PoC testing"
    tools = "read_write"  # needs bash for curl
    max_turns = 80
    timeout = 1200  # 20 min — needs time for multiple curl rounds with delays

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        super().__init__(config, output_dir, runner)

    def get_system_prompt(self) -> str:
        return PROMPT_FILE.read_text()

    def get_task_prompt(self, context: Optional[dict] = None) -> str:
        if context is None:
            context = {}

        triaged = context.get("triaged_findings", {})
        fingerprint = context.get("fingerprint", {})
        all_findings = triaged.get("findings", [])
        chains = triaged.get("attack_chains", [])

        # Filter to critical + high only, cap at MAX_FINDINGS_TO_VALIDATE
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        priority_findings = [f for f in all_findings if f.get("severity") in ("critical", "high")]
        priority_findings.sort(key=lambda f: (severity_order.get(f.get("severity", "medium"), 2), -f.get("cvss_score", 0)))

        if len(priority_findings) > MAX_FINDINGS_TO_VALIDATE:
            priority_findings = priority_findings[:MAX_FINDINGS_TO_VALIDATE]

        # Filter chains to only include those referencing validated findings
        validated_ids = {f.get("id") for f in priority_findings}
        relevant_chains = [c for c in chains if any(fid in validated_ids for fid in c.get("finding_ids", []))]

        skipped_count = len(all_findings) - len(priority_findings)

        sections = []

        # Target info
        sections.append(self._build_target_info())

        # Fingerprint intelligence
        sections.append(self._format_fingerprint(fingerprint))

        # Findings to validate
        sections.append(self._format_findings(priority_findings))

        # Attack chains
        if relevant_chains:
            sections.append(self._format_chains(relevant_chains))

        # Task
        total = len(priority_findings)
        waf = fingerprint.get("waf", {}) if isinstance(fingerprint.get("waf"), dict) else {}
        waf_detected = waf.get("detected", False)
        waf_vendor = waf.get("vendor", "unknown") if waf_detected else None

        strategy_note = ""
        if waf_detected:
            bypass_hints = _safe_list(waf.get("bypass_hints"))
            strategy_note = (
                f"WAF DETECTED: {waf_vendor}. "
                f"Use the {len(bypass_hints)} bypass hints from the fingerprint. "
                f"Do NOT use naive payloads — they WILL be blocked."
            )
        else:
            strategy_note = (
                "NO WAF DETECTED. Use direct payloads. "
                "Expect most findings to confirm in round 1."
            )

        sections.append(
            f"## YOUR TASK\n\n"
            f"**{strategy_note}**\n\n"
            f"Validate {total} critical/high findings against {self.config.base_url}."
            + (f" ({skipped_count} medium/low findings skipped — not worth active testing.)" if skipped_count > 0 else "") +
            f"\n\n"
            f"1. Use fingerprint data to select the right payload technique FIRST.\n"
            f"2. Execute PoCs starting with CRITICAL severity.\n"
            f"3. If blocked, escalate using the bypass hints and payload matrix.\n"
            f"4. For attack chains, test the full chain end-to-end.\n"
            f"5. Document every attempt (successes AND failures).\n"
            f"6. Add 'sleep 1' between curl requests to avoid overwhelming the target.\n"
            f"7. Use 'curl --connect-timeout 10 --max-time 30' for all requests.\n\n"
            f"{'SAFE MODE IS ON. Non-destructive only. Boolean/time-based blind SQLi allowed.' if self.config.safe_only else 'Full testing mode. Destructive ops allowed with caution.'}\n\n"
            f"Respond with ONLY the JSON object as specified in your instructions.\n"
            f"No markdown, no prose — just valid JSON starting with {{ and ending with }}."
        )

        return "\n\n".join(sections)

    def _build_target_info(self) -> str:
        parts = ["## TARGET APPLICATION\n"]
        parts.append(f"**Base URL:** {self.config.base_url}")
        parts.append(f"**Safe mode:** {'YES' if self.config.safe_only else 'NO'}")

        if self.config.credentials:
            parts.append(f"**Credentials:** {len(self.config.credentials)} set(s)")
            for i, cred in enumerate(self.config.credentials):
                if ":" in cred:
                    user, pwd = cred.split(":", 1)
                    parts.append(f"  Cred {i+1}: username={user} password={pwd}")
                else:
                    parts.append(f"  Cred {i+1}: {cred}")

        if self.config.tokens:
            parts.append(f"**Tokens:** {len(self.config.tokens)}")
            for i, token in enumerate(self.config.tokens):
                parts.append(f"  Token {i+1}: {token}")

        return "\n".join(parts)

    def _format_fingerprint(self, fingerprint: dict) -> str:
        """Format the fingerprint data as actionable intelligence."""
        if not fingerprint:
            return (
                "## TARGET FINGERPRINT\n\n"
                "**No fingerprint data available.** Fingerprint agent did not run.\n"
                "Perform your own quick fingerprint: send a basic SQLi and XSS payload "
                "to detect WAF presence before testing findings."
            )

        sections = ["## TARGET FINGERPRINT (from fingerprint agent)\n"]

        # Server
        server = fingerprint.get("server", {})
        if isinstance(server, dict) and server:
            sections.append(
                f"**Server:** {server.get('web_server', '?')} | "
                f"Framework: {server.get('framework', '?')} | "
                f"Language: {server.get('language', '?')}"
            )

        # WAF — the critical section
        waf = fingerprint.get("waf", {})
        if not isinstance(waf, dict):
            waf = {}

        if waf.get("detected"):
            sections.append(f"\n**WAF DETECTED: {waf.get('vendor', 'unknown')}** (confidence: {waf.get('confidence', '?')})")
            sections.append(f"  Evidence: {waf.get('evidence', 'N/A')}")
            sections.append(f"  Mode: {waf.get('mode', 'unknown')}")

            inspects = waf.get("inspects", {})
            if isinstance(inspects, dict) and inspects:
                inspected = [k for k, v in inspects.items() if v]
                not_inspected = [k for k, v in inspects.items() if not v]
                sections.append(f"  INSPECTS: {', '.join(inspected) or 'unknown'}")
                sections.append(f"  DOES NOT INSPECT: {', '.join(not_inspected) or 'none identified'}")

            blocks = _safe_list(waf.get("blocks_on"))
            if blocks:
                sections.append(f"  BLOCKS: {_safe_join(blocks)}")

            passes = _safe_list(waf.get("passes_through"))
            if passes:
                sections.append(f"  PASSES THROUGH: {_safe_join(passes)}")

            hints = _safe_list(waf.get("bypass_hints"))
            if hints:
                sections.append("  BYPASS HINTS (use these):")
                for hint in hints:
                    sections.append(f"    → {str(hint)}")
        else:
            sections.append("\n**NO WAF DETECTED** — direct payloads should work.")

        # Rate limiting
        rl = fingerprint.get("rate_limiting", {})
        if not isinstance(rl, dict):
            rl = {}
        if rl.get("detected"):
            applies_to = _safe_join(rl.get("applies_to", []))
            sections.append(
                f"\n**Rate limiting:** YES — threshold {rl.get('threshold', '?')} "
                f"per {rl.get('window', '?')}. Applies to: {applies_to}"
            )
            sections.append("  IMPORTANT: Add 'sleep 2' between requests to these endpoints.")
        else:
            sections.append("\n**Rate limiting:** Not detected.")

        # Security headers summary
        sh = fingerprint.get("security_headers", {})
        if not isinstance(sh, dict):
            sh = {}
        missing = _safe_list(sh.get("missing", []))
        if missing:
            sections.append(f"\n**Missing security headers ({len(missing)}):** {_safe_join(missing)}")

        # TLS
        tls = fingerprint.get("tls", {})
        if not isinstance(tls, dict):
            tls = {}
        if not tls.get("https_enabled"):
            sections.append("\n**TLS:** NOT ENABLED — plaintext HTTP")

        # Attack surface notes
        notes = _safe_list(fingerprint.get("attack_surface_notes", []))
        if notes:
            sections.append("\n**Attack surface summary:**")
            for n in notes:
                sections.append(f"  • {str(n)}")

        return "\n".join(sections)

    def _format_findings(self, findings: list) -> str:
        if not findings:
            return "## FINDINGS TO VALIDATE\n\nNo findings."

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.get("severity", "medium"), 2), -f.get("cvss_score", 0)))

        lines = [f"## FINDINGS TO VALIDATE ({len(findings)} critical/high findings)\n"]

        for f in sorted_findings:
            lines.append(
                f"### {f.get('id', '?')}: {f.get('title', '?')}\n"
                f"  Severity: {f.get('severity', '?')} | CVSS: {f.get('cvss_score', 0)} | CWE: {f.get('cwe_id', '')}\n"
                f"  File: {f.get('file', '')}:{f.get('line_start', '')}\n"
                f"  Description: {str(f.get('description', ''))[:300]}\n"
                f"  Attack scenario: {str(f.get('attack_scenario', ''))[:300]}\n"
            )

        return "\n".join(lines)

    def _format_chains(self, chains: list) -> str:
        lines = [f"## ATTACK CHAINS ({len(chains)})\n"]
        for c in chains:
            finding_ids = _safe_list(c.get("finding_ids", []))
            lines.append(
                f"### {c.get('id', '?')}: {c.get('title', '?')}\n"
                f"  Findings: {', '.join(str(fid) for fid in finding_ids)}\n"
                f"  Impact: {c.get('combined_impact', '?')}\n"
            )
        return "\n".join(lines)

    def parse_output(self, result: RunResult) -> Optional[dict]:
        data = result.parsed_json

        if data is None:
            logger.error("No JSON could be extracted from validation output")
            return None

        if not isinstance(data, dict):
            logger.error(f"Expected dict, got {type(data).__name__}")
            return None

        if "validations" not in data:
            for alt in ("findings", "results", "validated", "tests"):
                if alt in data and isinstance(data[alt], list):
                    data["validations"] = data.pop(alt)
                    break
            else:
                data["validations"] = []

        data["validations"] = self._validate_entries(data.get("validations", []))
        data.setdefault("untested", [])
        data["summary"] = self._build_summary(data)

        confirmed = sum(1 for v in data["validations"] if v["status"] == "confirmed")
        bypassed = sum(1 for v in data["validations"] if v["status"] == "confirmed" and v.get("defenses_bypassed"))
        not_exp = sum(1 for v in data["validations"] if v["status"] == "not_exploitable")
        manual = sum(1 for v in data["validations"] if v["status"] == "needs_manual_review")
        untested = len(data.get("untested", []))

        logger.info(
            f"Validation complete: {confirmed} confirmed ({bypassed} with bypass), "
            f"{not_exp} not exploitable, {manual} needs review, {untested} untested"
        )

        return data

    def _validate_entries(self, validations: list) -> list:
        valid = []
        for v in validations:
            if not isinstance(v, dict):
                continue

            status = v.get("status", "needs_manual_review").lower()
            if status not in ("confirmed", "not_exploitable", "needs_manual_review"):
                status = "needs_manual_review"

            cvss = v.get("cvss_adjusted", v.get("cvss_score", 0.0))
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 0.0

            rounds = []
            for r in v.get("rounds", []):
                if not isinstance(r, dict):
                    continue
                r_result = r.get("result", "inconclusive").lower()
                if r_result not in ("success", "blocked_by_waf", "blocked_by_filter",
                                     "blocked_by_rate_limit", "error", "inconclusive"):
                    r_result = "inconclusive"
                rounds.append({
                    "round": r.get("round", len(rounds) + 1),
                    "technique": r.get("technique", ""),
                    "poc_command": r.get("poc_command", ""),
                    "response_code": r.get("response_code"),
                    "response_excerpt": str(r.get("response_excerpt", ""))[:1000],
                    "result": r_result,
                })

            if not rounds and v.get("poc_command"):
                rounds.append({
                    "round": 1,
                    "technique": "direct",
                    "poc_command": v.get("poc_command", ""),
                    "response_code": None,
                    "response_excerpt": str(v.get("poc_response", ""))[:1000],
                    "result": "success" if status == "confirmed" else "inconclusive",
                })

            defenses = _safe_list(v.get("defenses_bypassed", []))

            valid.append({
                "finding_id": v.get("finding_id", v.get("id", "")),
                "title": v.get("title", ""),
                "status": status,
                "rounds": rounds,
                "final_poc": v.get("final_poc", v.get("poc_command", "")),
                "final_response": str(v.get("final_response", v.get("poc_response", "")))[:2000],
                "evidence": str(v.get("evidence", "")),
                "defenses_bypassed": defenses,
                "notes": str(v.get("notes", "")),
                "severity_adjusted": v.get("severity_adjusted", v.get("severity", "medium")),
                "cvss_adjusted": cvss,
            })

        return valid

    def _build_summary(self, data: dict) -> dict:
        validations = data.get("validations", [])
        untested = data.get("untested", [])

        confirmed = sum(1 for v in validations if v["status"] == "confirmed")
        confirmed_bypass = sum(1 for v in validations if v["status"] == "confirmed" and v.get("defenses_bypassed"))
        not_exp = sum(1 for v in validations if v["status"] == "not_exploitable")
        manual = sum(1 for v in validations if v["status"] == "needs_manual_review")

        all_defenses = set()
        total_requests = 0
        for v in validations:
            all_defenses.update(v.get("defenses_bypassed", []))
            total_requests += len(v.get("rounds", []))

        return {
            "total_findings": len(validations) + len(untested),
            "tested": len(validations),
            "confirmed": confirmed,
            "confirmed_with_bypass": confirmed_bypass,
            "not_exploitable": not_exp,
            "needs_manual_review": manual,
            "untested": len(untested),
            "safe_mode": self.config.safe_only,
            "target_url": self.config.base_url,
            "total_requests_sent": total_requests,
            "defenses_bypassed": sorted(all_defenses),
        }

    def _count_findings(self, parsed: dict) -> int:
        return sum(1 for v in parsed.get("validations", []) if v["status"] == "confirmed")