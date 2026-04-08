"""
A-FP: FINGERPRINT — Application Defense Profiling Agent

Non-destructive active reconnaissance against a running target application.
Probes the application to identify:
  - Server technology and versions
  - WAF / security layer presence, vendor, and bypass characteristics
  - Rate limiting behavior
  - Security headers
  - TLS configuration
  - Live endpoint discovery

Runs BEFORE the validation agent. Its output is consumed by A7 to
select and adapt exploitation payloads.

REQUIRES:
  --validate flag (opt-in, same as validation)
  --base-url (target application URL)

Inputs:  recon_report + base URL
Outputs: fingerprint.json
"""

import json
import logging
from pathlib import Path
from typing import Optional

from agents.base import BaseAgent
from models.schemas import EngagementConfig
from utils.runners.base import BaseRunner, RunResult

logger = logging.getLogger("nomad.agents.fingerprint")

PROMPT_FILE = Path(__file__).parent / "prompts" / "fingerprint.md"


class FingerprintAgent(BaseAgent):
    name = "a_fp_fingerprint"
    description = "Application fingerprinting — maps WAFs, server config, defenses, and attack surface"
    tools = "read_write"  # needs bash for curl
    max_turns = 60
    timeout = 600  # 10 min — many sequential curl calls

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        super().__init__(config, output_dir, runner)

    def get_system_prompt(self) -> str:
        return PROMPT_FILE.read_text()

    def get_task_prompt(self, context: Optional[dict] = None) -> str:
        if context is None:
            context = {}

        recon = context.get("recon_report", {})
        sections = []

        # Target info
        sections.append(
            f"## TARGET APPLICATION\n\n"
            f"**Base URL:** {self.config.base_url}\n"
            f"**Task:** Fingerprint this application — identify technologies, WAFs, "
            f"rate limiting, security headers, and map the live attack surface."
        )

        # Known endpoints from recon (so the agent can verify them live)
        eps = recon.get("entry_points", [])
        if eps:
            ep_lines = ["## KNOWN ENDPOINTS (from source code analysis)\n"]
            for ep in eps:
                ep_lines.append(
                    f"  - {ep.get('method', '?')} {ep.get('path', '?')} "
                    f"[auth={'required' if ep.get('auth_required') else 'none'}] "
                    f"— {ep.get('description', '')[:150]}"
                )
            sections.append("\n".join(ep_lines))

        # Tech stack from recon (for correlation)
        ts = recon.get("tech_stack", {})
        if ts:
            sections.append(
                f"## EXPECTED TECH STACK (from source analysis)\n\n"
                f"Languages: {', '.join(ts.get('languages', []))}\n"
                f"Frameworks: {', '.join(ts.get('frameworks', []))}\n"
                f"Databases: {', '.join(ts.get('databases', []))}\n"
                f"Runtime: {ts.get('runtime', '?')}\n\n"
                f"Verify these against the live application's headers and responses."
            )

        # Credentials for authenticated fingerprinting
        if self.config.credentials:
            sections.append(
                f"## CREDENTIALS (for authenticated endpoint probing)\n\n"
                f"{len(self.config.credentials)} credential set(s) available. "
                f"Use them ONLY to check authenticated endpoint access patterns, "
                f"NOT for exploitation."
            )

        # Task
        sections.append(
            "## YOUR TASK\n\n"
            "Execute all 7 phases of your fingerprinting methodology:\n"
            "1. Server & technology fingerprinting\n"
            "2. WAF / security layer detection (passive + active probing)\n"
            "3. Input vector analysis (which input channels are filtered)\n"
            "4. Rate limiting & throttling detection\n"
            "5. Security headers audit\n"
            "6. TLS/SSL configuration check\n"
            "7. Endpoint discovery (verify known + probe common hidden paths)\n\n"
            "For WAF detection: send progressively suspicious payloads and record "
            "exactly which ones are blocked vs allowed. This data is critical for "
            "the exploitation agent that runs after you.\n\n"
            "Respond with ONLY the JSON object as specified in your instructions.\n"
            "No markdown, no prose — just valid JSON starting with { and ending with }."
        )

        return "\n\n".join(sections)

    def parse_output(self, result: RunResult) -> Optional[dict]:
        data = result.parsed_json

        if data is None:
            logger.error("No JSON could be extracted from fingerprint output")
            return None

        if not isinstance(data, dict):
            logger.error(f"Expected dict, got {type(data).__name__}")
            return None

        # Apply defaults for all required sections
        data.setdefault("server", {})
        data.setdefault("waf", {"detected": False, "vendor": None, "confidence": "none"})
        data.setdefault("rate_limiting", {"detected": False})
        data.setdefault("security_headers", {"present": [], "missing": []})
        data.setdefault("tls", {"https_enabled": False})
        data.setdefault("endpoints_discovered", [])
        data.setdefault("attack_surface_notes", [])

        # Validate WAF section
        waf = data["waf"]
        if isinstance(waf, dict):
            waf.setdefault("detected", False)
            waf.setdefault("vendor", None)
            conf = waf.get("confidence", "none").lower()
            if conf not in ("high", "medium", "low", "none"):
                conf = "none"
            waf["confidence"] = conf
            waf.setdefault("inspects", {})
            waf.setdefault("blocks_on", [])
            waf.setdefault("passes_through", [])
            waf.setdefault("bypass_hints", [])

        # Validate endpoints
        valid_eps = []
        for ep in data.get("endpoints_discovered", []):
            if isinstance(ep, dict) and ep.get("path"):
                ep.setdefault("methods", ["GET"])
                ep.setdefault("status_code", None)
                ep.setdefault("auth_required", False)
                ep.setdefault("notes", "")
                valid_eps.append(ep)
        data["endpoints_discovered"] = valid_eps

        # Log summary
        waf_status = "detected" if waf.get("detected") else "not detected"
        waf_vendor = waf.get("vendor", "unknown") if waf.get("detected") else ""
        rate_limit = "yes" if data["rate_limiting"].get("detected") else "no"
        missing_headers = len(data["security_headers"].get("missing", []))
        live_eps = len(valid_eps)

        logger.info(
            f"Fingerprint complete: WAF={waf_status}"
            + (f" ({waf_vendor})" if waf_vendor else "")
            + f" | Rate limiting={rate_limit}"
            + f" | Missing headers={missing_headers}"
            + f" | Live endpoints={live_eps}"
        )

        if waf.get("bypass_hints"):
            logger.info("  Bypass hints:")
            for hint in waf["bypass_hints"][:5]:
                logger.info(f"    → {hint}")

        return data

    def _count_findings(self, parsed: dict) -> int:
        """Count actionable items: bypass hints + missing headers + live endpoints."""
        count = len(parsed.get("waf", {}).get("bypass_hints", []))
        count += len(parsed.get("security_headers", {}).get("missing", []))
        count += len(parsed.get("endpoints_discovered", []))
        count += len(parsed.get("attack_surface_notes", []))
        return count
