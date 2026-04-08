"""
A1: RECON — Codebase Comprehension Agent

First agent in the pipeline. Builds the architectural map that all
downstream agents depend on.

Inputs:  repo path
Outputs: recon_report.json

The parser includes a fallback mapper that handles the common case where
the LLM ignores our schema and invents its own JSON structure (e.g., using
"app_profile", "attack_surface", "dangerous_dataflows" instead of our keys).
"""

import json
import logging
import re
from pathlib import Path
from typing import Optional

from agents.base import BaseAgent
from models.schemas import EngagementConfig
from utils.runners.base import BaseRunner, RunResult

logger = logging.getLogger("nomad.agents.recon")

PROMPT_FILE = Path(__file__).parent / "prompts" / "recon.md"

# The 10 required top-level keys in our schema
REQUIRED_KEYS = {
    "tech_stack", "entry_points", "auth", "data_flows", "trust_boundaries",
    "critical_files", "modules", "third_party_integrations", "repo_stats",
    "security_observations",
}


class ReconAgent(BaseAgent):
    name = "a1_recon"
    description = "Codebase reconnaissance — maps architecture, entry points, data flows"
    tools = "read_only"
    max_turns = 50
    timeout = 1200

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        super().__init__(config, output_dir, runner)

    def get_system_prompt(self) -> str:
        return PROMPT_FILE.read_text()

    def get_task_prompt(self, context: Optional[dict] = None) -> str:
        repo = self.config.repo_path
        scope = self.config.scope.value

        prompt = f"""Analyze the source code repository at the current working directory.

Repository path: {repo}
Scan scope: {scope}

Perform a complete reconnaissance of this codebase following your methodology steps 1-8.

YOUR RESPONSE MUST BE ONLY A JSON OBJECT using the EXACT schema from your instructions.
Use exactly these 10 top-level keys: tech_stack, entry_points, auth, data_flows, trust_boundaries, critical_files, modules, third_party_integrations, repo_stats, security_observations.
No other keys. No text before or after the JSON. No markdown fences."""

        if scope == "quick":
            prompt += """

QUICK SCAN MODE: Focus only on:
- Tech stack identification
- Entry point enumeration
- Auth mechanism overview
- Critical files list
Skip detailed data flow tracing and trust boundary analysis."""

        return prompt

    def parse_output(self, result: RunResult) -> Optional[dict]:
        data = result.parsed_json

        if data is None:
            logger.error("No JSON could be extracted from recon output")
            return None

        if not isinstance(data, dict):
            logger.error(f"Expected dict, got {type(data).__name__}")
            return None

        # Check if the output matches our schema or is freestyle
        present_keys = set(data.keys())
        schema_match = present_keys & REQUIRED_KEYS

        if len(schema_match) < 5:
            # Fewer than half our expected keys — this is a freestyle response.
            # Try to map it to our schema.
            logger.warning(
                f"Output uses non-standard schema (matched {len(schema_match)}/10 keys). "
                f"Attempting to map freestyle output to expected schema."
            )
            data = _map_freestyle_to_schema(data)

        # Apply defaults for any missing keys
        data = _apply_defaults(data)

        # Validate and clean sub-structures
        data["entry_points"] = _validate_entry_points(data.get("entry_points", []))
        data["modules"] = _validate_modules(data.get("modules", []))
        data["data_flows"] = _validate_data_flows(data.get("data_flows", []))
        data["critical_files"] = _validate_critical_files(data.get("critical_files", {}))

        # Ensure repo_stats has required fields
        if not isinstance(data.get("repo_stats"), dict):
            data["repo_stats"] = {"total_files": 0, "total_loc": 0, "language_breakdown": {}}
        for k in ("total_files", "total_loc"):
            if k not in data["repo_stats"]:
                data["repo_stats"][k] = 0
        if "language_breakdown" not in data["repo_stats"]:
            data["repo_stats"]["language_breakdown"] = {}

        ep_count = len(data["entry_points"])
        mod_count = len(data["modules"])
        df_count = len(data["data_flows"])
        loc = data.get("repo_stats", {}).get("total_loc", 0)

        logger.info(
            f"Recon complete: {mod_count} modules, {ep_count} entry points, "
            f"{df_count} data flows, {loc} LOC"
        )

        return data

    def _count_findings(self, parsed: dict) -> int:
        return (
            len(parsed.get("modules", []))
            + len(parsed.get("entry_points", []))
            + len(parsed.get("data_flows", []))
        )


# ── Freestyle-to-Schema Mapper ──────────────────────────────────────────────

def _map_freestyle_to_schema(raw: dict) -> dict:
    """
    Maps common freestyle JSON structures (that LLMs produce when they ignore
    the schema) to our expected format. This is a best-effort rescue.
    """
    mapped = {}

    # ── tech_stack ───────────────────────────────────────────────────
    ts = raw.get("tech_stack", raw.get("app_profile", {}))
    if isinstance(ts, dict):
        mapped["tech_stack"] = {
            "languages": _extract_list(ts, "languages", []),
            "frameworks": (
                _extract_list(ts, "frameworks", [])
                or _extract_list(ts, "app_model", [])
            ),
            "databases": (
                _extract_list(ts, "databases", [])
                or _extract_list(ts, "orm", [])
            ),
            "runtime": ts.get("runtime", ts.get("dotnet_version", "")),
            "package_manager": ts.get("package_manager", ""),
            "containerized": ts.get("containerized", False),
            "ci_cd": ts.get("ci_cd"),
            "iac": _extract_list(ts, "iac", []),
        }
        # Pull key_dependencies into tech_stack if present
        deps = _extract_list(ts, "key_dependencies", [])
        if deps and not mapped["tech_stack"]["frameworks"]:
            mapped["tech_stack"]["frameworks"] = deps
    else:
        mapped["tech_stack"] = {}

    # ── entry_points ─────────────────────────────────────────────────
    eps = raw.get("entry_points", [])
    if not eps:
        # Try to extract from attack_surface
        atk = raw.get("attack_surface", {})
        if isinstance(atk, dict):
            for key in ("endpoints_without_auth", "endpoints_with_raw_sql",
                        "endpoints_with_file_upload", "endpoints_accepting_xml",
                        "signalr_hubs", "grpc_services", "webhook_receivers"):
                for item in _extract_list(atk, key, []):
                    if isinstance(item, str) and item.lower() not in ("none", "n/a", ""):
                        ep = _parse_endpoint_string(item)
                        ep["auth_required"] = "without_auth" not in key
                        eps.append(ep)
    mapped["entry_points"] = eps

    # ── auth ─────────────────────────────────────────────────────────
    auth = raw.get("auth", raw.get("auth_mechanisms"))
    if isinstance(auth, list) and auth:
        mapped["auth"] = {
            "mechanisms": [a.get("type", str(a)) if isinstance(a, dict) else str(a) for a in auth],
            "notes": "",
        }
    elif isinstance(auth, dict) and auth:
        mapped["auth"] = auth
    else:
        # Try to pull from security_controls or auth_stack
        sc = raw.get("security_controls", {})
        auth_stack = _extract_list(raw.get("app_profile", {}), "auth_stack", [])
        mechs = []
        notes_parts = []
        if auth_stack:
            for item in auth_stack:
                if "none" in item.lower():
                    mechs.append("none")
                notes_parts.append(item)
        if isinstance(sc, dict):
            if not sc.get("global_auth_filter", True):
                if "none" not in mechs:
                    mechs.append("none")
            for k, v in sc.items():
                if isinstance(v, (str, bool)):
                    notes_parts.append(f"{k}={v}")
        mapped["auth"] = {
            "mechanisms": mechs or ["unknown"],
            "session_store": None,
            "password_hashing": None,
            "mfa_supported": False,
            "authorization_model": "none" if "none" in mechs else "unknown",
            "key_files": [],
            "notes": "; ".join(notes_parts),
        }

    # ── data_flows ───────────────────────────────────────────────────
    dfs = raw.get("data_flows", [])
    if not dfs:
        # Map from dangerous_dataflows (common freestyle key)
        for item in raw.get("dangerous_dataflows", []):
            if isinstance(item, dict):
                dfs.append({
                    "name": f"{item.get('source', 'unknown')} → {item.get('sink', 'unknown')}",
                    "input_source": item.get("source", ""),
                    "validation": "none detected",
                    "processing": item.get("path", ""),
                    "storage": item.get("sink", ""),
                    "output": "",
                    "sanitization_notes": item.get("sanitization", item.get("risk_notes", "")),
                })
    mapped["data_flows"] = dfs

    # ── trust_boundaries ─────────────────────────────────────────────
    mapped["trust_boundaries"] = raw.get("trust_boundaries", [])

    # ── critical_files ───────────────────────────────────────────────
    cf = raw.get("critical_files", {})
    if isinstance(cf, list):
        # Convert flat list to categorized object
        cf = {"auth": cf, "database": [], "config": [], "middleware": [],
              "input_validation": [], "crypto": [], "file_handling": [],
              "error_handling": [], "external_apis": []}
    mapped["critical_files"] = cf

    # ── modules ──────────────────────────────────────────────────────
    mods = raw.get("modules", [])
    if not mods:
        # Try to synthesize a single module from the overall info
        name = raw.get("app_profile", {}).get("name", "main")
        if isinstance(name, str) and name:
            mods = [{
                "name": name,
                "paths": ["."],
                "loc_estimate": 0,
                "risk": "high",
                "depends_on": [],
                "description": "Auto-generated module from freestyle recon output",
            }]
    mapped["modules"] = mods

    # ── third_party_integrations ─────────────────────────────────────
    tpi = raw.get("third_party_integrations", [])
    if not tpi:
        for dep in raw.get("vuln_dependencies", []):
            if isinstance(dep, dict):
                tpi.append({
                    "service": dep.get("package", ""),
                    "purpose": dep.get("notes", ""),
                    "sdk": dep.get("package", ""),
                    "config_location": "",
                    "key_files": [],
                })
    mapped["third_party_integrations"] = tpi

    # ── repo_stats ───────────────────────────────────────────────────
    mapped["repo_stats"] = raw.get("repo_stats", {
        "total_files": 0,
        "total_loc": raw.get("total_loc", 0),
        "language_breakdown": {},
    })

    # ── security_observations ────────────────────────────────────────
    obs = raw.get("security_observations", [])
    if not obs:
        # Pull from patterns_noted or recommended_audit_focus
        for key in ("patterns_noted", "recommended_audit_focus"):
            for item in raw.get(key, []):
                if isinstance(item, str):
                    obs.append(item)
    mapped["security_observations"] = obs

    logger.info(f"Mapped freestyle output: {len(mapped['entry_points'])} endpoints, "
                f"{len(mapped['data_flows'])} data flows, {len(mapped['modules'])} modules")

    return mapped


# ── Validation Helpers ───────────────────────────────────────────────────────

def _apply_defaults(data: dict) -> dict:
    """Ensure all required top-level keys exist with sensible defaults."""
    defaults = {
        "tech_stack": {},
        "entry_points": [],
        "auth": {"mechanisms": [], "notes": ""},
        "data_flows": [],
        "trust_boundaries": [],
        "critical_files": {
            "auth": [], "input_validation": [], "database": [], "crypto": [],
            "file_handling": [], "config": [], "middleware": [],
            "error_handling": [], "external_apis": [],
        },
        "modules": [],
        "third_party_integrations": [],
        "repo_stats": {"total_files": 0, "total_loc": 0, "language_breakdown": {}},
        "security_observations": [],
    }
    for key, default in defaults.items():
        if key not in data:
            data[key] = default
    return data


def _validate_entry_points(eps: list) -> list:
    """Keep only well-formed entry points."""
    valid = []
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        # Must have at least type and path (or description)
        if "type" in ep or "path" in ep or "description" in ep:
            ep.setdefault("type", "http")
            ep.setdefault("method", "GET")
            ep.setdefault("path", "")
            ep.setdefault("handler", "")
            ep.setdefault("file", "")
            ep.setdefault("line", None)
            ep.setdefault("auth_required", False)
            ep.setdefault("description", "")
            valid.append(ep)
    return valid


def _validate_modules(mods: list) -> list:
    """Keep only well-formed modules."""
    valid = []
    for mod in mods:
        if not isinstance(mod, dict):
            continue
        if "name" not in mod:
            continue
        mod.setdefault("paths", [])
        mod.setdefault("loc_estimate", 0)
        mod.setdefault("risk", "medium")
        mod.setdefault("depends_on", [])
        mod.setdefault("description", "")
        valid.append(mod)
    return valid


def _validate_data_flows(dfs: list) -> list:
    """Keep only well-formed data flows."""
    valid = []
    for df in dfs:
        if not isinstance(df, dict):
            continue
        df.setdefault("name", "unnamed flow")
        df.setdefault("input_source", "")
        df.setdefault("validation", "")
        df.setdefault("processing", "")
        df.setdefault("storage", "")
        df.setdefault("output", "")
        df.setdefault("sanitization_notes", "")
        valid.append(df)
    return valid


def _validate_critical_files(cf) -> dict:
    """Ensure critical_files is a properly categorized object."""
    categories = [
        "auth", "input_validation", "database", "crypto",
        "file_handling", "config", "middleware", "error_handling", "external_apis",
    ]
    if isinstance(cf, list):
        return {"auth": cf, **{c: [] for c in categories[1:]}}
    if not isinstance(cf, dict):
        return {c: [] for c in categories}
    for cat in categories:
        if cat not in cf:
            cf[cat] = []
        elif not isinstance(cf[cat], list):
            cf[cat] = [cf[cat]] if cf[cat] else []
    return cf


def _extract_list(d: dict, key: str, default: list) -> list:
    """Safely extract a list from a dict, coercing single values."""
    val = d.get(key, default)
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        return [val] if val else default
    return default


def _parse_endpoint_string(s: str) -> dict:
    """
    Parse a freestyle endpoint description like:
    "GET /login — accepts username and password via query string"
    into a structured entry_point dict.
    """
    ep = {
        "type": "http",
        "method": "GET",
        "path": "",
        "handler": "",
        "file": "",
        "line": None,
        "auth_required": False,
        "description": s,
    }

    # Try to extract method and path
    # Pattern: "GET /path" or "POST /path" at the start
    match = re.match(r"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(/\S+)", s)
    if match:
        ep["method"] = match.group(1)
        ep["path"] = match.group(2)
    else:
        # Try just a path
        match = re.search(r"(/\S+)", s)
        if match:
            ep["path"] = match.group(1)

    # Try to extract file reference
    match = re.search(r"[\w/]+\.\w+:\d+", s)
    if match:
        parts = match.group(0).rsplit(":", 1)
        ep["file"] = parts[0]
        ep["line"] = int(parts[1])

    return ep
