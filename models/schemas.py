"""
Shared data models for the multi-agent source code review pipeline.
Every agent reads/writes these structures — they are the contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from pathlib import Path


# ── Enums ────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanMode(str, Enum):
    FULL = "full"
    QUICK = "quick"
    SECRETS_ONLY = "secrets_only"
    DEPS_ONLY = "deps_only"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Recon Report (A1 output) ────────────────────────────────────────────────

@dataclass
class ModuleInfo:
    name: str
    paths: list[str]
    risk: str = "medium"
    description: str = ""
    loc: int = 0  # lines of code


@dataclass
class EntryPoint:
    type: str  # "http_route", "cli_handler", "websocket", "grpc", "message_consumer", "cron"
    method: str = ""  # GET, POST, etc. (for HTTP)
    path: str = ""  # URL path or handler identifier
    file: str = ""
    line: int = 0
    auth_required: bool = True
    description: str = ""


@dataclass
class DataFlow:
    source: str  # where user input enters
    processing: list[str] = field(default_factory=list)  # intermediate steps
    sink: str = ""  # where data ends up (DB, template, exec, file, etc.)
    sanitization: str = ""  # what sanitization exists (if any)
    risk_notes: str = ""


@dataclass
class TrustBoundary:
    name: str
    from_zone: str
    to_zone: str
    crossing_points: list[str] = field(default_factory=list)  # files/functions where boundary is crossed
    notes: str = ""


@dataclass
class AuthMechanism:
    type: str  # "jwt", "session", "oauth2", "api_key", "basic", "custom"
    implementation_files: list[str] = field(default_factory=list)
    notes: str = ""
    weaknesses: list[str] = field(default_factory=list)


@dataclass
class ThirdPartyIntegration:
    name: str
    type: str  # "payment", "email", "storage", "auth_provider", "api", "sdk"
    config_files: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ReconReport:
    """Complete output of the A1 Recon agent."""
    tech_stack: dict = field(default_factory=dict)
    # Expected keys: languages, frameworks, databases, runtime, build_tools, testing_frameworks

    modules: list[ModuleInfo] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    auth_mechanisms: list[AuthMechanism] = field(default_factory=list)
    third_party_integrations: list[ThirdPartyIntegration] = field(default_factory=list)
    critical_files: list[str] = field(default_factory=list)  # files that deserve extra scrutiny
    total_loc: int = 0
    scan_notes: str = ""  # any observations from recon agent


# ── Engagement Config (CLI → A0) ────────────────────────────────────────────

@dataclass
class EngagementConfig:
    repo_path: str
    provider: str = "claude"       # AI provider: claude, openai, ollama
    model: str = ""                # model override (empty = provider default)
    api_key: str = ""              # API key override (providers read env by default)
    base_url: str = ""
    tokens: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)  # "user:pass" pairs
    scope: ScanMode = ScanMode.FULL
    validate: bool = False
    safe_only: bool = True
    output_dir: str = "./output"
    output_formats: list[str] = field(default_factory=lambda: ["md", "json"])
    severity_threshold: RiskLevel = RiskLevel.LOW
    tester_name: str = ""
    engagement_id: str = ""
    max_concurrent: int = 5
    verbose: bool = False
    skip_agents: list[str] = field(default_factory=list)
    ollama_host: str = ""          # Ollama server URL (default: http://localhost:11434)
    caveman: bool = False          # Terse caveman-style output (reduces token usage ~75%)


# ── Agent Run Tracking (A0 internal) ────────────────────────────────────────

@dataclass
class AgentRun:
    agent_name: str
    status: AgentStatus = AgentStatus.PENDING
    scope: str = ""  # which module/vuln class this run covers
    output_file: str = ""
    duration_seconds: float = 0.0
    finding_count: int = 0
    error: str = ""


# ── Serialization Helpers ────────────────────────────────────────────────────

def to_json(obj, indent: int = 2) -> str:
    """Serialize a dataclass to JSON string."""
    return json.dumps(asdict(obj), indent=indent, default=str)


def save_json(obj, path: str | Path) -> None:
    """Serialize a dataclass to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(obj))


def load_recon_report(path: str | Path) -> dict:
    """Load a recon report JSON file as a plain dict (for prompt injection)."""
    return json.loads(Path(path).read_text())
