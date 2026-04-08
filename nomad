#!/usr/bin/env python3
"""
nomad: Multi-agent source code security review — provider-agnostic.

A0 ORCHESTRATOR
================
This is NOT an LLM agent — it's a deterministic Python program that:
  1. Parses nomadI arguments
  2. Creates the appropriate AI provider runner
  3. Runs agents in the correct order
  4. Passes context between agents
  5. Manages scaling (parallel sub-agent calls for large repos)
  6. Tracks progress and handles errors

Supported providers:
  nomad.pyaude  — Claude Code CLI (agentic, full tool use)
  openai  — OpenAI Codex CLI or API (agentic CLI / single-shot API)
  ollama  — Ollama local models (single-shot, file context injected)

Usage:
  python nomad.py --repo ./target-app
  python nomad.py --repo ./target-app --provider ollama --model qwen2.5-coder:32b
  python nomad.py --repo ./target-app --provider openai --model o4-mini
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent))

from models.schemas import (
    EngagementConfig,
    ScanMode,
    RiskLevel,
    AgentStatus,
    AgentRun,
)
from utils.runners import create_runner, list_providers, BaseRunner
from agents.recon import ReconAgent
from agents.static_analysis import StaticAnalysisAgent
from agents.secrets import SecretsAgent
from agents.dependency_audit import DependencyAuditAgent
from agents.triage import TriageAgent
from agents.fingerprint import FingerprintAgent
from agents.validation import ValidationAgent


# ── Logging Setup ────────────────────────────────────────────────────────────

def setup_logging(verbose: bool, log_file: Path) -> None:
    """Configure logging to both console and file."""
    log_file.parent.mkdir(parents=True, exist_ok=True)

    fmt = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
    datefmt = "%H:%M:%S"

    file_handler = logging.FileHandler(log_file, mode="w")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(fmt, datefmt))

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter(fmt, datefmt))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


logger = logging.getLogger("nomad.orchestrator")


# ── CLI Argument Parsing ─────────────────────────────────────────────────────

def parse_args() -> EngagementConfig:
    parser = argparse.ArgumentParser(
        prog="nomad",
        description="Multi-agent source code security review — provider-agnostic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with Claude (default)
  %(prog)s --repo ./my-app

  # Use local Ollama model
  %(prog)s --repo ./my-app --provider ollama --model qwen2.5-coder:32b

  # Use OpenAI
  %(prog)s --repo ./my-app --provider openai --model o4-mini

  # Quick scan, only report high+ severity
  %(prog)s --repo ./my-app --scope quick --severity-threshold high

  # Full scan with validation
  %(prog)s --repo ./my-app --validate --creds "admin:password" --base-url https://staging.example.com

  # Skip dependency audit and secrets scan
  %(prog)s --repo ./my-app --skip deps secrets

  # Only recon + static analysis
  %(prog)s --repo ./my-app --skip secrets deps triage fingerprint validation
        """,
    )

    # Required
    parser.add_argument(
        "--repo", required=True,
        help="Path to the target source code repository",
    )

    # Provider selection
    parser.add_argument(
        "--provider", choices=list_providers(), default="claude",
        help=f"AI provider (default: claude). Available: {', '.join(list_providers())}",
    )
    parser.add_argument(
        "--model", default="",
        help="Model override (provider-specific). Defaults: claude=default, openai=o4-mini, ollama=qwen2.5-coder:32b",
    )
    parser.add_argument(
        "--api-key", default="",
        help="API key override (most providers read from env vars by default)",
    )
    parser.add_argument(
        "--ollama-host", default="",
        help="Ollama server URL (default: http://localhost:11434)",
    )

    # Scope & mode
    parser.add_argument(
        "--scope", choices=["full", "quick", "secrets_only", "deps_only"], default="full",
        help="Scan scope (default: full)",
    )
    parser.add_argument(
        "--severity-threshold", choices=["critical", "high", "medium", "low", "info"], default="low",
        help="Minimum severity to report (default: low)",
    )

    # Validation (A7)
    parser.add_argument("--validate", action="store_true", help="Enable active validation (A7)")
    parser.add_argument("--safe-only", action="store_true", default=True, help="Non-destructive PoCs only (default: true)")
    parser.add_argument("--base-url", default="", help="Running app URL (required for --validate)")
    parser.add_argument("--tokens", nargs="*", default=[], help="Auth tokens for validation")
    parser.add_argument("--creds", nargs="*", default=[], help="Credentials for validation (user:pass)")

    # Output
    parser.add_argument("--output-dir", default="./output", help="Output directory (default: ./output)")
    parser.add_argument("--format", default="md,json", help="Output formats: md, json, pdf (default: md,json)")

    # Engagement metadata
    parser.add_argument("--tester", default="", help="Tester name for the report")
    parser.add_argument("--engagement-id", default="", help="Engagement ID for the report")

    # Execution
    parser.add_argument("--max-concurrent", type=int, default=5, help="Max parallel agents (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--skip", nargs="*", default=[],
        metavar="AGENT",
        help="Agents to skip: static, secrets, deps, triage, fingerprint, validation. Recon cannot be skipped.",
    )
    parser.add_argument(
        "--fresh", action="store_true",
        help="Ignore checkpoint and start fresh (deletes previous output)",
    )

    args = parser.parse_args()

    # Resolve repo path
    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        parser.error(f"Repository path does not exist: {repo_path}")

    if args.validate and not args.base_url:
        parser.error("--validate requires --base-url")

    # Validate --skip values
    valid_skips = {"static", "secrets", "deps", "triage", "fingerprint", "validation"}
    for s in args.skip:
        if s == "recon":
            parser.error("Recon cannot be skipped — all agents depend on it")
        if s not in valid_skips:
            parser.error(f"Unknown agent '{s}' in --skip. Valid: {', '.join(sorted(valid_skips))}")

    return EngagementConfig(
        repo_path=str(repo_path),
        provider=args.provider,
        model=args.model,
        api_key=args.api_key,
        base_url=args.base_url,
        tokens=args.tokens,
        credentials=args.creds,
        scope=ScanMode(args.scope),
        validate=args.validate,
        safe_only=args.safe_only,
        output_dir=args.output_dir,
        output_formats=args.format.split(","),
        severity_threshold=RiskLevel(args.severity_threshold),
        tester_name=args.tester,
        engagement_id=args.engagement_id,
        max_concurrent=args.max_concurrent,
        verbose=args.verbose,
        ollama_host=args.ollama_host,
        skip_agents=args.skip,
    )


# ── Runner Factory ───────────────────────────────────────────────────────────

def create_runner_from_config(config: EngagementConfig) -> BaseRunner:
    """Create the appropriate runner based on CLI config."""
    kwargs = {}

    if config.model:
        kwargs["model"] = config.model
    if config.api_key:
        kwargs["api_key"] = config.api_key

    # Provider-specific config
    if config.provider == "ollama" and config.ollama_host:
        kwargs["api_base"] = config.ollama_host

    return create_runner(config.provider, **kwargs)


# ── Scaling Engine ───────────────────────────────────────────────────────────

class ScalingEngine:
    """
    Decides how to partition work for downstream agents based on recon output.

    Thresholds:
      - < 5K LOC:  single-pass (no splitting)
      - < 50K LOC: horizontal (split by module)
      - > 50K LOC: hybrid (module × vuln class matrix)
    """

    SMALL_THRESHOLD = 5_000
    LARGE_THRESHOLD = 50_000

    def __init__(self, recon_report: dict, config: EngagementConfig):
        self.recon = recon_report
        self.config = config
        self.total_loc = recon_report.get("repo_stats", {}).get("total_loc", 0)
        self.modules = recon_report.get("modules", [])

    def get_strategy(self) -> str:
        if self.total_loc < self.SMALL_THRESHOLD:
            return "single_pass"
        elif self.total_loc < self.LARGE_THRESHOLD:
            return "horizontal"
        else:
            return "hybrid"

    def get_partitions(self) -> list[dict]:
        strategy = self.get_strategy()

        if strategy == "single_pass":
            return [{
                "scope_name": "full_repo",
                "paths": ["."],
                "risk": "high",
                "context_files": self._all_critical_files(),
            }]

        partitions = []
        for mod in self._prioritized_modules():
            if self.config.scope == ScanMode.QUICK and mod.get("risk") == "low":
                continue
            partitions.append({
                "scope_name": mod["name"],
                "paths": mod.get("paths", []),
                "risk": mod.get("risk", "medium"),
                "context_files": self._cross_cutting_files(mod),
            })

        shared = self._get_shared_files()
        if shared:
            partitions.append({
                "scope_name": "cross_cutting",
                "paths": shared,
                "risk": "high",
                "context_files": [],
            })

        return partitions

    def _prioritized_modules(self) -> list[dict]:
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            self.modules,
            key=lambda m: (risk_order.get(m.get("risk", "medium"), 2), -m.get("loc_estimate", 0)),
        )

    def _all_critical_files(self) -> list[str]:
        """Flatten the critical_files object into a single list."""
        cf = self.recon.get("critical_files", {})
        if isinstance(cf, list):
            return cf
        if isinstance(cf, dict):
            files = []
            for category_files in cf.values():
                if isinstance(category_files, list):
                    files.extend(category_files)
            return files
        return []

    def _cross_cutting_files(self, module: dict) -> list[str]:
        critical = set(self._all_critical_files())
        own_paths = set(module.get("paths", []))
        return [f for f in critical if not any(f.startswith(p) for p in own_paths)]

    def _get_shared_files(self) -> list[str]:
        all_module_paths = set()
        for mod in self.modules:
            all_module_paths.update(mod.get("paths", []))
        return [
            f for f in self._all_critical_files()
            if not any(f.startswith(p) for p in all_module_paths)
        ]


# ── Pipeline Runner ──────────────────────────────────────────────────────────

class Pipeline:
    CHECKPOINT_FILE = "checkpoint.json"

    def __init__(self, config: EngagementConfig, runner: BaseRunner):
        self.config = config
        self.runner = runner
        self.output_dir = Path(config.output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.runs: list[AgentRun] = []
        self.recon_report: dict | None = None
        self.scaling_engine: ScalingEngine | None = None
        # Collected findings for triage
        self.static_findings: dict = {}
        self.secrets_findings: dict = {}
        self.deps_findings: dict = {}
        self.triaged_findings: dict = {}
        self.fingerprint_data: dict = {}
        # Checkpoint state
        self.completed_phases: set[str] = set()
        self._load_checkpoint()

    def _checkpoint_path(self) -> Path:
        return self.output_dir / self.CHECKPOINT_FILE

    def _load_checkpoint(self) -> None:
        """Load previous run state if checkpoint exists."""
        cp = self._checkpoint_path()
        if not cp.exists():
            return

        try:
            data = json.loads(cp.read_text())
            self.completed_phases = set(data.get("completed_phases", []))

            if self.completed_phases:
                logger.info(f"Checkpoint found: {', '.join(sorted(self.completed_phases))} already completed")

                # Reload saved outputs
                if "recon" in self.completed_phases:
                    recon_file = self.output_dir / "recon" / "a1_recon_output.json"
                    if recon_file.exists():
                        self.recon_report = json.loads(recon_file.read_text())

                if "static" in self.completed_phases:
                    merged_file = self.output_dir / "analysis" / "findings_static_merged.json"
                    if merged_file.exists():
                        self.static_findings = json.loads(merged_file.read_text())

                if "secrets" in self.completed_phases:
                    secrets_file = self.output_dir / "secrets" / "a3_secrets_output.json"
                    if secrets_file.exists():
                        self.secrets_findings = json.loads(secrets_file.read_text())

                if "deps" in self.completed_phases:
                    deps_file = self.output_dir / "deps" / "a4_deps_output.json"
                    if deps_file.exists():
                        self.deps_findings = json.loads(deps_file.read_text())

                if "triage" in self.completed_phases:
                    triage_file = self.output_dir / "triage" / "a6_triage_output.json"
                    if triage_file.exists():
                        self.triaged_findings = json.loads(triage_file.read_text())

                if "fingerprint" in self.completed_phases:
                    fp_file = self.output_dir / "fingerprint" / "a_fp_fingerprint_output.json"
                    if fp_file.exists():
                        self.fingerprint_data = json.loads(fp_file.read_text())

        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not load checkpoint: {e}. Starting fresh.")
            self.completed_phases = set()

    def _save_checkpoint(self, phase: str) -> None:
        """Mark a phase as completed and save checkpoint."""
        self.completed_phases.add(phase)
        data = {
            "completed_phases": sorted(self.completed_phases),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo": self.config.repo_path,
        }
        self._checkpoint_path().write_text(json.dumps(data, indent=2))
        logger.debug(f"Checkpoint saved: {phase} completed")

    def _phase_done(self, phase: str) -> bool:
        """Check if a phase already completed in a previous run."""
        return phase in self.completed_phases

    def run(self) -> bool:
        start = time.time()
        self._print_banner()

        if self.config.skip_agents:
            logger.info(f"  Skipping:   {', '.join(self.config.skip_agents)}")
        if self.completed_phases:
            logger.info(f"  Resuming:   {', '.join(sorted(self.completed_phases))} already done")
        logger.info("")

        # ── Phase 1: Recon ───────────────────────────────────────────
        logger.info("=" * 60)
        logger.info("PHASE 1: RECONNAISSANCE")
        logger.info("=" * 60)

        if self._phase_done("recon"):
            logger.info("Resumed from checkpoint — skipping")
            if not self.recon_report:
                logger.error("Checkpoint says recon done but no output found. Use --fresh.")
                return False
        else:
            recon = ReconAgent(self.config, self.output_dir / "recon", self.runner)
            run = recon.run()
            self.runs.append(run)

            if run.status != AgentStatus.COMPLETED:
                logger.error(f"Recon failed: {run.error}")
                logger.error("Cannot proceed without reconnaissance. Aborting.")
                self._print_summary(time.time() - start)
                return False

            self.recon_report = json.loads(recon.output_file.read_text())
            self._save_checkpoint("recon")

        self._print_recon_summary()

        # Initialize scaling
        self.scaling_engine = ScalingEngine(self.recon_report, self.config)
        strategy = self.scaling_engine.get_strategy()
        partitions = self.scaling_engine.get_partitions()
        logger.info(f"Scaling strategy: {strategy} ({len(partitions)} partition(s))")
        for p in partitions:
            logger.info(f"  → [{p['risk'].upper():8s}] {p['scope_name']}: {p['paths']}")

        (self.output_dir / "scaling_plan.json").write_text(
            json.dumps({"strategy": strategy, "partitions": partitions}, indent=2)
        )

        # ── Phase 2: Static Analysis (A2) ──────────────────────────
        logger.info("=" * 60)
        logger.info("PHASE 2: STATIC ANALYSIS")
        logger.info("=" * 60)

        if not self._should_run("static"):
            logger.info("Skipped (--skip static)")
        elif self._phase_done("static"):
            logger.info("Resumed from checkpoint — skipping")
        else:
            static_findings = []
            for partition in partitions:
                scope_name = partition["scope_name"]
                logger.info(f"Running static analysis on: {scope_name}")

                a2 = StaticAnalysisAgent(
                    self.config,
                    self.output_dir / "analysis",
                    self.runner,
                    scope_name=scope_name,
                )
                context = {
                    "recon_report": self.recon_report,
                    "partition": partition,
                    "max_findings": 25 if len(partitions) <= 2 else 15,
                }
                run = a2.run(context=context)
                self.runs.append(run)

                if run.status == AgentStatus.COMPLETED:
                    try:
                        findings = json.loads(a2.output_file.read_text())
                        static_findings.append(findings)
                    except (json.JSONDecodeError, FileNotFoundError) as e:
                        logger.warning(f"Could not load findings from {scope_name}: {e}")
                else:
                    logger.warning(f"Static analysis failed for {scope_name}: {run.error}")

            if static_findings:
                merged = self._merge_static_findings(static_findings)
                merged_path = self.output_dir / "analysis" / "findings_static_merged.json"
                merged_path.write_text(json.dumps(merged, indent=2))
                self.static_findings = merged
                total = merged.get("summary", {}).get("total_findings", 0)
                by_sev = merged.get("summary", {}).get("by_severity", {})
                logger.info(
                    f"Static analysis complete: {total} total findings "
                    f"(critical={by_sev.get('critical', 0)}, high={by_sev.get('high', 0)}, "
                    f"medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)})"
                )
            self._save_checkpoint("static")

        # ── Phase 3: Secrets Scanning (A3) ────────────────────────
        logger.info("=" * 60)
        logger.info("PHASE 3: SECRETS SCANNING")
        logger.info("=" * 60)

        if not self._should_run("secrets"):
            logger.info("Skipped (--skip secrets)")
        elif self._phase_done("secrets"):
            logger.info("Resumed from checkpoint — skipping")
        else:
            a3 = SecretsAgent(
                self.config,
                self.output_dir / "secrets",
                self.runner,
            )
            context_a3 = {"recon_report": self.recon_report}
            run_a3 = a3.run(context=context_a3)
            self.runs.append(run_a3)

            if run_a3.status == AgentStatus.COMPLETED:
                try:
                    secrets_data = json.loads(a3.output_file.read_text())
                    self.secrets_findings = secrets_data
                    tool_results = secrets_data.get("tool_results", {})
                    for tool_name, tool_info in tool_results.items():
                        if tool_info.get("ran"):
                            logger.info(
                                f"  {tool_name}: {tool_info.get('findings_raw', 0)} raw → "
                                f"{tool_info.get('findings_confirmed', 0)} confirmed, "
                                f"{tool_info.get('findings_false_positive', 0)} false positives"
                            )
                        elif not tool_info.get("available"):
                            logger.info(f"  {tool_name}: not installed (skipped)")
                except (json.JSONDecodeError, FileNotFoundError) as e:
                    logger.warning(f"Could not load secrets findings: {e}")
            else:
                logger.warning(f"Secrets scan failed: {run_a3.error}")
            self._save_checkpoint("secrets")

        # ── Phase 4: Dependency Audit (A4) ──────────────────────────
        logger.info("=" * 60)
        logger.info("PHASE 4: DEPENDENCY AUDIT")
        logger.info("=" * 60)

        if not self._should_run("deps"):
            logger.info("Skipped (--skip deps)")
        elif self._phase_done("deps"):
            logger.info("Resumed from checkpoint — skipping")
        else:
            a4 = DependencyAuditAgent(
                self.config,
                self.output_dir / "deps",
                self.runner,
            )
            context_a4 = {"recon_report": self.recon_report}
            run_a4 = a4.run(context=context_a4)
            self.runs.append(run_a4)

            if run_a4.status == AgentStatus.COMPLETED:
                try:
                    deps_data = json.loads(a4.output_file.read_text())
                    self.deps_findings = deps_data
                    overview = deps_data.get("dependency_overview", {})
                    if overview:
                        logger.info(
                            f"  Ecosystem: {overview.get('ecosystem', '?')} | "
                            f"Direct: {overview.get('total_direct', '?')} | "
                            f"Transitive: {overview.get('total_transitive', '?')} | "
                            f"Lockfile: {overview.get('lockfile_present', '?')}"
                        )
                    tool_results = deps_data.get("tool_results", {})
                    for tool_name, tool_info in tool_results.items():
                        if tool_info.get("ran"):
                            logger.info(
                                f"  {tool_name}: {tool_info.get('findings_raw', 0)} raw → "
                                f"{tool_info.get('findings_confirmed', 0)} confirmed"
                            )
                        elif not tool_info.get("available"):
                            logger.info(f"  {tool_name}: not installed (skipped)")
                except (json.JSONDecodeError, FileNotFoundError) as e:
                    logger.warning(f"Could not load dependency findings: {e}")
            else:
                logger.warning(f"Dependency audit failed: {run_a4.error}")
            self._save_checkpoint("deps")

        # ── Phase 5: Triage & Deduplication (A6) ─────────────────────
        logger.info("=" * 60)
        logger.info("PHASE 5: TRIAGE & DEDUPLICATION")
        logger.info("=" * 60)

        if not self._should_run("triage"):
            logger.info("Skipped (--skip triage)")
        elif self._phase_done("triage"):
            logger.info("Resumed from checkpoint — skipping")
        else:
            total_input = (
                len(self.static_findings.get("findings", []))
                + len(self.secrets_findings.get("findings", []))
                + len(self.deps_findings.get("findings", []))
            )
            logger.info(f"Triaging {total_input} total findings from A2+A3+A4...")

            a6 = TriageAgent(
                self.config,
                self.output_dir / "triage",
                self.runner,
            )
            context_a6 = {
                "recon_report": self.recon_report,
                "static_findings": self.static_findings,
                "secrets_findings": self.secrets_findings,
                "deps_findings": self.deps_findings,
                "severity_threshold": self.config.severity_threshold.value,
            }
            run_a6 = a6.run(context=context_a6)
            self.runs.append(run_a6)

            if run_a6.status == AgentStatus.COMPLETED:
                try:
                    triage_data = json.loads(a6.output_file.read_text())
                    self.triaged_findings = triage_data
                    summary = triage_data.get("summary", {})
                    chains = triage_data.get("attack_chains", [])
                    logger.info(
                        f"  Input: {summary.get('total_input_findings', '?')} → "
                        f"Output: {summary.get('total_output_findings', '?')} "
                        f"({summary.get('duplicates_removed', 0)} duplicates removed)"
                    )
                    if chains:
                        logger.info(f"  Attack chains identified: {len(chains)}")
                        for chain in chains:
                            logger.info(f"    → {chain.get('title', '?')}")
                except (json.JSONDecodeError, FileNotFoundError) as e:
                    logger.warning(f"Could not load triage results: {e}")
            else:
                logger.warning(f"Triage failed: {run_a6.error}")
            self._save_checkpoint("triage")

        # ── Phase 6: Fingerprint + Validation — opt-in only ──────────
        if self.config.validate:
            # ── Phase 6a: Fingerprint ────────────────────────────────
            logger.info("=" * 60)
            logger.info("PHASE 6a: TARGET FINGERPRINTING")
            logger.info("=" * 60)

            if not self._should_run("fingerprint"):
                logger.info("Skipped (--skip fingerprint)")
            elif self._phase_done("fingerprint"):
                logger.info("Resumed from checkpoint — skipping")
            else:
                logger.info(f"Fingerprinting {self.config.base_url}...")

                a_fp = FingerprintAgent(
                    self.config,
                    self.output_dir / "fingerprint",
                    self.runner,
                )
                context_fp = {"recon_report": self.recon_report}
                run_fp = a_fp.run(context=context_fp)
                self.runs.append(run_fp)

                if run_fp.status == AgentStatus.COMPLETED:
                    try:
                        self.fingerprint_data = json.loads(a_fp.output_file.read_text())
                        waf = self.fingerprint_data.get("waf", {})
                        if waf.get("detected"):
                            logger.info(
                                f"  WAF detected: {waf.get('vendor', 'unknown')} "
                                f"(confidence: {waf.get('confidence', '?')})"
                            )
                            for hint in waf.get("bypass_hints", [])[:3]:
                                logger.info(f"    → {hint}")
                        else:
                            logger.info("  No WAF detected")
                        rl = self.fingerprint_data.get("rate_limiting", {})
                        logger.info(f"  Rate limiting: {'yes' if rl.get('detected') else 'no'}")
                        missing = self.fingerprint_data.get("security_headers", {}).get("missing", [])
                        logger.info(f"  Missing security headers: {len(missing)}")
                        eps = self.fingerprint_data.get("endpoints_discovered", [])
                        logger.info(f"  Live endpoints discovered: {len(eps)}")
                    except (json.JSONDecodeError, FileNotFoundError) as e:
                        logger.warning(f"Could not load fingerprint data: {e}")
                else:
                    logger.warning(f"Fingerprinting failed: {run_fp.error}")
                self._save_checkpoint("fingerprint")

            # ── Phase 6b: Validation ─────────────────────────────────
            logger.info("=" * 60)
            logger.info("PHASE 6b: EXPLOIT VALIDATION")
            logger.info("=" * 60)

            if not self._should_run("validation"):
                logger.info("Skipped (--skip validation)")
            elif self._phase_done("validation"):
                logger.info("Resumed from checkpoint — skipping")
            elif not self.triaged_findings.get("findings"):
                logger.warning("No triaged findings to validate — skipping")
            else:
                finding_count = len(self.triaged_findings.get("findings", []))
                logger.info(
                    f"Validating {finding_count} findings against {self.config.base_url} "
                    f"(safe_only={self.config.safe_only})"
                )

                a7 = ValidationAgent(
                    self.config,
                    self.output_dir / "validation",
                    self.runner,
                )
                context_a7 = {
                    "triaged_findings": self.triaged_findings,
                    "fingerprint": self.fingerprint_data,
                }
                run_a7 = a7.run(context=context_a7)
                self.runs.append(run_a7)

                if run_a7.status == AgentStatus.COMPLETED:
                    try:
                        val_data = json.loads(a7.output_file.read_text())
                        vs = val_data.get("summary", {})
                        logger.info(
                            f"  Tested: {vs.get('tested', 0)} | "
                            f"Confirmed: {vs.get('confirmed', 0)} | "
                            f"Not exploitable: {vs.get('not_exploitable', 0)} | "
                            f"Needs review: {vs.get('needs_manual_review', 0)} | "
                            f"Untested: {vs.get('untested', 0)}"
                        )
                        if vs.get("confirmed_with_bypass", 0) > 0:
                            logger.info(f"  Confirmed with WAF bypass: {vs['confirmed_with_bypass']}")
                            for d in vs.get("defenses_bypassed", []):
                                logger.info(f"    → Bypassed: {d}")
                        for v in val_data.get("validations", []):
                            if v.get("status") == "confirmed":
                                bypass = f" [bypassed: {', '.join(v['defenses_bypassed'])}]" if v.get("defenses_bypassed") else ""
                                logger.info(f"    ✓ CONFIRMED: {v.get('finding_id')} — {v.get('title')}{bypass}")
                    except (json.JSONDecodeError, FileNotFoundError) as e:
                        logger.warning(f"Could not load validation results: {e}")
                else:
                    logger.warning(f"Validation failed: {run_a7.error}")
                self._save_checkpoint("validation")
        else:
            logger.info("Phase 6 (Fingerprint + Validation) skipped — use --validate to enable")

        logger.info("=" * 60)
        logger.info("PHASE 7: REPORTING — not yet implemented")
        logger.info("=" * 60)

        self._print_summary(time.time() - start)
        return True

    def _should_run(self, agent_key: str) -> bool:
        """Check if an agent should run based on --skip flag."""
        return agent_key not in self.config.skip_agents

    def _merge_static_findings(self, all_findings: list[dict]) -> dict:
        """Merge findings from multiple partition runs into a single result."""
        merged_findings = []
        all_files = set()
        finding_counter = 0

        for result in all_findings:
            for f in result.get("findings", []):
                finding_counter += 1
                f["id"] = f"VULN-{finding_counter:03d}"
                merged_findings.append(f)
            # Collect analyzed files
            summary = result.get("summary", {})
            for fpath in summary.get("files_analyzed", []):
                all_files.add(fpath)

        # Rebuild summary
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        for f in merged_findings:
            sev = f.get("severity", "medium")
            conf = f.get("confidence", "medium")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_confidence[conf] = by_confidence.get(conf, 0) + 1

        return {
            "findings": merged_findings,
            "summary": {
                "total_findings": len(merged_findings),
                "by_severity": by_severity,
                "by_confidence": by_confidence,
                "files_analyzed": sorted(all_files),
                "scope_notes": f"Merged from {len(all_findings)} partition(s)",
            },
        }

    def _print_banner(self) -> None:
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                        N O M A D                            ║
║          Multi-Agent Source Code Security Audit              ║
╚══════════════════════════════════════════════════════════════╝"""
        logger.info(banner)
        logger.info(f"  Provider:   {self.runner.provider_name} ({self.runner.get_model_display()})")
        logger.info(f"  Target:     {self.config.repo_path}")
        logger.info(f"  Scope:      {self.config.scope.value}")
        logger.info(f"  Validate:   {self.config.validate}")
        logger.info(f"  Output:     {self.output_dir}")
        logger.info(f"  Threshold:  {self.config.severity_threshold.value}+")
        logger.info(f"  Started:    {datetime.now(timezone.utc).isoformat()}")
        if self.config.tester_name:
            logger.info(f"  Tester:     {self.config.tester_name}")
        if self.config.engagement_id:
            logger.info(f"  Engagement: {self.config.engagement_id}")
        logger.info("")

    def _print_recon_summary(self) -> None:
        r = self.recon_report
        auth = r.get("auth", {})
        stats = r.get("repo_stats", {})
        obs = r.get("security_observations", [])
        logger.info("── Recon Results ──")
        logger.info(f"  Tech stack:    {_fmt_tech_stack(r.get('tech_stack', {}))}")
        logger.info(f"  Modules:       {len(r.get('modules', []))}")
        logger.info(f"  Entry points:  {len(r.get('entry_points', []))}")
        logger.info(f"  Data flows:    {len(r.get('data_flows', []))}")
        logger.info(f"  Auth:          {', '.join(auth.get('mechanisms', [])) or 'none detected'}")
        logger.info(f"  Total LOC:     {stats.get('total_loc', '?')}")
        if obs:
            logger.info(f"  Observations:  {len(obs)}")
            for o in obs[:3]:  # show first 3
                logger.info(f"    • {o[:120]}")
        logger.info("")

    def _print_summary(self, elapsed: float) -> None:
        logger.info("")
        logger.info("=" * 60)
        logger.info("PIPELINE SUMMARY")
        logger.info("=" * 60)
        for run in self.runs:
            icon = {
                AgentStatus.COMPLETED: "✓",
                AgentStatus.FAILED: "✗",
                AgentStatus.SKIPPED: "⊘",
                AgentStatus.RUNNING: "…",
                AgentStatus.PENDING: "·",
            }.get(run.status, "?")
            line = (
                f"  {icon} {run.agent_name:20s}  "
                f"{run.status.value:10s}  "
                f"{run.duration_seconds:6.1f}s  "
                f"{run.finding_count} items"
            )
            if run.error:
                line += f"  ERROR: {run.error}"
            logger.info(line)
        logger.info(f"\n  Provider:      {self.runner.provider_name} ({self.runner.get_model_display()})")
        logger.info(f"  Total elapsed: {elapsed:.1f}s")
        logger.info(f"  Output dir:    {self.output_dir}")
        logger.info("=" * 60)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _fmt_tech_stack(ts: dict) -> str:
    parts = []
    for fw in ts.get("frameworks", []):
        name = fw if isinstance(fw, str) else fw.get("name", "")
        ver = fw.get("version", "") if isinstance(fw, dict) else ""
        parts.append(f"{name} {ver}".strip())
    for lang in ts.get("languages", []):
        name = lang if isinstance(lang, str) else lang.get("name", "")
        parts.append(name)
    return ", ".join(parts) if parts else "unknown"


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    # Pre-parse --fresh before full parse (need it before pipeline init)
    import sys as _sys
    fresh = "--fresh" in _sys.argv

    config = parse_args()

    # Logging
    log_file = Path(config.output_dir) / "nomad.log"
    setup_logging(config.verbose, log_file)

    # Handle --fresh: clear checkpoint
    if fresh:
        cp = Path(config.output_dir) / Pipeline.CHECKPOINT_FILE
        if cp.exists():
            cp.unlink()
            logger.info("Fresh run: checkpoint cleared")

    # Create runner for the chosen provider
    try:
        runner = create_runner_from_config(config)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    # Preflight check
    ok, msg = runner.preflight()
    if not ok:
        logger.error(f"Provider preflight failed:\n{msg}")
        sys.exit(1)
    logger.info(f"Provider ready: {msg}")

    # Run pipeline
    pipeline = Pipeline(config, runner)
    success = pipeline.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()