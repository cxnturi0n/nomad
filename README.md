# Nomad — Multi-Agent Source Code Security Audit

A provider-agnostic, multi-agent penetration testing pipeline for source code review. Each agent specializes in a different phase of the assessment — from reconnaissance to exploit validation — coordinated by a deterministic Python orchestrator.

Works with **Claude**, **OpenAI**, or local **Ollama** models.

## Prerequisites

- **Python 3.10+**
- **One AI provider:**

| Provider | Setup |
|---|---|
| Claude (default) | `npm install -g @anthropic-ai/claude-code && claude auth login` |
| OpenAI Codex CLI | `npm install -g @openai/codex && export OPENAI_API_KEY=sk-...` |
| OpenAI API | `pip install openai && export OPENAI_API_KEY=sk-...` |
| Ollama (local) | `curl -fsSL https://ollama.com/install.sh \| sh && ollama pull qwen2.5-coder:32b` |

- **Optional tools** (improves results when installed):

| Tool | What it does | Install |
|---|---|---|
| Semgrep | AST-aware pattern matching (secrets, SQLi, XSS, OWASP) | `pipx install semgrep` |
| TruffleHog | Entropy-based secret detection | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sudo sh -s -- -b /usr/local/bin` |
| npm | Node.js dependency auditing | `sudo apt install npm` |
| pip-audit | Python dependency auditing | `pipx install pip-audit` |
| osv-scanner | Universal dependency scanner (Go, Java, Rust, etc.) | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |

## Quick Start

```bash
# Full scan with Claude
python3 nomad --repo /path/to/target-app

# OpenAI
python3 nomad --repo /path/to/target-app --provider openai --model o4-mini

# Ollama (free, offline)
python3 nomad --repo /path/to/target-app --provider ollama --model qwen2.5-coder:32b

# Quick scan, verbose
python3 nomad --repo /path/to/target-app --scope quick -v

# Full scan + active exploit validation against a running app
python3 nomad --repo /path/to/target-app \
  --validate --base-url http://localhost:3000 \
  --creds "admin:password123" --safe-only

# Skip slow agents
python3 nomad --repo /path/to/target-app --skip deps triage

# Only recon + static analysis
python3 nomad --repo /path/to/target-app --skip secrets deps triage fingerprint validation
```

## Agent Pipeline

```
A0  Orchestrator (deterministic Python — not an LLM)
 │
 ├─ A1  Recon ................. ✅  Maps codebase architecture, entry points, data flows
 ├─ A2  Static Analysis ....... ✅  Hunts vulnerabilities across 30+ CWE classes (+ Semgrep SAST)
 ├─ A3  Secrets Scanner ....... ✅  Hardcoded credentials, API keys, tokens (+ Semgrep secrets, TruffleHog)
 ├─ A4  Dependency Audit ...... ✅  Vulnerable packages, supply chain risks (+ npm audit, pip-audit, osv-scanner)
 ├─ A5  Triage & Dedup ........ ✅  Merges findings, identifies attack chains, assigns CVSS 3.1
 ├─ A6 Fingerprint ...........  ✅  Probes running app: WAF detection, bypass hints, defense profiling
 ├─ A7  Validation ............ ✅  Active exploit testing with adaptive WAF bypass
 └─ A8  Reporting ............. ⬜  Planned
```

### How agents connect

```
A1 Recon → A2 Static Analysis ─┐
         → A3 Secrets Scanner  ─┤→ A6 Triage & Dedup
         → A4 Dependency Audit ─┘         │
                                          ├─→ AFP Fingerprint (probes live app)
                                          └─→ A7  Validation  (exploits with fingerprint intel)
```

A1 feeds every downstream agent. A2/A3/A4 run independently and produce findings. A6 merges, deduplicates, identifies attack chains, and assigns CVSS scores. AFP fingerprints the running application's defenses (WAFs, rate limiting, security headers). A7 uses the fingerprint data to select optimal payloads and bypass techniques.

## CLI Reference

| Flag | Description | Default |
|---|---|---|
| `--repo` | Path to target repository (**required**) | — |
| `--provider` | `claude`, `openai`, `ollama` | `claude` |
| `--model` | Strong model override | auto per provider |
| `--model-light` | Cheaper model (same provider) for low-stakes agents; enables tiered execution | — (single model) |
| `--light-agents` | Override which agents use `--model-light` | secrets, deps, fingerprint |
| `--effort` | Reasoning effort (Claude only): `low`/`medium`/`high`/`max`; applied to both tiers | provider default |
| `--api-key` | API key override | env var |
| `--ollama-host` | Ollama server URL | `localhost:11434` |
| `--scope` | `full`, `quick`, `secrets_only`, `deps_only` | `full` |
| `--severity-threshold` | `critical`, `high`, `medium`, `low`, `info` | `low` |
| `--skip` | Agents to skip: `static`, `secrets`, `deps`, `triage`, `fingerprint`, `validation` | none |
| `--validate` | Enable active exploit testing (AFP + A7) | off |
| `--safe-only` / `--no-safe-only` | Non-destructive PoCs only; `--no-safe-only` permits destructive tests | `true` |
| `--base-url` | Running app URL (required with `--validate`) | — |
| `--tokens` | Auth tokens for validation | — |
| `--creds` | Credentials for validation (`user:pass`) | — |
| `--output-dir` | Report output directory | `./output` |
| `--format` | `md`, `json`, `pdf` | `md,json` |
| `--tester` | Tester name for report | — |
| `--engagement-id` | Engagement ID for report | — |
| `-v, --verbose` | Show agent reasoning | off |
| `--caveman` | Terse agent output via [caveman plugin](https://github.com/JuliusBrussee/caveman) — reduces token usage ~75% | off |

## Provider Comparison

| Capability | Claude Code | OpenAI Codex | Ollama |
|---|---|---|---|
| Agentic (iterative file browsing) | ✓ | ✓ | ✗ (single-shot) |
| Shell command execution | ✓ | ✓ | ✗ |
| File read/write | ✓ | ✓ | ✗ (pre-loaded) |
| Offline / free | ✗ | ✗ | ✓ |
| Best for | Full scans, large repos | Full scans | Quick scans, small repos |

Agentic providers (Claude, OpenAI) iteratively explore the codebase — read a file, decide what to read next, run commands. Ollama runs in single-shot mode where Nomad pre-reads source files and injects them into the prompt context.

**`--validate` requires an agentic provider.** The fingerprint and validation agents must execute live HTTP requests (`curl`), so on single-shot providers (Ollama, or OpenAI API-fallback mode) they are **skipped** rather than fabricating untested results. Recon also degrades on single-shot providers (no live file browsing) and logs a warning.

## Model Tiering (token optimization)

By default every agent uses one model (`--model`). To cut token cost, route the
reasoning-light agents to a cheaper model and reserve the strong model for the
agents that actually need deep reasoning.

```bash
# Opus 4.8 for the hard agents (recon, static, triage, validation),
# Sonnet 4.6 for the rest (secrets, deps, fingerprint), high reasoning on both
python3 nomad --repo /path/to/app \
  --model claude-opus-4-8 \
  --model-light claude-sonnet-4-6 \
  --effort high
```

- **Strong (default):** `recon`, `static`, `triage`, `validation` — map building, vulnerability hunting, correlation/CVSS, exploit crafting.
- **Light (`--model-light`):** `secrets`, `deps`, `fingerprint` — these mainly validate the output of CLI tools (TruffleHog, Semgrep, npm/pip/osv audit, curl), so a smaller model is usually enough.

Override the split with `--light-agents` (recon is allowed here):

```bash
# Maximum savings: also push the token-heavy recon pass onto the light model
python3 nomad --repo /path/to/app \
  --model claude-opus-4-8 --model-light claude-haiku-4-5 \
  --light-agents secrets deps fingerprint recon
```

Notes:
- `--model-light` must be the **same provider** as `--model`. Cross-provider tiering (e.g. bulk on local Ollama, validation on Claude) is not yet supported.
- Both tiers are preflighted at startup (for Ollama, each model must be pulled).
- Without `--model-light`, behaviour is unchanged: one model for all agents.

## Output Structure

```
output/
├── nomad.log                            # Full execution log
├── scaling_plan.json                    # How the orchestrator partitioned work
├── recon/
│   └── a1_recon_output.json             # Codebase architecture map
├── analysis/
│   ├── a2_static_full_repo_output.json  # Per-partition findings
│   └── findings_static_merged.json      # Merged static analysis findings
├── secrets/
│   └── a3_secrets_output.json           # Secrets scan findings
├── deps/
│   └── a4_deps_output.json              # Dependency audit findings
├── triage/
│   └── a6_triage_output.json            # Deduplicated, CVSS-scored, prioritized findings
├── fingerprint/
│   └── a_fp_fingerprint_output.json     # Target defense profile (WAF, headers, endpoints)
└── validation/
    └── a7_validation_output.json        # Exploit confirmation with PoC evidence
```

## Architecture

```
nomad                          ← A0 Orchestrator + CLI entry point
├── agents/
│   ├── base.py                   ← BaseAgent (provider-agnostic contract)
│   ├── recon.py                  ← A1 Recon
│   ├── static_analysis.py        ← A2 Static Analysis
│   ├── secrets.py                ← A3 Secrets (+ Semgrep/TruffleHog integration)
│   ├── dependency_audit.py       ← A4 Dependency Audit (+ npm audit/pip-audit/osv-scanner)
│   ├── triage.py                 ← A6 Triage & Deduplication
│   ├── fingerprint.py            ← AFP Target Fingerprinting
│   ├── validation.py             ← A7 Exploit Validation
│   └── prompts/
│       ├── recon.md              ← A1 system prompt
│       ├── static_analysis.md    ← A2 system prompt
│       ├── secrets.md            ← A3 system prompt
│       ├── dependency_audit.md   ← A4 system prompt
│       ├── triage.md             ← A6 system prompt
│       ├── fingerprint.md        ← AFP system prompt
│       └── validation.md         ← A7 system prompt
├── models/
│   └── schemas.py                ← Shared dataclasses (EngagementConfig, AgentRun, etc.)
└── utils/
    └── runners/
        ├── base.py               ← BaseRunner interface + RunResult + JSON extraction
        ├── claude.py             ← Claude Code CLI runner
        ├── openai.py             ← OpenAI Codex CLI / API runner
        └── ollama.py             ← Ollama HTTP API runner
```

## Key Design Decisions

**The orchestrator is code, not an LLM.** `nomad` uses `if` statements, not AI, for routing and decisions. This keeps the pipeline predictable and debuggable.

**Agents communicate via JSON files.** No shared memory, no message passing. Each agent writes structured JSON output. The orchestrator reads it and injects relevant parts into the next agent's prompt.

**Agents never know which AI runs them.** They define a system prompt and task prompt, call `self.runner.run(...)`, and get back a `RunResult`. Swapping providers is a CLI flag.

**Hybrid tool + LLM approach.** A2, A3, and A4 run CLI security tools first, then feed raw results to the LLM for validation, deduplication, and enrichment. A2 gets Semgrep SAST (SQLi/XSS/command-injection/OWASP), A3 gets Semgrep secret rules + TruffleHog, A4 gets npm/pip/osv audit. Semgrep SAST runs once per repo and is cached across analysis partitions. Tools catch known patterns fast; the LLM confirms, removes false positives, and finds what they miss.

**Fingerprint-informed exploitation.** AFP probes the target's defenses before A7 runs. A7 receives WAF vendor, bypass hints, and input vector analysis — so it picks the right payload technique on the first attempt instead of wasting rounds re-discovering what's blocked.

**Scaling is partition-based.** For large repos, the orchestrator splits work by module and/or vulnerability class based on A1's LOC estimates: under 5K LOC = single pass, under 50K = split by module, over 50K = module × vulnerability class matrix.

## Security

Nomad runs AI agents that read **untrusted target source code** and execute shell commands in the repo. Treat every engagement as potentially hostile input:

- **Sandbox untrusted targets.** Run Nomad in a network-isolated container/VM when scanning code you don't trust — a malicious repo can attempt prompt-injection to make an agent run commands.
- **Network deny-list (Claude).** Read-only agents (recon, static, secrets, deps, triage) are denied `WebFetch` and shell network tools (`curl`, `wget`, `nc`, `ssh`, …) via `--disallowedTools`. This is defense-in-depth, **not** a sandbox — a determined payload can still egress via `python`/`perl`/etc.
- **Live testing is opt-in and scoped.** Fingerprint and validation run only with `--validate` and only target `--base-url`. Only test systems you are authorized to test.
- **`--no-safe-only` enables destructive PoCs.** Off by default (safe mode permits non-destructive tests only, incl. boolean/time-based blind SQLi). Use only with explicit authorization.
- **Secrets in prompts.** `--creds` / `--tokens` are injected into the validation agent's prompt. Avoid `-v` verbose logging in shared environments.

## Adding a New Provider

1. Create `utils/runners/your_provider.py` implementing `BaseRunner`
2. Register it in `utils/runners/__init__.py` → `PROVIDERS` dict
3. Done — all agents work with it automatically

## Adding a New Agent

1. Create `agents/prompts/your_agent.md` (system prompt)
2. Create `agents/your_agent.py` extending `BaseAgent`
3. Wire it into `nomad`'s pipeline
4. Add its skip key to the `valid_skips` set in `parse_args`