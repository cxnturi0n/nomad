# Nomad — Multi-Agent Source Code Security Audit

A provider-agnostic, multi-agent security review pipeline. Each agent specializes in a different aspect of code analysis, coordinated by a deterministic Python orchestrator. Works with Claude, OpenAI, or local Ollama models.

## Prerequisites

- **Python 3.10+**
- **One of the following AI providers:**

| Provider | Setup |
|---|---|
| Claude (default) | `npm install -g @anthropic-ai/claude-code && claude auth login` |
| OpenAI Codex CLI | `npm install -g @openai/codex && export OPENAI_API_KEY=sk-...` |
| OpenAI API | `pip install openai && export OPENAI_API_KEY=sk-...` |
| Ollama (local) | `curl -fsSL https://ollama.com/install.sh \| sh && ollama pull qwen2.5-coder:32b` |

## Quick Start

```bash
# Claude (default provider)
python nomad.py --repo /path/to/target-app

# OpenAI
python nomad.py --repo /path/to/target-app --provider openai --model o4-mini

# Ollama (free, offline, local)
python nomad.py --repo /path/to/target-app --provider ollama --model qwen2.5-coder:32b

# Quick scan, verbose
python nomad.py --repo /path/to/target-app --scope quick -v

# With active validation
python nomad.py --repo /path/to/target-app \
  --validate --base-url https://staging.example.com \
  --creds "admin:password123" --tokens "Bearer eyJ..."
```

## Provider Comparison

| Capability | Claude Code | OpenAI Codex | Ollama |
|---|---|---|---|
| Agentic (iterative file browsing) | ✓ | ✓ | ✗ (single-shot) |
| Shell command execution | ✓ | ✓ | ✗ |
| File read/write | ✓ | ✓ | ✗ (pre-loaded) |
| Offline / free | ✗ | ✗ | ✓ |
| Best for | Full scans | Full scans | Quick scans, small repos |

Agentic runners (Claude, OpenAI) can iteratively explore the codebase — read a file, decide what to read next, run commands. Ollama runs in single-shot mode where Nomad pre-reads source files and injects them into the prompt. This works well for small/medium repos but hits context limits on large ones.

## CLI Reference

| Flag | Description | Default |
|---|---|---|
| `--repo` | Path to target repository (required) | — |
| `--provider` | `claude`, `openai`, `ollama` | `claude` |
| `--model` | Model override (provider-specific) | auto |
| `--api-key` | API key override | env var |
| `--ollama-host` | Ollama server URL | `localhost:11434` |
| `--scope` | `full`, `quick`, `secrets_only`, `deps_only` | `full` |
| `--severity-threshold` | `critical`, `high`, `medium`, `low`, `info` | `low` |
| `--validate` | Enable active exploitation testing (A7) | off |
| `--safe-only` | Non-destructive PoCs only | `true` |
| `--base-url` | Running app URL (for `--validate`) | — |
| `--tokens` | Auth tokens for validation | — |
| `--creds` | Credentials (`user:pass`) | — |
| `--output-dir` | Report output directory | `./output` |
| `--format` | `md`, `json`, `pdf` | `md,json` |
| `--tester` | Tester name | — |
| `--engagement-id` | Engagement ID | — |
| `-v, --verbose` | Show agent reasoning | off |

## Agent Pipeline

```
A0 Orchestrator (deterministic Python, not LLM)
 │
 ├─ A1 Recon .............. ✅ Implemented
 ├─ A2 Static Analysis ..... ⬜ Planned
 ├─ A3 Secrets Scanner ..... ⬜ Planned
 ├─ A4 Dependency Auditor .. ⬜ Planned
 ├─ A5 Config Reviewer ..... ⬜ Planned
 ├─ A6 Triage & Dedup ...... ⬜ Planned
 ├─ A7 Validation .......... ⬜ Planned
 └─ A8 Reporting ........... ⬜ Planned
```

## Architecture

```
nomad.py              ← A0 Orchestrator + CLI
├── agents/
│   ├── base.py               ← BaseAgent (provider-agnostic contract)
│   ├── recon.py              ← A1 Recon agent
│   └── prompts/recon.md      ← A1 system prompt (8-step methodology)
├── models/schemas.py         ← Shared dataclasses
└── utils/runners/
    ├── base.py               ← BaseRunner interface + RunResult + JSON extraction
    ├── claude.py             ← Claude Code CLI runner
    ├── openai.py             ← OpenAI Codex CLI / API runner
    └── ollama.py             ← Ollama HTTP API runner (with prompt enrichment)
```

The key abstraction: agents never know which AI provider is running them. They define a system prompt and task prompt, call `self.runner.run(...)`, and get back a `RunResult`. The orchestrator creates the runner based on `--provider` and injects it into every agent.

## Adding a New Provider

1. Create `utils/runners/your_provider.py` implementing `BaseRunner`
2. Register it in `utils/runners/__init__.py` → `PROVIDERS` dict
3. Done — all existing agents work with it automatically

```python
class YourRunner(BaseRunner):
    provider_name = "your_provider"

    def run(self, system_prompt, task_prompt, working_dir, **kwargs) -> RunResult:
        # Your implementation here
        ...

    def preflight(self) -> tuple[bool, str]:
        # Check if provider is available
        ...
```
# nomad
