"""
Base runner interface — the contract every AI provider must implement.

The runner is the only component that knows how to talk to a specific AI.
Everything else (agents, orchestrator, schemas) is provider-agnostic.
"""

import json
import re
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("nomad.runner")


# ── Shared Result Type ───────────────────────────────────────────────────────

@dataclass
class RunResult:
    """
    Universal result from any AI provider invocation.
    Every runner returns this — agents never see provider-specific types.
    """
    success: bool
    raw_output: str = ""
    parsed_json: Optional[dict | list] = None
    duration_seconds: float = 0.0
    error: str = ""
    cost_usd: float = 0.0
    provider: str = ""
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0


# ── Tool Presets ─────────────────────────────────────────────────────────────
# Semantic tool categories. Each runner translates these into provider-specific
# tool configurations.

TOOL_PRESETS = {
    "read_only": {
        "description": "Can read files and run read-only shell commands",
        "capabilities": ["file_read", "shell_readonly"],
    },
    "read_write": {
        "description": "Can read/write files and run shell commands",
        "capabilities": ["file_read", "file_write", "shell"],
    },
    "full": {
        "description": "Full access: files, shell, and network",
        "capabilities": ["file_read", "file_write", "shell", "network"],
    },
}


# ── Base Runner Interface ────────────────────────────────────────────────────

class BaseRunner(ABC):
    """
    Abstract interface for AI provider runners.

    Each provider must implement:
      - run(): Execute a prompt with a system prompt and return RunResult
      - preflight(): Check that the provider is available and configured
      - provider_name: Human-readable name for logging
    """

    provider_name: str = "base"

    def __init__(self, model: str = "", api_base: str = "", api_key: str = "", **kwargs):
        """
        Common constructor. Providers ignore irrelevant kwargs.

        Args:
            model: Model name/ID override (provider-specific default if empty)
            api_base: API endpoint override (for self-hosted / proxied setups)
            api_key: API key override (most providers read from env by default)
        """
        self.model = model
        self.api_base = api_base
        self.api_key = api_key
        self.extra_config = kwargs

    @abstractmethod
    def run(
        self,
        system_prompt: str,
        task_prompt: str,
        working_dir: str,
        tools: str = "read_only",
        max_turns: int = 30,
        timeout: int = 300,
        verbose: bool = False,
    ) -> RunResult:
        """
        Execute an agent task.

        Args:
            system_prompt: The agent's identity and instructions.
            task_prompt: The specific task for this run.
            working_dir: Directory the agent operates in (the repo).
            tools: Tool preset key from TOOL_PRESETS.
            max_turns: Max agentic turns/iterations.
            timeout: Max wall-clock seconds.
            verbose: Stream output in real time.

        Returns:
            RunResult with parsed output.
        """
        ...

    @abstractmethod
    def preflight(self) -> tuple[bool, str]:
        """
        Check if this provider is ready to use.

        Returns:
            (ok, message) — ok=True if ready, message explains what's wrong if not.
        """
        ...

    def get_model_display(self) -> str:
        """Human-readable model identifier for logging."""
        return self.model or f"{self.provider_name} (default)"


# ── Shared JSON Extraction Utilities ─────────────────────────────────────────
# Every provider's output may need JSON extraction. These are shared.

def extract_json_from_text(text: str) -> Optional[dict | list]:
    """
    Extract a JSON object or array from text that may contain markdown fences,
    surrounding prose, or other noise. Used by all runners.
    """
    if not text:
        return None

    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Markdown code fences
    for pattern in [
        r"```json\s*\n(.*?)\n\s*```",
        r"```\s*\n(.*?)\n\s*```",
    ]:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                continue

    # 3. Find first valid JSON object or array by bracket matching
    for open_ch, close_ch in [("{", "}"), ("[", "]")]:
        start = text.find(open_ch)
        if start == -1:
            continue
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    break

    logger.warning("Could not extract JSON from output")
    return None
