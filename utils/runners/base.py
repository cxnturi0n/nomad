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
    surrounding prose, truncated output, or other noise. Used by all runners.

    Strategies (in order):
    1. Direct parse
    2. Markdown code fences
    3. First { to last } (handles prose before/after JSON)
    4. Bracket-matching parser (handles complex nesting)
    5. Truncation repair (closes unclosed braces/brackets)
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

    # 3. Simple slice: first { to last } (covers prose-wrapped JSON)
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidate = text[first_brace : last_brace + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Also try first [ to last ]
    first_bracket = text.find("[")
    last_bracket = text.rfind("]")
    if first_bracket != -1 and last_bracket > first_bracket:
        candidate = text[first_bracket : last_bracket + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # 4. Bracket-matching parser (handles cases where last } isn't the right one)
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
            if ch == '"':
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

    # 5. Truncation repair — JSON was cut off mid-output
    if first_brace != -1:
        truncated = text[first_brace:]
        repaired = _repair_truncated_json(truncated)
        if repaired is not None:
            return repaired

    logger.warning("Could not extract JSON from output")
    return None


def _repair_truncated_json(text: str) -> Optional[dict]:
    """
    Attempt to repair truncated JSON by finding the last complete object
    in a findings array and closing the structure.
    """
    # Strategy: find the last complete finding (ending with }) and close the array + object
    # Look for the last complete object boundary: }\n    {  or },\n    {
    # Then close with ]}}

    # Find where the findings array likely starts
    findings_start = text.find('"findings"')
    if findings_start == -1:
        return None

    # Try progressively shorter substrings, cutting at the last complete finding
    # A finding ends with: }  followed by , or ] at same indent level
    # Look for the pattern: closing brace followed by optional comma, then newline
    last_complete = -1
    search_patterns = [
        '}\n    },\n',       # between findings (pretty printed, 4-space indent)
        '}\n      },\n',     # 6-space indent
        '}\r\n    },\r\n',   # Windows line endings
        '},\n    {',          # compact: end of one finding, start of next
        '}\n    }\n  ],',     # last finding before summary
        '}\n    }\n  ]',      # last finding, end of array
        '"references": [',    # find last references field (end of a finding)
    ]

    for pattern in search_patterns:
        pos = text.rfind(pattern)
        if pos > findings_start:
            last_complete = max(last_complete, pos)

    if last_complete == -1:
        # Last resort: find the last } that could close a finding
        # Walk backwards from end looking for }
        pos = len(text) - 1
        while pos > findings_start:
            if text[pos] == '}':
                last_complete = pos
                break
            pos -= 1

    if last_complete == -1:
        return None

    # Cut at last complete position + find a good closure point
    # Try to find the end of the current object
    cut_pos = text.find('}', last_complete)
    if cut_pos == -1:
        cut_pos = last_complete

    candidate = text[:cut_pos + 1]

    # Count unclosed braces and brackets
    open_braces = candidate.count('{') - candidate.count('}')
    open_brackets = candidate.count('[') - candidate.count(']')

    # Close them
    suffix = ''
    # Close any open strings first (rough check)
    # Count unescaped quotes
    in_str = False
    esc = False
    for ch in candidate:
        if esc:
            esc = False
            continue
        if ch == '\\':
            esc = True
            continue
        if ch == '"':
            in_str = not in_str

    if in_str:
        suffix += '"'

    # Close brackets then braces
    suffix += ']' * max(0, open_brackets)
    suffix += '}' * max(0, open_braces)

    if not suffix:
        # Nothing to repair
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None

    repaired = candidate + suffix
    try:
        result = json.loads(repaired)
        logger.info(f"Repaired truncated JSON (added {repr(suffix)})")
        return result
    except json.JSONDecodeError:
        # Try adding a summary stub before closing
        repaired2 = candidate + '],"summary":{}' + '}' * max(0, open_braces - 1)
        try:
            result = json.loads(repaired2)
            logger.info("Repaired truncated JSON with summary stub")
            return result
        except json.JSONDecodeError:
            return None