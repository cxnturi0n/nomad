"""
Claude Code CLI runner.

Invokes the `claude` CLI as a subprocess. This is the most capable runner
because Claude Code has native agentic tool use (bash, file read/write,
web fetch) built in.

Prerequisites:
    npm install -g @anthropic-ai/claude-code
    claude auth login
"""

import json
import logging
import shutil
import subprocess
import time

from utils.runners.base import BaseRunner, RunResult, TOOL_PRESETS, extract_json_from_text

logger = logging.getLogger("nomad.runner.claude")

# Claude Code CLI tool names mapped from our semantic presets
_CLAUDE_TOOLS = {
    "file_read": "Read",
    "file_write": "Write",
    "shell_readonly": "Bash(read_only=true)",
    "shell": "Bash",
    "network": "WebFetch",
}


class ClaudeRunner(BaseRunner):
    provider_name = "claude"

    def _resolve_tools(self, preset: str) -> list[str]:
        """Convert semantic tool preset to Claude Code --allowedTools list."""
        capabilities = TOOL_PRESETS.get(preset, TOOL_PRESETS["read_only"])["capabilities"]
        return [_CLAUDE_TOOLS[cap] for cap in capabilities if cap in _CLAUDE_TOOLS]

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
        tool_list = self._resolve_tools(tools)

        cmd = [
            "claude",
            "-p", task_prompt,
            "--system-prompt", system_prompt,
            "--output-format", "json",
            "--max-turns", str(max_turns),
            "--allowedTools", ",".join(tool_list),
        ]

        if self.model:
            cmd.extend(["--model", self.model])
        if verbose:
            cmd.append("--verbose")

        logger.info(f"[claude] Running in {working_dir}")
        logger.debug(f"[claude] Tools: {tool_list}")
        start = time.time()

        try:
            result = subprocess.run(
                cmd,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration = time.time() - start
            raw = result.stdout.strip()

            if result.returncode != 0:
                error_msg = result.stderr.strip() or f"Exit code {result.returncode}"
                logger.error(f"[claude] Failed: {error_msg}")
                return RunResult(
                    success=False,
                    raw_output=raw,
                    duration_seconds=duration,
                    error=error_msg,
                    provider="claude",
                    model=self.model,
                )

            parsed, cost = self._parse_output(raw)

            return RunResult(
                success=True,
                raw_output=raw,
                parsed_json=parsed,
                duration_seconds=duration,
                cost_usd=cost,
                provider="claude",
                model=self.model,
            )

        except subprocess.TimeoutExpired:
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=f"Timed out after {timeout}s",
                provider="claude",
            )
        except FileNotFoundError:
            return RunResult(
                success=False,
                error=(
                    "'claude' CLI not found. Install Claude Code:\n"
                    "  npm install -g @anthropic-ai/claude-code\n"
                    "  claude auth login"
                ),
                provider="claude",
            )
        except Exception as e:
            logger.error(f"[claude] Error: {e}")
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=str(e),
                provider="claude",
            )

    def preflight(self) -> tuple[bool, str]:
        if not shutil.which("claude"):
            return False, (
                "'claude' CLI not found in PATH.\n"
                "Install: npm install -g @anthropic-ai/claude-code\n"
                "Auth:    claude auth login"
            )
        return True, "Claude Code CLI found"

    def _parse_output(self, raw: str) -> tuple[dict | list | None, float]:
        """
        Parse Claude Code's JSON output.

        Claude CLI --output-format json returns either:
        A) A single JSON object: {"type":"result", "result":"...", "cost_usd":...}
        B) A JSON array of event objects, where the last element is the result:
           [{"type":"system",...}, {"type":"assistant",...}, ..., {"type":"result","result":"..."}]

        Returns (parsed_content, cost_usd).
        """
        cost = 0.0
        if not raw:
            return None, cost

        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError:
            return extract_json_from_text(raw), cost

        # Case B: JSON array of events — find the result event
        if isinstance(envelope, list):
            for item in reversed(envelope):
                if isinstance(item, dict) and item.get("type") == "result":
                    cost = item.get("total_cost_usd", item.get("cost_usd", 0.0))
                    content = item.get("result", "")
                    if content:
                        return extract_json_from_text(content), cost
                    return item, cost
            # No result event found — try to extract from the whole thing
            logger.warning("No 'result' event found in Claude CLI output array")
            return extract_json_from_text(raw), cost

        # Case A: Single JSON object envelope
        cost = envelope.get("total_cost_usd", envelope.get("cost_usd", 0.0))
        content = envelope.get("result", "")

        if not content:
            return envelope, cost

        return extract_json_from_text(content), cost
