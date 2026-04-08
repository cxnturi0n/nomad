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
import os
import re
import shutil
import subprocess
import tempfile
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
        tool_str = ",".join(tool_list)

        # Write prompts to temp files to avoid CLI argument length limits
        # (Linux execve has ~2MB arg limit; large codebases produce huge prompts)
        sys_file = os.path.join(tempfile.gettempdir(), f"nomad_sys_{os.getpid()}.txt")
        task_file = os.path.join(tempfile.gettempdir(), f"nomad_task_{os.getpid()}.txt")

        with open(sys_file, "w") as f:
            f.write(system_prompt)
        with open(task_file, "w") as f:
            f.write(task_prompt)

        # Build shell command using $(cat file) to load prompts from files
        shell_cmd = (
            f'claude -p "$(cat \'{task_file}\')" '
            f'--system-prompt "$(cat \'{sys_file}\')" '
            f'--output-format json '
            f'--max-turns {max_turns} '
            f'--max-tokens 16000 '
            f'--allowedTools "{tool_str}"'
        )

        if self.model:
            shell_cmd += f' --model {self.model}'
        if verbose:
            shell_cmd += ' --verbose'

        logger.info(f"[claude] Running in {working_dir}")
        logger.debug(f"[claude] Tools: {tool_list}")
        start = time.time()

        try:
            result = subprocess.run(
                shell_cmd,
                shell=True,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            duration = time.time() - start
            raw = result.stdout.strip()

            if result.returncode != 0:
                error_msg = result.stderr.strip() or result.stdout.strip() or f"Exit code {result.returncode}"
                combined = error_msg + " " + raw

                # Check for rate/usage limiting
                if self._is_rate_limited(combined) or self._is_usage_limit(combined):
                    wait = self._get_usage_limit_wait(combined) if self._is_usage_limit(combined) else self._get_rate_limit_wait(combined)
                    logger.warning(
                        f"[claude] Rate/usage limited. Waiting {wait // 60}m {wait % 60}s..."
                    )
                    time.sleep(wait)
                    logger.info("[claude] Retrying after rate limit wait...")
                    return self.run(
                        system_prompt, task_prompt, working_dir,
                        tools, max_turns, timeout, verbose,
                    )

                logger.error(f"[claude] Failed: {error_msg[:500]}")
                return RunResult(
                    success=False,
                    raw_output=raw,
                    duration_seconds=duration,
                    error=error_msg,
                    provider="claude",
                    model=self.model,
                )

            parsed, cost = self._parse_output(raw)

            # Check for rate limit in "successful" responses where
            # Claude CLI returns exit code 0 but is_error=true
            if self._is_usage_limit(raw):
                wait = self._get_usage_limit_wait(raw)
                logger.warning(
                    f"[claude] Usage limit hit. Waiting {wait // 60}m {wait % 60}s for reset..."
                )
                time.sleep(wait)
                logger.info("[claude] Retrying after usage limit wait...")
                return self.run(
                    system_prompt, task_prompt, working_dir,
                    tools, max_turns, timeout, verbose,
                )

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
        finally:
            # Clean up temp files
            for f in (sys_file, task_file):
                try:
                    os.unlink(f)
                except OSError:
                    pass

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

    def _is_rate_limited(self, text: str) -> bool:
        """Detect rate limiting in Claude CLI error output."""
        indicators = [
            "rate limit", "rate_limit", "too many", "capacity",
            "overloaded", "429", "rateLimitType",
        ]
        lower = text.lower()
        return any(ind in lower for ind in indicators)

    def _get_rate_limit_wait(self, text: str, default: int = 300) -> int:
        """Extract wait time from rate limit error responses."""
        match = re.search(r'"resetsAt"\s*:\s*(\d{10,})', text)
        if match:
            reset_ts = int(match.group(1))
            wait = max(0, reset_ts - int(time.time())) + 30
            if 0 < wait < 86400:
                return wait
        match = re.search(r'retry.?after\s*:\s*(\d+)', text, re.IGNORECASE)
        if match:
            return int(match.group(1)) + 10
        return default

    def _is_usage_limit(self, text: str) -> bool:
        """
        Detect the usage limit response where Claude CLI returns exit 0
        but is_error=true with 'You've hit your limit'.
        """
        indicators = [
            "hit your limit",
            "you've hit your limit",
            "resets ",
        ]
        lower = text.lower()
        # Must also have is_error indicator
        has_error = '"is_error":true' in text.lower() or '"is_error": true' in text.lower()
        has_limit = any(ind in lower for ind in indicators)
        return has_error and has_limit

    def _get_usage_limit_wait(self, text: str, default: int = 3600) -> int:
        """
        Parse the reset time from 'resets 5pm (UTC)' style messages.
        Returns seconds to wait.
        """
        import re
        from datetime import datetime, timezone

        # Pattern: "resets 5pm (UTC)" or "resets 5:00pm (UTC)"
        match = re.search(r'resets?\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)\s*\(?UTC\)?', text, re.IGNORECASE)
        if match:
            hour = int(match.group(1))
            minute = int(match.group(2)) if match.group(2) else 0
            ampm = match.group(3).lower()

            if ampm == "pm" and hour != 12:
                hour += 12
            elif ampm == "am" and hour == 12:
                hour = 0

            now = datetime.now(timezone.utc)
            reset_time = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

            # If reset time is in the past, it's tomorrow
            if reset_time <= now:
                from datetime import timedelta
                reset_time += timedelta(days=1)

            wait = int((reset_time - now).total_seconds()) + 30  # +30s buffer
            if 0 < wait < 86400:  # sanity: max 24 hours
                return wait

        # Fallback: look for resetsAt timestamp
        match = re.search(r'"resetsAt"\s*:\s*(\d{10,})', text)
        if match:
            reset_ts = int(match.group(1))
            wait = max(0, reset_ts - int(time.time())) + 30
            if 0 < wait < 86400:
                return wait

        return default