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

# Bound the rate/usage-limit back-off so a long reset window can't hang the
# whole pipeline for hours (previously: unbounded recursion + uncapped sleep).
MAX_RATE_LIMIT_RETRIES = 5
MAX_WAIT_SECONDS = 3600  # cap a single back-off at 1 hour

# Claude Code CLI tool names mapped from our semantic presets.
# NOTE: Claude Code's --allowedTools has no "read-only Bash" specifier. The old
# "Bash(read_only=true)" was an invalid pattern that matched no command, so in
# headless `-p` mode every bash call (find/grep/wc/cat that recon & static rely
# on) was denied. We grant plain `Bash` instead, and enforce the read-only
# intent via a --disallowedTools deny-list (see _resolve_disallowed).
_CLAUDE_TOOLS = {
    "file_read": "Read",
    "file_write": "Write",
    "shell_readonly": "Bash",
    "shell": "Bash",
    "network": "WebFetch",
}

# Denied for presets WITHOUT the 'network' capability (everything except the
# 'full' preset used by the fingerprint/validation agents). Defense-in-depth so
# an agent analysing untrusted source code can't trivially exfiltrate. This is
# NOT a sandbox — a determined payload can still egress via python/perl/etc., so
# run nomad in a network-isolated container when scanning untrusted targets.
_NETWORK_DENY = [
    "WebFetch",
    "Bash(curl:*)", "Bash(wget:*)", "Bash(nc:*)", "Bash(ncat:*)",
    "Bash(telnet:*)", "Bash(ssh:*)", "Bash(scp:*)",
]


class ClaudeRunner(BaseRunner):
    provider_name = "claude"

    def _resolve_tools(self, preset: str) -> list[str]:
        """Convert semantic tool preset to Claude Code --allowedTools list."""
        capabilities = TOOL_PRESETS.get(preset, TOOL_PRESETS["read_only"])["capabilities"]
        # dict.fromkeys to dedupe while preserving order (shell_readonly/shell both → Bash)
        return list(dict.fromkeys(
            _CLAUDE_TOOLS[cap] for cap in capabilities if cap in _CLAUDE_TOOLS
        ))

    def _resolve_disallowed(self, preset: str) -> list[str]:
        """
        Build the --disallowedTools deny-list for a preset. Presets without the
        'network' capability (read_only, read_write) get network egress denied;
        presets without 'file_write' also get Write denied. The 'full' preset
        (fingerprint/validation — they legitimately curl the target) gets nothing.
        """
        capabilities = TOOL_PRESETS.get(preset, TOOL_PRESETS["read_only"])["capabilities"]
        if "network" in capabilities:
            return []
        deny = list(_NETWORK_DENY)
        if "file_write" not in capabilities:
            deny.append("Write")
        return deny

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
        disallowed_list = self._resolve_disallowed(tools)
        disallowed_str = ",".join(disallowed_list)

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
            f'--allowedTools "{tool_str}"'
        )

        if disallowed_str:
            shell_cmd += f' --disallowedTools "{disallowed_str}"'
        if self.model:
            shell_cmd += f' --model {self.model}'
        if verbose:
            shell_cmd += ' --verbose'

        logger.info(f"[claude] Running in {working_dir}")
        logger.debug(f"[claude] Tools: {tool_list}")
        start = time.time()

        try:
            for attempt in range(MAX_RATE_LIMIT_RETRIES + 1):
                try:
                    result = subprocess.run(
                        shell_cmd,
                        shell=True,
                        cwd=working_dir,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
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

                duration = time.time() - start
                raw = result.stdout.strip()

                if result.returncode != 0:
                    error_msg = result.stderr.strip() or result.stdout.strip() or f"Exit code {result.returncode}"
                    combined = error_msg + " " + raw

                    # Bounded retry on rate/usage limiting
                    if self._is_rate_limited(combined) or self._is_usage_limit(combined):
                        if attempt >= MAX_RATE_LIMIT_RETRIES:
                            logger.error(f"[claude] Still rate/usage limited after {MAX_RATE_LIMIT_RETRIES} retries; giving up.")
                            return RunResult(
                                success=False,
                                raw_output=raw,
                                duration_seconds=duration,
                                error=f"Rate/usage limited after {MAX_RATE_LIMIT_RETRIES} retries: {error_msg[:300]}",
                                provider="claude",
                                model=self.model,
                            )
                        wait = self._get_usage_limit_wait(combined) if self._is_usage_limit(combined) else self._get_rate_limit_wait(combined)
                        wait = min(wait, MAX_WAIT_SECONDS)
                        logger.warning(
                            f"[claude] Rate/usage limited (attempt {attempt + 1}/{MAX_RATE_LIMIT_RETRIES}). "
                            f"Waiting {wait // 60}m {wait % 60}s..."
                        )
                        time.sleep(wait)
                        logger.info("[claude] Retrying after rate limit wait...")
                        continue

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

                # Rate limit can also appear in exit-0 responses (is_error=true)
                if self._is_usage_limit(raw):
                    if attempt >= MAX_RATE_LIMIT_RETRIES:
                        logger.error(f"[claude] Still usage limited after {MAX_RATE_LIMIT_RETRIES} retries; giving up.")
                        return RunResult(
                            success=False,
                            raw_output=raw,
                            duration_seconds=duration,
                            error=f"Usage limited after {MAX_RATE_LIMIT_RETRIES} retries",
                            provider="claude",
                            model=self.model,
                        )
                    wait = min(self._get_usage_limit_wait(raw), MAX_WAIT_SECONDS)
                    logger.warning(
                        f"[claude] Usage limit hit (attempt {attempt + 1}/{MAX_RATE_LIMIT_RETRIES}). "
                        f"Waiting {wait // 60}m {wait % 60}s for reset..."
                    )
                    time.sleep(wait)
                    logger.info("[claude] Retrying after usage limit wait...")
                    continue

                return RunResult(
                    success=True,
                    raw_output=raw,
                    parsed_json=parsed,
                    duration_seconds=duration,
                    cost_usd=cost,
                    provider="claude",
                    model=self.model,
                )

            # Loop exhausted without an explicit return (defensive)
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error="Rate limit retries exhausted",
                provider="claude",
                model=self.model,
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