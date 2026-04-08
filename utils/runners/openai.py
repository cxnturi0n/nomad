"""
OpenAI Codex CLI runner.

Invokes the `codex` CLI as a subprocess. Codex CLI has native agentic
tool use (shell, file I/O) similar to Claude Code.

Prerequisites:
    npm install -g @openai/codex
    export OPENAI_API_KEY=sk-...

Alternatively, this runner can use the OpenAI Responses API with tool use
for non-CLI setups. Set api_mode=True or use model names like "gpt-4.1"
without having the codex CLI installed.
"""

import json
import logging
import os
import shutil
import subprocess
import time
from typing import Optional

from utils.runners.base import BaseRunner, RunResult, TOOL_PRESETS, extract_json_from_text

logger = logging.getLogger("nomad.runner.openai")

# Codex CLI approval policies mapped from our presets
_CODEX_POLICIES = {
    "read_only": "suggest",        # suggest commands, don't auto-execute writes
    "read_write": "auto-edit",     # auto-approve file edits, suggest shell
    "full": "full-auto",           # auto-approve everything
}


class OpenAIRunner(BaseRunner):
    provider_name = "openai"

    def __init__(self, model: str = "", api_base: str = "", api_key: str = "", **kwargs):
        super().__init__(model=model, api_base=api_base, api_key=api_key, **kwargs)
        self.api_mode: bool = kwargs.get("api_mode", False)
        if not self.model:
            self.model = "o4-mini"  # sensible default for code analysis

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
        if self.api_mode:
            return self._run_api(
                system_prompt, task_prompt, working_dir, tools, max_turns, timeout, verbose
            )
        return self._run_cli(
            system_prompt, task_prompt, working_dir, tools, max_turns, timeout, verbose
        )

    # ── Codex CLI Mode ───────────────────────────────────────────────────

    def _run_cli(
        self,
        system_prompt: str,
        task_prompt: str,
        working_dir: str,
        tools: str,
        max_turns: int,
        timeout: int,
        verbose: bool,
    ) -> RunResult:
        policy = _CODEX_POLICIES.get(tools, "suggest")

        # Codex CLI uses a combined prompt (no separate --system-prompt flag).
        # We prepend the system prompt to the task prompt.
        full_prompt = f"{system_prompt}\n\n---\n\nTASK:\n{task_prompt}"

        cmd = [
            "codex",
            "--approval-policy", policy,
            "--quiet",  # reduce noise for structured output
        ]

        if self.model:
            cmd.extend(["--model", self.model])

        cmd.extend([full_prompt])

        env = os.environ.copy()
        if self.api_key:
            env["OPENAI_API_KEY"] = self.api_key
        if self.api_base:
            env["OPENAI_BASE_URL"] = self.api_base

        logger.info(f"[openai/codex] Running in {working_dir} (policy={policy})")
        start = time.time()

        try:
            result = subprocess.run(
                cmd,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )

            duration = time.time() - start
            raw = result.stdout.strip()

            if result.returncode != 0:
                error_msg = result.stderr.strip() or f"Exit code {result.returncode}"
                logger.error(f"[openai/codex] Failed: {error_msg}")
                return RunResult(
                    success=False,
                    raw_output=raw,
                    duration_seconds=duration,
                    error=error_msg,
                    provider="openai",
                    model=self.model,
                )

            parsed = extract_json_from_text(raw)

            return RunResult(
                success=True,
                raw_output=raw,
                parsed_json=parsed,
                duration_seconds=duration,
                provider="openai",
                model=self.model,
            )

        except subprocess.TimeoutExpired:
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=f"Timed out after {timeout}s",
                provider="openai",
            )
        except FileNotFoundError:
            return RunResult(
                success=False,
                error=(
                    "'codex' CLI not found. Install OpenAI Codex:\n"
                    "  npm install -g @openai/codex\n"
                    "  export OPENAI_API_KEY=sk-..."
                ),
                provider="openai",
            )
        except Exception as e:
            logger.error(f"[openai/codex] Error: {e}")
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=str(e),
                provider="openai",
            )

    # ── API Mode (Responses API with tool use) ───────────────────────────

    def _run_api(
        self,
        system_prompt: str,
        task_prompt: str,
        working_dir: str,
        tools: str,
        max_turns: int,
        timeout: int,
        verbose: bool,
    ) -> RunResult:
        """
        Use OpenAI Responses API directly. Requires the `openai` Python package.
        This is a non-agentic fallback — no shell/file tools, pure prompt-in/text-out.
        Best for analysis tasks that don't need filesystem access.
        """
        try:
            from openai import OpenAI
        except ImportError:
            return RunResult(
                success=False,
                error=(
                    "openai package required for API mode.\n"
                    "  pip install openai\n"
                    "Or use CLI mode (install codex CLI instead)."
                ),
                provider="openai",
            )

        client_kwargs = {}
        if self.api_key:
            client_kwargs["api_key"] = self.api_key
        if self.api_base:
            client_kwargs["base_url"] = self.api_base

        client = OpenAI(**client_kwargs)

        logger.info(f"[openai/api] Running (model={self.model})")
        start = time.time()

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": task_prompt},
                ],
                temperature=0,
                max_tokens=16384,
            )

            duration = time.time() - start
            raw = response.choices[0].message.content or ""
            parsed = extract_json_from_text(raw)

            usage = response.usage
            tokens_in = usage.prompt_tokens if usage else 0
            tokens_out = usage.completion_tokens if usage else 0

            return RunResult(
                success=True,
                raw_output=raw,
                parsed_json=parsed,
                duration_seconds=duration,
                provider="openai",
                model=self.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )

        except Exception as e:
            logger.error(f"[openai/api] Error: {e}")
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=str(e),
                provider="openai",
            )

    # ── Preflight ────────────────────────────────────────────────────────

    def preflight(self) -> tuple[bool, str]:
        if self.api_mode:
            api_key = self.api_key or os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                return False, (
                    "OPENAI_API_KEY not set.\n"
                    "  export OPENAI_API_KEY=sk-..."
                )
            return True, f"OpenAI API mode (model={self.model})"

        if not shutil.which("codex"):
            # Fall back to API mode check
            api_key = self.api_key or os.environ.get("OPENAI_API_KEY", "")
            if api_key:
                self.api_mode = True
                logger.info("[openai] codex CLI not found, falling back to API mode")
                return True, f"OpenAI API fallback mode (model={self.model})"
            return False, (
                "'codex' CLI not found and no OPENAI_API_KEY set.\n"
                "Option 1: npm install -g @openai/codex\n"
                "Option 2: export OPENAI_API_KEY=sk-... (API mode)"
            )

        return True, "OpenAI Codex CLI found"
