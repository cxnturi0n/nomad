"""
Ollama runner — local models via the Ollama HTTP API.

Unlike Claude/Codex CLIs, Ollama models don't have native filesystem tools.
This runner works in "prompt-stuffing" mode:
  1. Reads the files the agent would need (based on tool preset)
  2. Injects file contents into the prompt
  3. Sends a single completion request
  4. Parses the response

This is less capable than agentic runners (no iterative exploration), but
works offline, costs nothing, and is fast for small/medium repos.

Prerequisites:
    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull qwen2.5-coder:32b   # or any model

Supports any Ollama-compatible API (LocalAI, LM Studio, vLLM with
OpenAI-compat endpoint) via the api_base parameter.
"""

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from utils.runners.base import BaseRunner, RunResult, TOOL_PRESETS, extract_json_from_text

logger = logging.getLogger("nomad.runner.ollama")

# Default context window estimates for common models
_DEFAULT_CTX = 32768


class OllamaRunner(BaseRunner):
    provider_name = "ollama"

    def __init__(self, model: str = "", api_base: str = "", api_key: str = "", **kwargs):
        super().__init__(model=model, api_base=api_base, api_key=api_key, **kwargs)
        if not self.model:
            self.model = "qwen2.5-coder:32b"
        if not self.api_base:
            self.api_base = "http://localhost:11434"
        self.context_length: int = kwargs.get("context_length", _DEFAULT_CTX)

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
        Ollama runs in single-shot mode — no agentic tool loop.
        For tasks that need file access, we pre-read files and inject
        them into the prompt.
        """
        # Build an enriched prompt with file context if the task
        # references the working directory
        enriched_prompt = self._enrich_prompt(task_prompt, working_dir, tools)

        logger.info(f"[ollama] Running (model={self.model}, base={self.api_base})")
        start = time.time()

        try:
            import urllib.request
            import urllib.error

            payload = {
                "model": self.model,
                "stream": False,
                "options": {
                    "temperature": 0,
                    "num_ctx": self.context_length,
                },
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": enriched_prompt},
                ],
            }

            data = json.dumps(payload).encode("utf-8")
            url = f"{self.api_base.rstrip('/')}/api/chat"

            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            # Add auth header if provided (for OpenAI-compat endpoints)
            if self.api_key:
                req.add_header("Authorization", f"Bearer {self.api_key}")

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))

            duration = time.time() - start

            raw = body.get("message", {}).get("content", "")
            parsed = extract_json_from_text(raw)

            # Token counts from Ollama response
            tokens_in = body.get("prompt_eval_count", 0)
            tokens_out = body.get("eval_count", 0)

            return RunResult(
                success=True,
                raw_output=raw,
                parsed_json=parsed,
                duration_seconds=duration,
                provider="ollama",
                model=self.model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )

        except urllib.error.URLError as e:
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=f"Cannot connect to Ollama at {self.api_base}: {e}",
                provider="ollama",
            )
        except TimeoutError:
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=f"Timed out after {timeout}s",
                provider="ollama",
            )
        except Exception as e:
            logger.error(f"[ollama] Error: {e}")
            return RunResult(
                success=False,
                duration_seconds=time.time() - start,
                error=str(e),
                provider="ollama",
            )

    def preflight(self) -> tuple[bool, str]:
        """Check if Ollama is running and the model is available."""
        try:
            import urllib.request
            url = f"{self.api_base.rstrip('/')}/api/tags"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            models = [m.get("name", "") for m in data.get("models", [])]
            # Ollama model names may or may not include the tag
            model_base = self.model.split(":")[0]
            found = any(model_base in m for m in models)

            if not found:
                return False, (
                    f"Model '{self.model}' not found in Ollama.\n"
                    f"Available: {', '.join(models[:10])}\n"
                    f"Pull it:   ollama pull {self.model}"
                )

            return True, f"Ollama ready (model={self.model})"

        except Exception as e:
            return False, (
                f"Cannot connect to Ollama at {self.api_base}: {e}\n"
                "Start it:  ollama serve\n"
                "Install:   curl -fsSL https://ollama.com/install.sh | sh"
            )

    # ── Prompt Enrichment ────────────────────────────────────────────────

    def _enrich_prompt(self, task_prompt: str, working_dir: str, tools: str) -> str:
        """
        Since Ollama can't browse files itself, we pre-read key files
        and inject them into the prompt. This gives the model the context
        it needs for analysis.
        """
        repo = Path(working_dir)
        if not repo.is_dir():
            return task_prompt

        sections = []

        # 1. Directory structure
        tree = self._get_tree(repo)
        if tree:
            sections.append(f"## Repository Structure\n```\n{tree}\n```")

        # 2. Key config files (always include if they exist)
        config_files = [
            "package.json", "requirements.txt", "pyproject.toml", "go.mod",
            "Cargo.toml", "pom.xml", "Gemfile", "composer.json",
            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
            ".env.example", "Makefile",
        ]
        for fname in config_files:
            fpath = repo / fname
            if fpath.is_file():
                content = self._safe_read(fpath, max_lines=100)
                if content:
                    sections.append(f"## File: {fname}\n```\n{content}\n```")

        # 3. Source files (read up to context budget)
        # Budget ~60% of context for source, rest for system prompt + response
        budget_chars = int(self.context_length * 2.5)  # rough chars-per-token estimate
        used = sum(len(s) for s in sections)
        remaining = budget_chars - used

        source_files = self._find_source_files(repo)
        for fpath in source_files:
            if remaining <= 0:
                sections.append(f"\n[... {len(source_files)} total source files, truncated for context ...]")
                break
            content = self._safe_read(fpath, max_lines=300)
            if content:
                rel = fpath.relative_to(repo)
                block = f"## File: {rel}\n```\n{content}\n```"
                if len(block) > remaining:
                    break
                sections.append(block)
                remaining -= len(block)

        if sections:
            context_block = "\n\n".join(sections)
            return (
                f"{task_prompt}\n\n"
                f"--- FILE CONTEXT (pre-loaded since you cannot browse files) ---\n\n"
                f"{context_block}"
            )

        return task_prompt

    def _get_tree(self, repo: Path, max_depth: int = 3) -> str:
        """Get directory tree, excluding common noise."""
        try:
            result = subprocess.run(
                ["find", ".", "-maxdepth", str(max_depth), "-type", "f",
                 "-not", "-path", "*/node_modules/*",
                 "-not", "-path", "*/.git/*",
                 "-not", "-path", "*/vendor/*",
                 "-not", "-path", "*/__pycache__/*",
                 "-not", "-path", "*/.venv/*"],
                cwd=repo, capture_output=True, text=True, timeout=10,
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) > 200:
                return "\n".join(lines[:200]) + f"\n... ({len(lines)} files total)"
            return result.stdout.strip()
        except Exception:
            return ""

    def _find_source_files(self, repo: Path) -> list[Path]:
        """Find source files, prioritized by security relevance."""
        extensions = {
            ".py", ".js", ".ts", ".go", ".java", ".rb", ".php",
            ".rs", ".c", ".cpp", ".cs", ".jsx", ".tsx", ".vue", ".svelte",
        }
        skip_dirs = {"node_modules", ".git", "vendor", "__pycache__", ".venv", "dist", "build"}

        files = []
        for fpath in sorted(repo.rglob("*")):
            if not fpath.is_file():
                continue
            if any(skip in fpath.parts for skip in skip_dirs):
                continue
            if fpath.suffix in extensions:
                files.append(fpath)

        # Prioritize: auth/security files first, then routes, then everything else
        priority_keywords = ["auth", "login", "session", "jwt", "token", "middleware",
                             "route", "controller", "view", "api", "admin", "payment",
                             "billing", "upload", "config", "setting"]

        def priority(f: Path) -> int:
            name = f.stem.lower()
            for i, kw in enumerate(priority_keywords):
                if kw in name:
                    return i
            return 100

        files.sort(key=priority)
        return files

    def _safe_read(self, fpath: Path, max_lines: int = 200) -> str:
        """Read a file safely, truncating if too long."""
        try:
            text = fpath.read_text(errors="replace")
            lines = text.split("\n")
            if len(lines) > max_lines:
                return "\n".join(lines[:max_lines]) + f"\n\n[... truncated, {len(lines)} total lines ...]"
            return text
        except Exception:
            return ""
