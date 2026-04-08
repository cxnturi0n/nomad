"""
Base agent class — defines the contract every agent must follow.
Provider-agnostic: receives a Runner instance, never imports one directly.
"""

import logging
import time
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from models.schemas import EngagementConfig, AgentRun, AgentStatus
from utils.runners.base import BaseRunner, RunResult

logger = logging.getLogger("nomad.agents")


class BaseAgent(ABC):
    """
    Every agent must:
      1. Define a system prompt (who it is, what it does, output format)
      2. Build a task prompt (the specific job for this run, with context)
      3. Run via the provided Runner (any AI provider)
      4. Parse and validate the output
      5. Save results to disk
    """

    name: str = "base"
    description: str = ""
    tools: str = "read_only"  # semantic preset from TOOL_PRESETS
    max_turns: int = 30
    timeout: int = 1200

    def __init__(self, config: EngagementConfig, output_dir: Path, runner: BaseRunner):
        self.config = config
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.runner = runner

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the agent's system prompt."""
        ...

    @abstractmethod
    def get_task_prompt(self, context: Optional[dict] = None) -> str:
        """Build the task prompt for this run."""
        ...

    @abstractmethod
    def parse_output(self, result: RunResult) -> Optional[dict]:
        """Validate and structure the raw output."""
        ...

    @property
    def output_file(self) -> Path:
        return self.output_dir / f"{self.name}_output.json"

    def run(self, context: Optional[dict] = None) -> AgentRun:
        """Execute the agent via the runner. Returns an AgentRun tracking object."""
        run = AgentRun(
            agent_name=self.name,
            status=AgentStatus.RUNNING,
            output_file=str(self.output_file),
        )

        provider = self.runner.get_model_display()
        logger.info(f"[{self.name}] Starting (provider: {provider})...")
        start = time.time()

        try:
            system_prompt = self.get_system_prompt()
            task_prompt = self.get_task_prompt(context)

            result = self.runner.run(
                system_prompt=system_prompt,
                task_prompt=task_prompt,
                working_dir=self.config.repo_path,
                tools=self.tools,
                max_turns=self.max_turns,
                timeout=self.timeout,
                verbose=self.config.verbose,
            )

            run.duration_seconds = time.time() - start

            if not result.success:
                run.status = AgentStatus.FAILED
                run.error = result.error
                logger.error(f"[{self.name}] Failed: {result.error}")
                return run

            parsed = self.parse_output(result)
            if parsed is None:
                run.status = AgentStatus.FAILED
                run.error = "Failed to parse agent output"
                raw_path = self.output_dir / f"{self.name}_raw.txt"
                raw_path.write_text(result.raw_output)
                logger.error(f"[{self.name}] Output parse failed. Raw saved to {raw_path}")
                return run

            self.output_file.write_text(json.dumps(parsed, indent=2, default=str))

            run.status = AgentStatus.COMPLETED
            run.finding_count = self._count_findings(parsed)
            logger.info(
                f"[{self.name}] Completed in {run.duration_seconds:.1f}s "
                f"({run.finding_count} items, provider={result.provider})"
            )
            if result.cost_usd > 0:
                logger.info(f"[{self.name}] Cost: ${result.cost_usd:.4f}")
            return run

        except Exception as e:
            run.duration_seconds = time.time() - start
            run.status = AgentStatus.FAILED
            run.error = str(e)
            logger.exception(f"[{self.name}] Unexpected error")
            return run

    def _count_findings(self, parsed: dict) -> int:
        """Count items in the output — override per agent if needed."""
        if isinstance(parsed, list):
            return len(parsed)
        if isinstance(parsed, dict):
            for key in ("findings", "entry_points", "modules", "data_flows", "items"):
                if key in parsed and isinstance(parsed[key], list):
                    return len(parsed[key])
        return 0
