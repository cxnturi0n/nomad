from utils.runners.base import BaseRunner, RunResult, TOOL_PRESETS
from utils.runners.claude import ClaudeRunner
from utils.runners.openai import OpenAIRunner
from utils.runners.ollama import OllamaRunner

PROVIDERS: dict[str, type[BaseRunner]] = {
    "claude": ClaudeRunner,
    "openai": OpenAIRunner,
    "ollama": OllamaRunner,
}


def create_runner(provider: str, **kwargs) -> BaseRunner:
    cls = PROVIDERS.get(provider)
    if cls is None:
        available = ", ".join(sorted(PROVIDERS.keys()))
        raise ValueError(f"Unknown provider '{provider}'. Available: {available}")
    return cls(**kwargs)


def list_providers() -> list[str]:
    return sorted(PROVIDERS.keys())


__all__ = [
    "BaseRunner",
    "RunResult",
    "TOOL_PRESETS",
    "create_runner",
    "list_providers",
    "ClaudeRunner",
    "OpenAIRunner",
    "OllamaRunner",
]