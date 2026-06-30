"""
Stdlib smoke tests for nomad. No third-party deps, no network, no provider calls.

Run:
    python3 -m unittest discover -s tests -v
"""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from models.schemas import EngagementConfig, ScanMode  # noqa: E402
from utils.runners import create_runner, list_providers  # noqa: E402
from utils.runners.base import BaseRunner, RunResult, extract_json_from_text  # noqa: E402
from utils.runners.openai import OpenAIRunner  # noqa: E402


def _load_orchestrator():
    """Load the extension-less `nomad` entry-point file as a module."""
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("nomad_orchestrator", str(ROOT / "nomad"))
    spec = importlib.util.spec_from_loader("nomad_orchestrator", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class StubRunner(BaseRunner):
    """A runner that returns canned output — lets us exercise agent parsing."""
    provider_name = "stub"

    def run(self, *args, **kwargs) -> RunResult:
        return RunResult(success=True, raw_output="{}", parsed_json={})

    def preflight(self):
        return True, "stub ready"


class TestJsonExtraction(unittest.TestCase):
    def test_direct(self):
        self.assertEqual(extract_json_from_text('{"a": 1}'), {"a": 1})

    def test_markdown_fence(self):
        self.assertEqual(extract_json_from_text('```json\n{"a": 1}\n```'), {"a": 1})

    def test_prose_wrapped(self):
        self.assertEqual(extract_json_from_text('Here is the result: {"y": 2} done.'), {"y": 2})

    def test_truncation_repair(self):
        # Cut off mid-array — the repair pass should still recover the findings.
        out = extract_json_from_text('{"findings": [{"a": 1}, {"b": 2}')
        self.assertIsInstance(out, dict)
        self.assertIn("findings", out)

    def test_garbage_returns_none(self):
        self.assertIsNone(extract_json_from_text("no json here at all"))


class TestRunnerFactory(unittest.TestCase):
    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            create_runner("does-not-exist")

    def test_known_providers(self):
        self.assertEqual(list_providers(), ["claude", "ollama", "openai"])

    def test_reasoning_model_detection(self):
        self.assertTrue(OpenAIRunner._is_reasoning_model("o4-mini"))
        self.assertTrue(OpenAIRunner._is_reasoning_model("o3"))
        self.assertTrue(OpenAIRunner._is_reasoning_model("gpt-5-mini"))
        self.assertFalse(OpenAIRunner._is_reasoning_model("gpt-4o"))


class TestStaticAnalysisParsing(unittest.TestCase):
    def _agent(self):
        from agents.static_analysis import StaticAnalysisAgent
        tmp = pathlib.Path(tempfile.mkdtemp())
        cfg = EngagementConfig(repo_path=str(tmp))
        return StaticAnalysisAgent(cfg, tmp / "analysis", StubRunner())

    def test_normalizes_finding(self):
        agent = self._agent()
        rr = RunResult(success=True, parsed_json={
            "findings": [{
                "title": "SQLi",
                "severity": "SUPERBAD",      # invalid -> medium
                "confidence": "weird",        # invalid -> medium
                "cwe_id": "CWE-89",          # string -> 89
            }]
        })
        out = agent.parse_output(rr)
        self.assertEqual(len(out["findings"]), 1)
        f = out["findings"][0]
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["confidence"], "medium")
        self.assertEqual(f["cwe_id"], 89)
        self.assertTrue(f["id"].startswith("VULN-"))
        self.assertEqual(out["summary"]["total_findings"], 1)

    def test_drops_findings_without_title_or_desc(self):
        agent = self._agent()
        rr = RunResult(success=True, parsed_json={"findings": [{"severity": "high"}]})
        out = agent.parse_output(rr)
        self.assertEqual(out["findings"], [])


class TestReconFreestyleMapper(unittest.TestCase):
    def test_maps_app_profile_and_attack_surface(self):
        from agents.recon import _map_freestyle_to_schema
        mapped = _map_freestyle_to_schema({
            "app_profile": {"name": "demo"},
            "attack_surface": {"endpoints_without_auth": ["GET /admin"]},
        })
        self.assertGreaterEqual(len(mapped["entry_points"]), 1)
        self.assertFalse(mapped["entry_points"][0]["auth_required"])
        self.assertEqual(mapped["modules"][0]["name"], "demo")


class TestScalingEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nomad = _load_orchestrator()

    def _engine(self, loc):
        cfg = EngagementConfig(repo_path="/tmp", scope=ScanMode.FULL)
        report = {"repo_stats": {"total_loc": loc}, "modules": [], "critical_files": {}}
        return self.nomad.ScalingEngine(report, cfg)

    def test_thresholds(self):
        self.assertEqual(self._engine(1_000).get_strategy(), "single_pass")
        self.assertEqual(self._engine(20_000).get_strategy(), "horizontal")
        self.assertEqual(self._engine(100_000).get_strategy(), "hybrid")

    def test_single_pass_partition(self):
        parts = self._engine(1_000).get_partitions()
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["scope_name"], "full_repo")


class TestCliHelp(unittest.TestCase):
    def test_help_exposes_no_safe_only(self):
        # Validates argparse wiring incl. the BooleanOptionalAction safe-only fix.
        proc = subprocess.run(
            [sys.executable, str(ROOT / "nomad"), "--help"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--no-safe-only", proc.stdout)
        self.assertIn("--model-light", proc.stdout)
        self.assertIn("--effort", proc.stdout)

    def test_light_agents_requires_model_light(self):
        # --light-agents without --model-light must be a hard error.
        with tempfile.TemporaryDirectory() as d:
            proc = subprocess.run(
                [sys.executable, str(ROOT / "nomad"), "--repo", d, "--light-agents", "secrets"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("--light-agents requires --model-light", proc.stderr)


class TestModelTiering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nomad = _load_orchestrator()

    def _pipeline(self, light_runner=None, light_agents=None):
        from models.schemas import EngagementConfig
        d = tempfile.mkdtemp()
        cfg = EngagementConfig(repo_path="/tmp", output_dir=d)
        return self.nomad.Pipeline(cfg, StubRunner(), light_runner, light_agents)

    def test_routes_light_and_strong(self):
        light = StubRunner()
        p = self._pipeline(light, {"secrets", "deps", "fingerprint"})
        # default-strong agents
        for key in ("recon", "static", "triage", "validation"):
            self.assertIs(p._runner_for(key), p.runner, key)
        # light agents
        for key in ("secrets", "deps", "fingerprint"):
            self.assertIs(p._runner_for(key), light, key)

    def test_no_light_runner_everything_strong(self):
        p = self._pipeline(None, None)
        for key in ("recon", "static", "secrets", "deps", "fingerprint"):
            self.assertIs(p._runner_for(key), p.runner)

    def test_default_light_set(self):
        self.assertEqual(self.nomad.DEFAULT_LIGHT_AGENTS, {"secrets", "deps", "fingerprint"})


class TestClaudeToolResolution(unittest.TestCase):
    def _runner(self):
        from utils.runners.claude import ClaudeRunner
        return ClaudeRunner()

    def test_read_only_has_real_bash_not_bogus_spec(self):
        tools = self._runner()._resolve_tools("read_only")
        self.assertIn("Read", tools)
        self.assertIn("Bash", tools)
        self.assertNotIn("Bash(read_only=true)", tools)  # the old no-op spec

    def test_read_only_denies_network_and_write(self):
        deny = self._runner()._resolve_disallowed("read_only")
        self.assertIn("WebFetch", deny)
        self.assertIn("Bash(curl:*)", deny)
        self.assertIn("Write", deny)

    def test_full_preset_denies_nothing(self):
        self.assertEqual(self._runner()._resolve_disallowed("full"), [])


class TestAgenticFlags(unittest.TestCase):
    def test_flags(self):
        from utils.runners.claude import ClaudeRunner
        from utils.runners.ollama import OllamaRunner
        self.assertTrue(ClaudeRunner().agentic)
        self.assertFalse(OllamaRunner().agentic)
        self.assertTrue(OpenAIRunner().agentic)
        self.assertFalse(OpenAIRunner(api_mode=True).agentic)


class TestTriageDedup(unittest.TestCase):
    def _agent(self):
        from agents.triage import TriageAgent
        tmp = pathlib.Path(tempfile.mkdtemp())
        return TriageAgent(EngagementConfig(repo_path="/tmp"), tmp / "triage", StubRunner())

    def test_merges_cross_batch_duplicates(self):
        agent = self._agent()
        findings = [
            {"title": "SQLi", "file": "app.py", "line_start": 10, "cwe_id": 89,
             "severity": "high", "cvss_score": 7.0, "original_ids": ["VULN-1"]},
            {"title": "SQL injection", "file": "app.py", "line_start": 10, "cwe_id": 89,
             "severity": "critical", "cvss_score": 9.0, "original_ids": ["SEC-2"]},
            {"title": "XSS", "file": "view.py", "line_start": 5, "cwe_id": 79, "severity": "medium"},
        ]
        out = agent._dedup_findings(findings)
        self.assertEqual(len(out), 2)                      # first two merged
        merged = out[0]
        self.assertEqual(merged["severity"], "critical")    # worst-case kept
        self.assertEqual(merged["cvss_score"], 9.0)
        self.assertEqual(set(merged["original_ids"]), {"VULN-1", "SEC-2"})


class TestEffort(unittest.TestCase):
    def test_claude_runner_carries_effort(self):
        from utils.runners.claude import ClaudeRunner
        self.assertEqual(ClaudeRunner(effort="high").extra_config.get("effort"), "high")


class TestOsvCount(unittest.TestCase):
    def test_counts_all_packages(self):
        from agents.dependency_audit import _count_osv_vulns
        data = {"results": [
            {"packages": [{"vulnerabilities": [1, 2]}, {"vulnerabilities": [3]}]},
            {"packages": [{"vulnerabilities": [4]}]},
        ]}
        # old packages[0]-only logic would have returned 3
        self.assertEqual(_count_osv_vulns(data), 4)


if __name__ == "__main__":
    unittest.main()
