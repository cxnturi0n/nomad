"""
Stdlib smoke tests for nomad. No third-party deps, no network, no provider calls.

Run:
    python3 -m unittest discover -s tests -v
"""

import importlib.util
import json
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
        out, remap = agent._dedup_findings(findings)
        self.assertEqual(len(out), 2)                      # first two merged
        merged = out[0]
        self.assertEqual(merged["severity"], "critical")    # worst-case kept
        self.assertEqual(merged["cvss_score"], 9.0)
        self.assertEqual(set(merged["original_ids"]), {"VULN-1", "SEC-2"})
        # remap has no ids here (findings carry no "id"); it stays empty
        self.assertEqual(remap, {})

    def test_merge_batches_keeps_chain_cross_refs_coherent(self):
        # Renumber + cross-batch dedup + sort must not leave attack_chains
        # pointing at stale/dangling finding ids. Batch-local ids collide across
        # batches, and a duplicate is merged away — every path must remap.
        agent = self._agent()
        batch1 = {
            "findings": [
                {"id": "TRIAGE-001", "title": "SQLi", "file": "a.py", "line_start": 10,
                 "cwe_id": 89, "cvss_score": 9.8, "severity": "critical",
                 "confidence": "high", "attack_chain": "CHAIN-1"},
                {"id": "TRIAGE-002", "title": "XSS", "file": "b.py", "line_start": 20,
                 "cwe_id": 79, "cvss_score": 6.1, "severity": "medium",
                 "confidence": "medium", "attack_chain": "CHAIN-1"},
            ],
            "attack_chains": [{"id": "CHAIN-1", "title": "c1", "severity": "critical",
                               "cvss_score": 9.8, "description": "",
                               "finding_ids": ["TRIAGE-001", "TRIAGE-002"], "combined_impact": ""}],
            "dedup_log": [],
        }
        batch2 = {
            "findings": [
                # duplicate of batch1 SQLi (same file/line/cwe) -> merged away
                {"id": "TRIAGE-001", "title": "SQLi dup", "file": "a.py", "line_start": 10,
                 "cwe_id": 89, "cvss_score": 9.8, "severity": "critical",
                 "confidence": "high", "attack_chain": "CHAIN-1"},
                {"id": "TRIAGE-002", "title": "SSRF", "file": "c.py", "line_start": 30,
                 "cwe_id": 918, "cvss_score": 8.6, "severity": "high",
                 "confidence": "high", "attack_chain": "CHAIN-1"},
            ],
            "attack_chains": [{"id": "CHAIN-1", "title": "c2", "severity": "high",
                               "cvss_score": 8.6, "description": "",
                               "finding_ids": ["TRIAGE-001", "TRIAGE-002"], "combined_impact": ""}],
            "dedup_log": [],
        }
        merged = agent._merge_batches([batch1, batch2], total_input=4)

        fids = {f["id"] for f in merged["findings"]}
        cids = [c["id"] for c in merged["attack_chains"]]
        # chain ids are globally unique (batch-local collision resolved)
        self.assertEqual(len(cids), len(set(cids)))
        # no chain references a nonexistent finding
        for c in merged["attack_chains"]:
            for ref in c["finding_ids"]:
                self.assertIn(ref, fids, f"dangling finding ref {ref} in {c['id']}")
        # every finding.attack_chain resolves to a real chain
        for f in merged["findings"]:
            if f.get("attack_chain"):
                self.assertIn(f["attack_chain"], set(cids))


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


class SupportingStubRunner(StubRunner):
    """A stub that claims structured-output support (for gating tests)."""
    supports_structured_output = True


class TestStructuredOutput(unittest.TestCase):
    def _claude(self):
        from utils.runners.claude import ClaudeRunner
        return ClaudeRunner()

    def test_config_default_off(self):
        self.assertFalse(EngagementConfig(repo_path="/tmp").structured_output)

    def test_capability_flags(self):
        from utils.runners.claude import ClaudeRunner
        from utils.runners.openai import OpenAIRunner
        from utils.runners.ollama import OllamaRunner
        self.assertTrue(ClaudeRunner().supports_structured_output)
        self.assertFalse(OpenAIRunner().supports_structured_output)
        self.assertFalse(OllamaRunner().supports_structured_output)

    def test_parse_prefers_structured_output_object(self):
        # structured_output must win over the (deliberately bogus) result text.
        raw = json.dumps({
            "type": "result",
            "result": "not json at all",
            "structured_output": {"findings": [{"title": "x"}], "summary": {}},
            "total_cost_usd": 0.02,
        })
        parsed, cost = self._claude()._parse_output(raw)
        self.assertEqual(parsed, {"findings": [{"title": "x"}], "summary": {}})
        self.assertEqual(cost, 0.02)

    def test_parse_structured_output_in_event_array(self):
        raw = json.dumps([
            {"type": "system"},
            {"type": "result", "result": "nope", "structured_output": {"a": 1}, "total_cost_usd": 0.03},
        ])
        parsed, cost = self._claude()._parse_output(raw)
        self.assertEqual(parsed, {"a": 1})
        self.assertEqual(cost, 0.03)

    def test_parse_falls_back_to_text_without_structured(self):
        raw = json.dumps({"type": "result", "result": '{"findings": []}', "total_cost_usd": 0.01})
        parsed, cost = self._claude()._parse_output(raw)
        self.assertEqual(parsed, {"findings": []})
        self.assertEqual(cost, 0.01)

    def test_empty_structured_output_ignored(self):
        # An empty {} structured_output should not shadow real result text.
        raw = json.dumps({"type": "result", "result": '{"findings": [{"title": "y"}]}',
                          "structured_output": {}, "total_cost_usd": 0.0})
        parsed, _ = self._claude()._parse_output(raw)
        self.assertEqual(parsed, {"findings": [{"title": "y"}]})

    def test_static_agent_declares_schema(self):
        from agents.static_analysis import StaticAnalysisAgent, STATIC_OUTPUT_SCHEMA
        self.assertIs(StaticAnalysisAgent.output_schema, STATIC_OUTPUT_SCHEMA)
        # strict-mode shape the CLI requires
        self.assertEqual(STATIC_OUTPUT_SCHEMA["additionalProperties"], False)
        item = STATIC_OUTPUT_SCHEMA["properties"]["findings"]["items"]
        self.assertEqual(item["additionalProperties"], False)
        # every property is required (strict), and the escape hatch exists
        self.assertEqual(set(item["required"]), set(item["properties"].keys()))
        self.assertIn("notes", item["properties"])

    def _static_agent(self, runner, structured):
        from agents.static_analysis import StaticAnalysisAgent
        tmp = pathlib.Path(tempfile.mkdtemp())
        cfg = EngagementConfig(repo_path=str(tmp), structured_output=structured)
        return StaticAnalysisAgent(cfg, tmp / "a2", runner)

    def test_use_structured_requires_all_three(self):
        # all aligned -> on
        self.assertTrue(self._static_agent(SupportingStubRunner(), True)._use_structured())
        # runner can't -> off
        self.assertFalse(self._static_agent(StubRunner(), True)._use_structured())
        # user opted out -> off
        self.assertFalse(self._static_agent(SupportingStubRunner(), False)._use_structured())

    def test_use_structured_off_when_agent_has_no_schema(self):
        # An agent that declares no output_schema must never use structured mode,
        # even when the runner supports it and the user opted in.
        from agents.base import BaseAgent

        class _NoSchemaAgent(BaseAgent):
            name = "no_schema"
            output_schema = None

            def get_system_prompt(self):
                return ""

            def get_task_prompt(self, context=None):
                return ""

            def parse_output(self, result):
                return {}

        tmp = pathlib.Path(tempfile.mkdtemp())
        cfg = EngagementConfig(repo_path=str(tmp), structured_output=True)
        agent = _NoSchemaAgent(cfg, tmp / "noschema", SupportingStubRunner())
        self.assertIsNone(agent.output_schema)
        self.assertFalse(agent._use_structured())

    def test_notes_folded_into_description(self):
        agent = self._static_agent(SupportingStubRunner(), True)
        rr = RunResult(success=True, parsed_json={"findings": [
            {"title": "T", "description": "base desc", "notes": "extra context"},
        ]})
        out = agent.parse_output(rr)
        desc = out["findings"][0]["description"]
        self.assertIn("base desc", desc)
        self.assertIn("extra context", desc)

    def test_help_exposes_structured_flags(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "nomad"), "--help"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertIn("--structured-output", proc.stdout)
        self.assertIn("--no-structured-output", proc.stdout)

    def test_all_agents_declare_strict_schema(self):
        # Every pipeline agent now defines a strict, CLI-compatible output_schema.
        from agents.recon import ReconAgent
        from agents.static_analysis import StaticAnalysisAgent
        from agents.secrets import SecretsAgent
        from agents.dependency_audit import DependencyAuditAgent
        from agents.triage import TriageAgent
        from agents.fingerprint import FingerprintAgent
        from agents.validation import ValidationAgent

        def assert_strict(node, path):
            if isinstance(node, dict):
                if node.get("type") == "object" and "properties" in node:
                    self.assertIs(node.get("additionalProperties"), False, path)
                    self.assertEqual(set(node["properties"]), set(node.get("required", [])), path)
                    for k, v in node["properties"].items():
                        assert_strict(v, f"{path}.{k}")
                elif node.get("type") == "array":
                    assert_strict(node.get("items", {}), f"{path}[]")

        for cls in (ReconAgent, StaticAnalysisAgent, SecretsAgent, DependencyAuditAgent,
                    TriageAgent, FingerprintAgent, ValidationAgent):
            self.assertIsNotNone(cls.output_schema, cls.__name__)
            json.dumps(cls.output_schema)  # must be serializable for --json-schema
            assert_strict(cls.output_schema, cls.__name__)

    def test_structured_default_on_for_claude_only(self):
        # The provider decides the default: ON for claude, OFF for others,
        # unless the user passes an explicit --structured-output/--no-... flag.
        mod = _load_orchestrator()
        tmp = tempfile.mkdtemp()

        def parse(argv):
            saved = sys.argv
            sys.argv = ["nomad", "--repo", tmp, *argv]
            try:
                return mod.parse_args()
            finally:
                sys.argv = saved

        self.assertTrue(parse([]).structured_output)                       # claude default
        self.assertTrue(parse(["--provider", "claude"]).structured_output)
        self.assertFalse(parse(["--provider", "ollama"]).structured_output)
        self.assertFalse(parse(["--no-structured-output"]).structured_output)  # explicit off
        self.assertTrue(parse(["--provider", "ollama", "--structured-output"]).structured_output)  # explicit on


if __name__ == "__main__":
    unittest.main()
