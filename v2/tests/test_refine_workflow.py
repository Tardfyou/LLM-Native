import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.tools import ToolRegistry, ToolResult
from src.refine.agent import LangChainRefinementAgent
from src.refine.models import RefinementRequest


class StubTool:
    def __init__(self, name, fn):
        self.name = name
        self.description = name
        self.parameters_schema = {}
        self._fn = fn

    def execute(self, **kwargs):
        return self._fn(**kwargs)


class SequenceLLM:
    def __init__(self, responses):
        self._responses = list(responses)
        self.prompts = []
        self.bind_calls = []

    def bind(self, **kwargs):
        self.bind_calls.append(kwargs)
        return self

    def invoke(self, messages):
        self.prompts.append([getattr(message, "content", message) for message in messages])
        if not self._responses:
            raise AssertionError("Unexpected extra LLM call.")
        return self._responses.pop(0)


class RefineWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "paths": {
                "prompts_dir": str(PROJECT_ROOT / "prompts"),
            },
            "agent": {
                "max_iterations": 8,
            },
            "quality_gates": {
                "artifact_review": {
                    "enabled": True,
                }
            },
            "refine": {
                "structural_candidate": {
                    "enabled": False,
                }
            },
        }

    def _make_registry(self, root: Path, *, review_results):
        registry = ToolRegistry()
        calls = []
        review_queue = list(review_results)

        def register(name, fn):
            def wrapped(**kwargs):
                calls.append((name, dict(kwargs)))
                return fn(**kwargs)

            registry.register(StubTool(name, wrapped))

        def read_file(path: str):
            file_path = Path(path)
            if not file_path.exists():
                return ToolResult(success=False, output="", error=f"missing file: {path}")
            return ToolResult(success=True, output=file_path.read_text(encoding="utf-8"), metadata={"path": str(file_path)})

        def review_artifact(**_kwargs):
            passed = review_queue.pop(0) if review_queue else True
            if passed:
                return ToolResult(success=True, output="review ok", metadata={"findings": []})
            return ToolResult(success=False, output="review findings", error="review failed", metadata={"findings": ["bind guard to real capacity"]})

        def lsp_validate(**_kwargs):
            return ToolResult(success=True, output="lsp ok")

        def compile_checker(checker_name: str, output_dir: str, **_kwargs):
            output_path = Path(output_dir) / f"{checker_name}.so"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"\x7fELF")
            return ToolResult(success=True, output="compile ok", metadata={"output_file": str(output_path)})

        def semantic_validate(**_kwargs):
            return ToolResult(success=True, output="漏洞报告数: 1", metadata={"total_bug_reports": 1})

        def codeql_analyze(**_kwargs):
            return ToolResult(success=True, output="analysis ok", metadata={"diagnostics_count": 1})

        def apply_patch(target_path: str, resulting_content: str = "", **_kwargs):
            if not resulting_content:
                return ToolResult(success=False, output="", error="missing resulting content")
            file_path = Path(target_path)
            file_path.write_text(resulting_content, encoding="utf-8")
            return ToolResult(success=True, output="patch applied", metadata={"path": str(file_path)})

        register("read_file", read_file)
        register("review_artifact", review_artifact)
        register("lsp_validate", lsp_validate)
        register("compile_checker", compile_checker)
        register("semantic_validate", semantic_validate)
        register("codeql_analyze", codeql_analyze)
        register("apply_patch", apply_patch)
        return registry, calls

    def test_refine_can_finish_without_changes_when_baseline_review_passes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_path = root / "ExistingChecker.cpp"
            patch_path = root / "fix.patch"
            target_path.write_text("int guarded() { return 1; }\n", encoding="utf-8")
            patch_path.write_text("diff --git a/a.c b/a.c\n", encoding="utf-8")

            registry, calls = self._make_registry(root, review_results=[True])
            llm = SequenceLLM(
                [
                    '{"cot_analysis":{"baseline_quality":"已过关","mechanism_gap":"无","checker_weaknesses":[],"missing_context":"无","evidence_needed":[],"strategy":"直接结束"},"action":"finish","summary":"基线质量已过关，无需继续精炼","evidence_types":[],"patch":"","resulting_content":""}',
                ]
            )
            agent = LangChainRefinementAgent(
                config=self.config,
                tool_registry=registry,
                analyzer="csa",
                llm_override=llm,
            )

            result = agent.run(
                RefinementRequest(
                    analyzer="csa",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    target_path=str(target_path),
                    validate_path=str(root),
                    checker_name="ExistingChecker",
                    max_iterations=4,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual(result.output_path, str(target_path))
            self.assertEqual(result.compile_attempts, 0)
            self.assertTrue(result.metadata["accepted_without_changes"])
            self.assertEqual([name for name, _ in calls], ["read_file", "read_file", "review_artifact"])

    def test_refine_validation_failures_go_to_repair_prompt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_path = root / "RepairChecker.cpp"
            patch_path = root / "fix.patch"
            target_path.write_text("int vulnerable() { return 0; }\n", encoding="utf-8")
            patch_path.write_text("diff --git a/a.c b/a.c\n", encoding="utf-8")

            registry, calls = self._make_registry(root, review_results=[False, True, False, True])
            llm = SequenceLLM(
                [
                    '{"action":"apply_patch","summary":"先把当前轮需要的核心语义改动一次补上","evidence_types":[],"edits":[{"old_snippet":"int vulnerable() { return 0; }\\n","new_snippet":"int almost_repaired() { return 1; }\\n"}]}',
                    '{"cot_analysis":{"baseline_quality":"未过关","mechanism_gap":"主体机制已补上，进入验证","checker_weaknesses":[],"missing_context":"无","evidence_needed":[],"strategy":"进入验证"},"action":"validate","summary":"当前轮语义建模已完成，进入本地验证","evidence_types":[],"patch":"","resulting_content":""}',
                    '{"action":"apply_patch","summary":"只修这次 review 失败","edits":[{"old_snippet":"int almost_repaired() { return 1; }\\n","new_snippet":"int repaired() { return 2; }\\n"}]}',
                    '{"action":"finish","summary":"新基线已经通过本大轮质量门，停止精炼","evidence_types":[],"edits":[]}',
                ]
            )
            agent = LangChainRefinementAgent(
                config=self.config,
                tool_registry=registry,
                analyzer="csa",
                llm_override=llm,
            )

            result = agent.run(
                RefinementRequest(
                    analyzer="csa",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    target_path=str(target_path),
                    validate_path=str(root),
                    checker_name="RepairChecker",
                    max_iterations=6,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual(target_path.read_text(encoding="utf-8"), "int repaired() { return 2; }\n")
            self.assertEqual(llm.prompts[2][1].count("最后一次失败工具：validate.review_artifact"), 1)
            self.assertIn("review findings", llm.prompts[2][1])
            self.assertEqual(
                [name for name, _ in calls],
                [
                    "read_file",
                    "read_file",
                    "review_artifact",
                    "lsp_validate",
                    "review_artifact",
                    "apply_patch",
                    "read_file",
                    "lsp_validate",
                    "review_artifact",
                    "lsp_validate",
                    "apply_patch",
                    "read_file",
                    "lsp_validate",
                    "review_artifact",
                    "compile_checker",
                    "semantic_validate",
                ],
            )


    def test_refine_decide_reloads_latest_artifact_after_each_patch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_path = root / "LatestChecker.cpp"
            patch_path = root / "fix.patch"
            target_path.write_text("int base_version() { return 0; }\n", encoding="utf-8")
            patch_path.write_text("diff --git a/a.c b/a.c\n+semantic change\n", encoding="utf-8")

            registry, calls = self._make_registry(root, review_results=[False, True, True, True])
            llm = SequenceLLM(
                [
                    '{"action":"apply_patch","summary":"先把第一段语义补上","evidence_types":[],"edits":[{"old_snippet":"int base_version() { return 0; }\\n","new_snippet":"int first_version() { return 1; }\\n"}]}',
                    '{"action":"apply_patch","summary":"继续在最新代码上做第二次语义增强","evidence_types":[],"edits":[{"old_snippet":"int first_version() { return 1; }\\n","new_snippet":"int second_version() { return 2; }\\n"}]}',
                    '{"cot_analysis":{"baseline_quality":"当前轮已够用","mechanism_gap":"无","checker_weaknesses":[],"missing_context":"无","evidence_needed":[],"strategy":"进入验证"},"action":"validate","summary":"当前工作副本已经完成语义增强，进入验证","evidence_types":[],"patch":"","resulting_content":""}',
                    '{"action":"finish","summary":"新基线已经通过本大轮质量门，停止精炼","evidence_types":[],"edits":[]}',
                ]
            )
            agent = LangChainRefinementAgent(
                config=self.config,
                tool_registry=registry,
                analyzer="csa",
                llm_override=llm,
            )

            result = agent.run(
                RefinementRequest(
                    analyzer="csa",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    target_path=str(target_path),
                    validate_path=str(root),
                    checker_name="LatestChecker",
                    max_iterations=6,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual(target_path.read_text(encoding="utf-8"), "int second_version() { return 2; }\n")
            self.assertIn("int base_version() { return 0; }", llm.prompts[0][1])
            self.assertIn("int first_version() { return 1; }", llm.prompts[1][1])
            self.assertNotIn("int base_version() { return 0; }", llm.prompts[1][1])
            apply_calls = [(name, args) for name, args in calls if name == "apply_patch"]
            self.assertEqual(len(apply_calls), 2)
            self.assertTrue(all(args["target_path"] == str(target_path) for _, args in apply_calls))

    def test_refine_validation_success_returns_to_decide_for_next_round(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_path = root / "RoundChecker.cpp"
            patch_path = root / "fix.patch"
            target_path.write_text("int base_version() { return 0; }\n", encoding="utf-8")
            patch_path.write_text("diff --git a/a.c b/a.c\n+semantic change\n", encoding="utf-8")

            registry, calls = self._make_registry(root, review_results=[False, True, True, True, True])
            llm = SequenceLLM(
                [
                    '{"action":"apply_patch","summary":"补第一轮语义","evidence_types":[],"edits":[{"old_snippet":"int base_version() { return 0; }\\n","new_snippet":"int first_round() { return 1; }\\n"}]}',
                    '{"action":"validate","summary":"第一轮语义已够，进入验证","evidence_types":[],"edits":[]}',
                    '{"action":"apply_patch","summary":"基于新基线继续补第二轮语义","evidence_types":[],"edits":[{"old_snippet":"int first_round() { return 1; }\\n","new_snippet":"int second_round() { return 2; }\\n"}]}',
                    '{"action":"validate","summary":"第二轮语义已够，进入验证","evidence_types":[],"edits":[]}',
                ]
            )
            agent = LangChainRefinementAgent(
                config={
                    **self.config,
                    "refine": {
                        "max_rounds": 2,
                        "structural_candidate": {"enabled": False},
                    },
                },
                tool_registry=registry,
                analyzer="csa",
                llm_override=llm,
            )

            result = agent.run(
                RefinementRequest(
                    analyzer="csa",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    target_path=str(target_path),
                    validate_path=str(root),
                    checker_name="RoundChecker",
                    max_iterations=8,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual(target_path.read_text(encoding="utf-8"), "int second_round() { return 2; }\n")
            self.assertEqual(result.metadata["validation_rounds"], 2)
            self.assertIn("validation.round_1_passed", llm.prompts[2][1])
            self.assertEqual([name for name, _ in calls].count("compile_checker"), 2)
            self.assertEqual([name for name, _ in calls].count("semantic_validate"), 2)

    def test_codeql_apply_patch_success_enters_validate_immediately(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_path = root / "GuardedQuery.ql"
            patch_path = root / "fix.patch"
            target_path.write_text("from int x select x\n", encoding="utf-8")
            patch_path.write_text("diff --git a/a.c b/a.c\n+guard\n", encoding="utf-8")

            registry, calls = self._make_registry(root, review_results=[False, True, True])
            llm = SequenceLLM(
                [
                    '{"action":"apply_patch","summary":"先补上第一轮查询语义","evidence_types":[],"edits":[{"old_snippet":"from int x select x\\n","new_snippet":"from int x where x = 1 select x\\n"}]}',
                ]
            )
            agent = LangChainRefinementAgent(
                config={
                    **self.config,
                    "refine": {
                        "max_rounds": 1,
                        "structural_candidate": {"enabled": False},
                    },
                },
                tool_registry=registry,
                analyzer="codeql",
                llm_override=llm,
            )

            result = agent.run(
                RefinementRequest(
                    analyzer="codeql",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    target_path=str(target_path),
                    validate_path=str(root),
                    checker_name="GuardedQuery",
                    max_iterations=4,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual(target_path.read_text(encoding="utf-8"), "from int x where x = 1 select x\n")
            self.assertIn("codeql_analyze", [name for name, _ in calls])
            self.assertEqual(
                [name for name, _ in calls],
                [
                    "read_file",
                    "read_file",
                    "review_artifact",
                    "review_artifact",
                    "apply_patch",
                    "read_file",
                    "review_artifact",
                    "codeql_analyze",
                ],
            )


if __name__ == "__main__":
    unittest.main()
