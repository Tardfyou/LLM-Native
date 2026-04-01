import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.tools import ToolRegistry, ToolResult
from src.generate import GenerationRequest, LangChainGenerateAgent
from src.generate.toolkit import GenerationToolkit, GenerationTracker
from src.prompts import PromptRepository


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


class GenerateWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "paths": {
                "prompts_dir": str(PROJECT_ROOT / "prompts"),
            },
            "agent": {
                "max_iterations": 8,
                "generate_max_knowledge_search_calls": 2,
                "required_knowledge_min_similarity": 0.35,
                "required_knowledge_min_results": 1,
            },
            "quality_gates": {
                "artifact_review": {
                    "enabled": True,
                }
            },
        }

    def _make_registry(
        self,
        root: Path,
        analyzer: str,
        *,
        review_results=None,
        knowledge_success: bool = True,
        knowledge_metadata=None,
    ):
        registry = ToolRegistry()
        calls = []
        review_queue = list(review_results or [True])
        knowledge_metadata = dict(knowledge_metadata or {"top_similarity": 0.92, "qualified_count": 2})

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

        def analyze_patch(**_kwargs):
            metadata = {
                "affected_functions": ["handle_request"],
                "vulnerability_patterns": [{"pattern_type": "buffer_overflow" if analyzer == "csa" else "taint_tracking"}],
            }
            return ToolResult(success=True, output="patch analysis", metadata=metadata)

        def search_knowledge(**kwargs):
            if not knowledge_success:
                return ToolResult(success=False, output="", error=f"knowledge miss: {kwargs.get('query', '')}")
            return ToolResult(success=True, output="retrieved skeleton", metadata=knowledge_metadata)

        def lsp_validate(**_kwargs):
            return ToolResult(success=True, output="lsp ok")

        def write_file(path: str, content: str):
            file_path = Path(path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
            return ToolResult(success=True, output="write ok", metadata={"path": str(file_path)})

        def review_artifact(**_kwargs):
            passed = review_queue.pop(0) if review_queue else True
            if passed:
                return ToolResult(success=True, output="review ok", metadata={"findings": []})
            return ToolResult(success=False, output="review findings", error="review failed", metadata={"findings": ["fix trigger"]})

        def compile_checker(checker_name: str, output_dir: str, **_kwargs):
            output_path = Path(output_dir) / f"{checker_name}.so"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"\x7fELF")
            return ToolResult(success=True, output="compile ok", metadata={"output_file": str(output_path)})

        def generate_codeql_query(query_name: str, custom_query: str, **_kwargs):
            query_text = (
                "/** generated */\n"
                "import cpp\n\n"
                f"predicate patchGuidedMatch(Stmt node) {{\n  exists(string name | name = \"{query_name}\") and\n  {custom_query.strip() or 'false'}\n}}\n\n"
                "from Stmt node\n"
                "where patchGuidedMatch(node)\n"
                "select node, \"match\"\n"
            )
            return ToolResult(success=True, output="query built", metadata={"query_code": query_text})

        def codeql_analyze(**_kwargs):
            return ToolResult(success=True, output="codeql ok")

        def apply_patch(target_path: str, resulting_content: str = "", **_kwargs):
            if not resulting_content:
                return ToolResult(success=False, output="", error="missing resulting content")
            file_path = Path(target_path)
            file_path.write_text(resulting_content, encoding="utf-8")
            return ToolResult(success=True, output="patch applied", metadata={"path": str(file_path)})

        register("read_file", read_file)
        register("analyze_patch", analyze_patch)
        register("search_knowledge", search_knowledge)
        register("write_file", write_file)
        register("review_artifact", review_artifact)
        register("compile_checker", compile_checker)
        register("generate_codeql_query", generate_codeql_query)
        register("codeql_analyze", codeql_analyze)
        register("lsp_validate", lsp_validate)
        register("apply_patch", apply_patch)
        return registry, calls

    def test_prompt_manifest_resolves_new_generate_ids_and_drops_old_tree(self):
        repository = PromptRepository(config={"paths": {"prompts_dir": str(PROJECT_ROOT / "prompts")}})

        for prompt_id in (
            "generate.agent.system",
            "generate.agent.task",
            "generate.agent.plan",
            "generate.agent.draft",
            "generate.agent.repair",
            "generate.agent.analyzer.csa",
            "generate.agent.analyzer.codeql",
            "generate.agent.reference.csa",
            "generate.agent.reference.codeql",
            "refine.agent.system",
            "refine.agent.task",
            "refine.agent.decide",
        ):
            self.assertTrue(repository.has_prompt(prompt_id), prompt_id)

        csa_reference = repository.load_text("generate.agent.reference.csa", strict=True)
        self.assertIn("clang/StaticAnalyzer/Frontend/CheckerRegistry.h", csa_reference)
        self.assertIn("CLANG_VERSION_STRING", csa_reference)
        codeql_reference = repository.load_text("generate.agent.reference.codeql", strict=True)
        self.assertIn("SizeofExprOperator", codeql_reference)
        self.assertIn("ensuresLt", codeql_reference)
        self.assertFalse(repository.has_prompt("agent.system"))

        generate_repair = repository.load_text("generate.agent.repair", strict=True)
        self.assertIn("最后一次失败工具", generate_repair)
        self.assertIn("修复顺序", generate_repair)
        self.assertIn("当前焦点行", generate_repair)
        self.assertIn("edits", generate_repair)

        refine_decide = repository.load_text("refine.agent.decide", strict=True)
        self.assertIn("最后一个失败工具的报错", refine_decide)
        self.assertIn("不要用 `resulting_content` 去整文件重写", refine_decide)

    def test_uaf_knowledge_keeps_generalized_relookup_seeds(self):
        codeql_patterns = json.loads((PROJECT_ROOT / "data/knowledge/codeql/ql_patterns.json").read_text(encoding="utf-8"))
        codeql_examples = json.loads((PROJECT_ROOT / "data/knowledge/codeql/ql_examples.json").read_text(encoding="utf-8"))
        csa_examples = json.loads((PROJECT_ROOT / "data/knowledge/csa/checker_examples.json").read_text(encoding="utf-8"))
        csa_cwe = json.loads((PROJECT_ROOT / "data/knowledge/csa/cwe_patterns.json").read_text(encoding="utf-8"))

        self.assertIn("use-after-free-stable-handle-relookup-pattern", {item["id"] for item in codeql_patterns})
        self.assertIn("use-after-free-stable-handle-cached-pointer-example", {item["id"] for item in codeql_examples})
        self.assertIn("use-after-free-plugin", {item["id"] for item in csa_examples})
        self.assertIn("use-after-free-cached-pointer-relookup", {item["id"] for item in csa_examples})
        self.assertIn("cwe-416", {item["id"] for item in csa_cwe})

    def test_csa_generate_workflow_keeps_gate_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            patch_path = root / "buffer.patch"
            patch_path.write_text("diff --git a/a.c b/a.c\n", encoding="utf-8")

            registry, calls = self._make_registry(root, "csa")
            llm = SequenceLLM(
                [
                    '{"summary":"plan","checker_name":"BufferOverflowChecker","knowledge_query":"clang18 csa buffer guard skeleton","vulnerability_type":"buffer_overflow","query_description":"buffer overflow","pattern_description":"guarded buffer writes"}',
                    '{"summary":"draft","checker_name":"BufferOverflowChecker","content":"class BufferOverflowChecker {}\\n"}',
                ]
            )
            agent = LangChainGenerateAgent(
                config=self.config,
                tool_registry=registry,
                analyzer="csa",
                llm_override=llm,
            )

            result = agent.run(
                GenerationRequest(
                    analyzer="csa",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    validate_path=str(root),
                    max_iterations=6,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual(
                [name for name, _ in calls],
                [
                    "read_file",
                    "analyze_patch",
                    "search_knowledge",
                    "lsp_validate",
                    "write_file",
                    "read_file",
                    "lsp_validate",
                    "review_artifact",
                    "compile_checker",
                ],
            )
            self.assertTrue(Path(result.output_path).exists())
            self.assertEqual(result.checker_name, "BufferOverflowChecker")
            self.assertEqual(result.compile_attempts, 1)

    def test_codeql_generate_workflow_keeps_gate_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            patch_path = root / "taint.patch"
            patch_path.write_text("diff --git a/a.c b/a.c\n", encoding="utf-8")

            registry, calls = self._make_registry(root, "codeql")
            llm = SequenceLLM(
                [
                    '{"summary":"plan","checker_name":"PatchFlowQuery","knowledge_query":"codeql taint barrier skeleton","vulnerability_type":"taint_tracking","query_description":"taint flow query","pattern_description":"missing barrier on data flow"}',
                    '{"summary":"draft","checker_name":"PatchFlowQuery","content":"exists(FunctionCall call | false)"}',
                ]
            )
            agent = LangChainGenerateAgent(
                config=self.config,
                tool_registry=registry,
                analyzer="codeql",
                llm_override=llm,
            )

            result = agent.run(
                GenerationRequest(
                    analyzer="codeql",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    validate_path=str(root),
                    max_iterations=6,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual(
                [name for name, _ in calls],
                [
                    "read_file",
                    "analyze_patch",
                    "search_knowledge",
                    "generate_codeql_query",
                    "write_file",
                    "read_file",
                    "review_artifact",
                    "codeql_analyze",
                ],
            )
            self.assertTrue(Path(result.output_path).exists())
            self.assertEqual(result.output_path, str(root / "PatchFlowQuery.ql"))
            self.assertEqual(result.compile_attempts, 0)

    def test_generate_repairs_use_apply_patch_without_second_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            patch_path = root / "repair.patch"
            patch_path.write_text("diff --git a/a.c b/a.c\n", encoding="utf-8")

            registry, calls = self._make_registry(root, "csa", review_results=[False, True])
            llm = SequenceLLM(
                [
                    '{"summary":"plan","checker_name":"RepairChecker","knowledge_query":"clang18 csa repair skeleton","vulnerability_type":"buffer_overflow","query_description":"repair","pattern_description":"repair"}',
                    '{"summary":"draft","checker_name":"RepairChecker","content":"int vulnerable() { return 0; }\\n"}',
                    '{"action":"apply_patch","summary":"tighten the implementation","query":"","edits":[{"old_snippet":"int vulnerable() { return 0; }\\n","new_snippet":"int repaired() { return 1; }\\n"}]}',
                ]
            )
            agent = LangChainGenerateAgent(
                config=self.config,
                tool_registry=registry,
                analyzer="csa",
                llm_override=llm,
            )

            result = agent.run(
                GenerationRequest(
                    analyzer="csa",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    validate_path=str(root),
                    max_iterations=8,
                )
            )

            self.assertTrue(result.success, result.error_message)
            call_names = [name for name, _ in calls]
            self.assertEqual(call_names.count("write_file"), 2)
            self.assertEqual(call_names.count("apply_patch"), 0)
            self.assertEqual(
                call_names,
                [
                    "read_file",
                    "analyze_patch",
                    "search_knowledge",
                    "lsp_validate",
                    "write_file",
                    "read_file",
                    "lsp_validate",
                    "review_artifact",
                    "lsp_validate",
                    "write_file",
                    "read_file",
                    "lsp_validate",
                    "review_artifact",
                    "compile_checker",
                ],
            )
            repair_prompt = llm.prompts[2][1]
            self.assertIn("最后一次失败工具：validate.review_artifact", repair_prompt)
            self.assertIn("review findings", repair_prompt)
            self.assertEqual((root / "RepairChecker.cpp").read_text(encoding="utf-8"), "int repaired() { return 1; }\n")

    def test_generate_repairs_can_use_exact_snippet_replacement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            patch_path = root / "repair.patch"
            patch_path.write_text("diff --git a/a.c b/a.c\n", encoding="utf-8")

            registry, calls = self._make_registry(root, "csa", review_results=[False, True])
            llm = SequenceLLM(
                [
                    '{"summary":"plan","checker_name":"RepairChecker","knowledge_query":"clang18 csa repair skeleton","vulnerability_type":"buffer_overflow","query_description":"repair","pattern_description":"repair"}',
                    '{"summary":"draft","checker_name":"RepairChecker","content":"int vulnerable() { return 0; }\\n"}',
                    '{"action":"apply_patch","summary":"tighten the implementation","query":"","edits":[{"old_snippet":"int vulnerable() { return 0; }\\n","new_snippet":"int repaired() { return 1; }\\n"}]}',
                ]
            )
            agent = LangChainGenerateAgent(
                config=self.config,
                tool_registry=registry,
                analyzer="csa",
                llm_override=llm,
            )

            result = agent.run(
                GenerationRequest(
                    analyzer="csa",
                    patch_path=str(patch_path),
                    work_dir=str(root),
                    validate_path=str(root),
                    max_iterations=8,
                )
            )

            self.assertTrue(result.success, result.error_message)
            self.assertEqual((root / "RepairChecker.cpp").read_text(encoding="utf-8"), "int repaired() { return 1; }\n")
            self.assertEqual([name for name, _ in calls].count("apply_patch"), 0)
            self.assertEqual([name for name, _ in calls].count("write_file"), 2)

    def test_failed_knowledge_searches_still_consume_budget(self):
        registry = ToolRegistry()
        calls = []

        def search_knowledge(**kwargs):
            calls.append(dict(kwargs))
            return ToolResult(success=False, output="", error="miss")

        registry.register(StubTool("search_knowledge", search_knowledge))
        tracker = GenerationTracker(
            request=GenerationRequest(
                analyzer="csa",
                patch_path="dummy.patch",
                work_dir=".",
            )
        )
        toolkit = GenerationToolkit(
            tool_registry=registry,
            request=tracker.request,
            tracker=tracker,
            analyzer_name="CSA (Clang Static Analyzer)",
            max_knowledge_search_calls=2,
        )

        first = toolkit.search_knowledge("one")
        second = toolkit.search_knowledge("two")
        third = toolkit.search_knowledge("three")

        self.assertFalse(first.success)
        self.assertFalse(second.success)
        self.assertFalse(third.success)
        self.assertEqual(len(calls), 2)
        self.assertIn("最多只允许调用 2 次", third.error or "")

    def test_patch_hit_check_uses_changed_lines_not_just_hunk_start(self):
        agent = LangChainGenerateAgent(
            config=self.config,
            tool_registry=ToolRegistry(),
            analyzer="codeql",
            llm_override=SequenceLLM([]),
        )

        self.assertTrue(
            agent._patch_changes_failure_lines(
                "--- a/test.ql\n+++ b/test.ql\n@@ -54,4 +54,4 @@\n a\n b\n-old\n+new\n c\n",
                [56],
            )
        )
        self.assertFalse(
            agent._patch_changes_failure_lines(
                "--- a/test.ql\n+++ b/test.ql\n@@ -54,4 +54,4 @@\n-old\n+new\n b\n c\n d\n",
                [56],
            )
        )

    def test_exact_edits_require_unique_old_snippets(self):
        agent = LangChainGenerateAgent(
            config=self.config,
            tool_registry=ToolRegistry(),
            analyzer="codeql",
            llm_override=SequenceLLM([]),
        )

        replaced = agent._build_patch_from_exact_edits(
            file_name="test.ql",
            original_text="alpha\nbeta\n",
            edits=[{"old_snippet": "beta\n", "new_snippet": "gamma\n"}],
        )
        self.assertIn("+gamma", replaced["patch"])
        self.assertEqual(replaced["error"], "")

        missing = agent._build_patch_from_exact_edits(
            file_name="test.ql",
            original_text="alpha\nbeta\n",
            edits=[{"old_snippet": "delta\n", "new_snippet": "gamma\n"}],
        )
        self.assertIn("未在当前产物中命中", missing["error"])

        ambiguous = agent._build_patch_from_exact_edits(
            file_name="test.ql",
            original_text="beta\nbeta\n",
            edits=[{"old_snippet": "beta\n", "new_snippet": "gamma\n"}],
        )
        self.assertIn("不唯一", ambiguous["error"])


if __name__ == "__main__":
    unittest.main()
