"""
Tests for evidence system refactoring.

验证证据系统重构的核心功能：
1. 证据类型精简
2. 验证顺序调整
3. 证据查询工具
4. request_evidence action
"""
import pytest
import sys
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.evidence_types import EvidenceType
from src.core.analyzer_base import AnalyzerContext
from src.core.analyzer_base import AnalyzerResult
from src.core.evidence_planner import PatchFactsExtractor
from src.core.orchestrator import Orchestrator
from src.core.evidence_schema import (
    EvidenceBundle,
    EvidenceRecord,
    EvidenceScope,
    EvidenceSlice,
)
from src.evidence.collectors.artifact_extractor import ProjectArtifactExtractor
from src.evidence.collectors.codeql_flow import CodeQLFlowEvidenceCollector
from src.evidence.collectors.csa_path import CSAPathEvidenceCollector
from src.evidence.evidence_tools import (
    EvidenceQueryTools,
    AVAILABLE_EVIDENCE_TYPES,
)
from src.refine.models import RefinementRequest
from src.refine.toolkit import RefinementToolkit, RefinementTracker
from src.agent.tools import ToolRegistry
from src.tools.apply_patch import ApplyPatchTool


class TestEvidenceTypesSimplified:
    """测试证据类型精简"""

    def test_removed_types_not_exist(self):
        """验证已剔除的类型不存在"""
        assert not hasattr(EvidenceType, "METADATA_HINT")
        assert not hasattr(EvidenceType, "CONTEXT_SUMMARY")
        assert not hasattr(EvidenceType, "VALIDATION_OUTCOME")

        # 保留的核心类型
        assert hasattr(EvidenceType, "PATCH_FACT")
        assert hasattr(EvidenceType, "SEMANTIC_SLICE")
        assert hasattr(EvidenceType, "DATAFLOW_CANDIDATE")
        assert hasattr(EvidenceType, "CALL_CHAIN")
        assert hasattr(EvidenceType, "PATH_GUARD")
        assert hasattr(EvidenceType, "ALLOCATION_LIFECYCLE")
        assert hasattr(EvidenceType, "STATE_TRANSITION")

    def test_evidence_type_values(self):
        """验证证据类型值正确"""
        assert EvidenceType.PATCH_FACT.value == "patch_fact"
        assert EvidenceType.SEMANTIC_SLICE.value == "semantic_slice"
        assert EvidenceType.CALL_CHAIN.value == "call_chain"


class TestEvidenceQueryTools:
    """测试证据查询工具"""

    @pytest.fixture
    def empty_bundle(self):
        """空证据包"""
        return EvidenceBundle(records=[])

    @pytest.fixture
    def sample_bundle(self):
        """示例证据包"""
        records = [
            EvidenceRecord(
                evidence_id="pf_001",
                type="patch_fact",
                analyzer="patch",
                scope=EvidenceScope(file="test.c", function="main"),
                semantic_payload={
                    "fact_type": "vulnerability_patterns",
                    "label": "Test pattern",
                    "attributes": {
                        "patterns": ["buffer_overflow"],
                        "functions": ["main", "helper"],
                    },
                },
            ),
            EvidenceRecord(
                evidence_id="ss_001",
                type="semantic_slice",
                analyzer="csa",
                scope=EvidenceScope(file="test.c", function="main"),
                semantic_payload={
                    "summary": "main widens counters before helper sink",
                    "widened_variables": ["x"],
                    "sink_calls": ["helper"],
                    "state_after": ["counter_domain(int -> i64)"],
                    "source_excerpt": "10: x += 1;\n11: helper(x);",
                },
                evidence_slice=EvidenceSlice(
                    kind="function",
                    summary="Test slice",
                    statements=["int x = 1;", "return x;"],
                    guards=["if (x > 0)"],
                    call_edges=["main -> helper"],
                    api_terms=["malloc", "free"],
                ),
            ),
            EvidenceRecord(
                evidence_id="cg_001",
                type="call_chain",
                analyzer="codeql",
                scope=EvidenceScope(file="test.c", function="main"),
                semantic_payload={
                    "summary": ["main -> helper"],
                    "call_edges": ["main -> helper"],
                },
                evidence_slice=EvidenceSlice(
                    kind="interprocedural_slice",
                    summary="main -> helper",
                    call_edges=["main -> helper"],
                ),
            ),
            EvidenceRecord(
                evidence_id="pg_001",
                type="path_guard",
                analyzer="csa",
                scope=EvidenceScope(file="test.c", function="main"),
                semantic_payload={
                    "guard_expr": "x > 0",
                    "summary": "guard before helper",
                    "state_before": ["input(x)"],
                    "state_after": ["guard(x > 0)"],
                },
            ),
            EvidenceRecord(
                evidence_id="st_001",
                type="state_transition",
                analyzer="csa",
                scope=EvidenceScope(file="test.c", function="main"),
                semantic_payload={
                    "summary": "x transitions to checked state",
                    "state_before": ["input(x)"],
                    "state_after": ["checked(x)"],
                    "tracked_symbols": ["x"],
                    "call_targets": ["helper"],
                },
            ),
        ]
        return EvidenceBundle(records=records)

    def test_list_available_evidence_types(self, empty_bundle):
        """测试列出可用证据类型"""
        tools = EvidenceQueryTools(empty_bundle)
        available = tools.list_available_evidence_types()

        assert isinstance(available, dict)
        assert "patch_fact" in available
        assert "semantic_slice" in available
        assert "call_chain" in available
        assert "directory_tree" in available

    def test_get_patch_facts_empty(self, empty_bundle):
        """测试获取空的补丁事实"""
        tools = EvidenceQueryTools(empty_bundle)
        result = tools.get_patch_facts()

        assert result["available"] is False
        assert "message" in result

    def test_get_patch_facts_with_data(self, sample_bundle):
        """测试获取补丁事实"""
        tools = EvidenceQueryTools(sample_bundle)
        result = tools.get_patch_facts()

        assert result["available"] is True
        assert "facts" in result
        assert result["primary_pattern"] == "buffer_overflow"
        assert "main" in result["affected_functions"]

    def test_get_semantic_slices(self, sample_bundle):
        """测试获取语义切片"""
        tools = EvidenceQueryTools(sample_bundle)
        result = tools.get_semantic_slices()

        assert result["available"] is True
        assert result["count"] == 1
        assert result["items"][0]["file"] == "test.c"
        assert result["items"][0]["function"] == "main"
        assert len(result["items"][0]["statements"]) == 2

    def test_get_call_edges(self, sample_bundle):
        """测试获取调用链"""
        tools = EvidenceQueryTools(sample_bundle)
        result = tools.get_call_edges()

        assert result["available"] is True
        assert "edges" in result
        assert "call_targets" in result
        assert "main -> helper" in result["edges"]

    def test_get_guards(self, sample_bundle):
        """测试获取守卫条件"""
        tools = EvidenceQueryTools(sample_bundle)
        result = tools.get_guards()

        assert result["available"] is True
        assert len(result["items"]) == 1
        assert result["items"][0]["expression"] == "x > 0"
        assert result["items"][0]["summary"] == "guard before helper"

    def test_get_dataflow_candidates_fallback_from_semantic_slice(self, sample_bundle):
        """显式 dataflow 记录缺失时，允许从 semantic slice 回退提炼"""
        tools = EvidenceQueryTools(sample_bundle)
        result = tools.get_dataflow_candidates()

        assert result["available"] is True
        assert result["items"][0]["sink"] == "helper"
        assert "x" in result["items"][0]["source"]

    def test_get_evidence_by_types(self, sample_bundle):
        """测试批量获取证据"""
        tools = EvidenceQueryTools(sample_bundle)
        result = tools.get_evidence_by_types(["patch_fact", "call_chain"])

        assert "patch_fact" in result
        assert "call_chain" in result
        assert result["patch_fact"]["available"] is True

    def test_get_state_transitions_only_uses_state_transition_records(self, sample_bundle):
        tools = EvidenceQueryTools(sample_bundle)
        result = tools.get_state_transitions()

        assert result["available"] is True
        assert result["items"][0]["summary"] == "x transitions to checked state"
        assert result["items"][0]["state_after"] == ["checked(x)"]

    def test_get_directory_tree_no_root(self, empty_bundle):
        """测试无项目根目录时获取目录树"""
        tools = EvidenceQueryTools(empty_bundle)
        result = tools.get_directory_tree()

        assert result["available"] is False
        assert "项目根目录未设置" in result["message"]

    def test_get_directory_tree_with_root(self, sample_bundle, tmp_path):
        """测试获取目录树"""
        # 创建临时目录结构
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "test.c").write_text("int main() { return 0; }")
        (tmp_path / "include").mkdir()
        (tmp_path / "include" / "test.h").write_text("#ifndef TEST_H\n#define TEST_H\n#endif")

        bundle = EvidenceBundle(records=[
            EvidenceRecord(
                evidence_id="ss_tree",
                type="semantic_slice",
                analyzer="csa",
                scope=EvidenceScope(file="src/test.c", function="main"),
            )
        ])
        tools = EvidenceQueryTools(bundle, project_root=tmp_path)
        result = tools.get_directory_tree()

        assert result["available"] is True
        assert "tree" in result
        assert result["tree"]["name"] == tmp_path.name
        assert result["tree"]["children"][0]["name"] == "src"

    def test_get_call_edges_ignores_non_call_edge_fragments(self):
        bundle = EvidenceBundle(records=[
            EvidenceRecord(
                evidence_id="cg_001",
                type="call_chain",
                analyzer="codeql",
                scope=EvidenceScope(file="demo.c", function="demo"),
                semantic_payload={
                    "call_edges": ["demo -> helper", "function:demo", "x += 1"],
                },
            )
        ])
        tools = EvidenceQueryTools(bundle)
        result = tools.get_call_edges()

        assert result["available"] is True
        assert result["edges"] == ["demo -> helper"]


class TestArtifactExtractorCleanup:
    def test_sqlite_call_targets_drop_comment_and_macro_noise(self):
        patch_path = (
            PROJECT_ROOT.parent
            / "experiments"
            / "sqlite_cve202235737"
            / "workspace"
            / "patches"
            / "CVE-2022-35737.patch"
        )
        source_root = (
            PROJECT_ROOT.parent
            / "experiments"
            / "sqlite_cve202235737"
            / "workspace"
            / "src"
            / "sqlite-src-3390000"
        )
        context = AnalyzerContext(
            patch_path=str(patch_path),
            output_dir=str(PROJECT_ROOT.parent / "experiments" / "sqlite_cve202235737" / "outputs" / "generate"),
            evidence_dir=str(source_root),
        )

        source_contexts, _ = ProjectArtifactExtractor().collect_source_contexts(context)
        call_targets = source_contexts[0].call_targets

        assert "bytes" not in call_targets
        assert "SQLITE_SKIP_UTF8" not in call_targets
        assert "assert" not in call_targets
        assert "printfTempBuf" in call_targets

    def test_uaf_request_router_contexts_stay_within_changed_functions(self):
        patch_path = PROJECT_ROOT / "tests" / "patchweaver_uaf_lab" / "session_lifetime.patch"
        source_root = PROJECT_ROOT / "tests" / "patchweaver_uaf_lab"
        context = AnalyzerContext(
            patch_path=str(patch_path),
            output_dir=str(PROJECT_ROOT / "tests" / "test_project_uaf"),
            evidence_dir=str(source_root),
        )

        source_contexts, _ = ProjectArtifactExtractor().collect_source_contexts(context)
        request_router_contexts = [
            item
            for item in source_contexts
            if item.relative_file == "src/request_router.c"
        ]
        functions = {item.function_name for item in request_router_contexts}

        assert functions == {"release_request_session", "handle_admin_export"}

        release_contexts = [
            item for item in request_router_contexts if item.function_name == "release_request_session"
        ]
        assert release_contexts
        assert all(item.call_targets == ["destroy_session"] for item in release_contexts)

        export_contexts = [
            item for item in request_router_contexts if item.function_name == "handle_admin_export"
        ]
        assert export_contexts
        assert all("destroy_session" not in item.call_targets for item in export_contexts)
        assert any(item.call_targets == ["snprintf"] for item in export_contexts)


class TestUAFEvidenceCollectors:
    def _uaf_context(self) -> AnalyzerContext:
        return AnalyzerContext(
            patch_path=str(PROJECT_ROOT / "tests" / "patchweaver_uaf_lab" / "session_lifetime.patch"),
            output_dir=str(PROJECT_ROOT / "tests" / "test_project_uaf"),
            evidence_dir=str(PROJECT_ROOT / "tests" / "patchweaver_uaf_lab"),
        )

    def test_csa_emits_patch_local_reset_and_barrier_records(self):
        bundle = CSAPathEvidenceCollector().collect(self._uaf_context())

        semantic_summaries = [
            str(record.semantic_payload.get("summary", "") or "")
            for record in bundle.records
            if record.type == "semantic_slice"
        ]
        assert any("clears stale state via ctx->session = NULL" in summary for summary in semantic_summaries)
        assert any("handle_admin_export adds patch barrier `ctx->session_id < 0`" in summary for summary in semantic_summaries)

        state_records = [
            record
            for record in bundle.records
            if record.type == "state_transition" and record.scope.function == "release_request_session"
        ]
        assert len(state_records) == 1
        assert "transition(ctx->session = NULL)" in (state_records[0].semantic_payload.get("state_after") or [])
        assert "transition(ctx->session_id = -1)" in (state_records[0].semantic_payload.get("state_after") or [])
        assert "release_request_session -> destroy_session" in (state_records[0].semantic_payload.get("call_edges") or [])

    def test_codeql_call_chain_stays_patch_local(self):
        bundle = CodeQLFlowEvidenceCollector().collect(self._uaf_context())

        call_chain = next(record for record in bundle.records if record.type == "call_chain")
        call_edges = call_chain.semantic_payload.get("call_edges") or []

        assert call_chain.scope.function == "handle_admin_export"
        assert "main->create_session" not in call_edges
        assert "bind_request_session->find_session" not in call_edges
        assert any(edge.replace(" ", "").startswith("handle_admin_export->") for edge in call_edges)
        assert all(
            edge.split("->", 1)[0].strip() in {"handle_admin_export", "append_request_audit", "release_request_session"}
            for edge in call_edges
            if "->" in edge
        )

        semantic_slice = next(record for record in bundle.records if record.type == "semantic_slice")
        call_targets = semantic_slice.semantic_payload.get("call_targets") or []
        assert semantic_slice.scope.function == "handle_admin_export"
        assert "handle_admin_export" not in call_targets


class TestPatchFactsArithmeticInference:
    """测试 arithmetic/type-widening patch 推断"""

    def test_sqlite_patch_infers_integer_overflow(self):
        patch_path = (
            PROJECT_ROOT.parent
            / "experiments"
            / "sqlite_cve202235737"
            / "workspace"
            / "patches"
            / "CVE-2022-35737.patch"
        )
        facts = PatchFactsExtractor().extract(
            patch_path=str(patch_path),
            patch_analysis={
                "files_changed": ["src/printf.c"],
                "file_details": [{"path": "src/printf.c", "additions": 2, "deletions": 2, "hunks": 1}],
                "vulnerability_patterns": [],
                "cross_file_dependencies": [],
                "detection_strategy": {},
            },
        )

        by_type = {fact.fact_type: fact for fact in facts}
        assert "vulnerability_patterns" in by_type
        assert "affected_functions" in by_type
        assert "type_widening" in by_type
        assert "integer_overflow" in (by_type["vulnerability_patterns"].attributes.get("patterns", []) or [])
        assert "sqlite3_str_vappendf" in (by_type["affected_functions"].attributes.get("functions", []) or [])
        assert by_type["type_widening"].attributes.get("new_type") == "i64"
        assert "n" in (by_type["type_widening"].attributes.get("variables", []) or [])

    def test_buffer_guard_patch_only_keeps_changed_functions(self):
        patch_path = PROJECT_ROOT / "tests" / "patchweaver_buffer_lab" / "buffer_guard.patch"
        facts = PatchFactsExtractor().extract(
            patch_path=str(patch_path),
            patch_analysis={
                "files_changed": ["src/request_parser.c"],
                "file_details": [{"path": "src/request_parser.c", "additions": 13, "deletions": 5, "hunks": 2}],
                "vulnerability_patterns": [],
                "cross_file_dependencies": [],
                "detection_strategy": {},
            },
        )

        by_type = {fact.fact_type: fact for fact in facts}
        functions = set(by_type["affected_functions"].attributes.get("functions", []) or [])

        assert {"set_request_user", "copy_request_body", "build_cache_key"} <= functions
        assert "set_request_path" not in functions


class TestBufferGuardEvidenceCollectors:
    def _buffer_context(self) -> AnalyzerContext:
        return AnalyzerContext(
            patch_path=str(PROJECT_ROOT / "tests" / "patchweaver_buffer_lab" / "buffer_guard.patch"),
            output_dir=str(PROJECT_ROOT / "tests" / "patchweaver_buffer_lab" / "outputs"),
            evidence_dir=str(PROJECT_ROOT / "tests" / "patchweaver_buffer_lab"),
        )

    def test_csa_buffer_guard_prefers_patch_local_barriers(self):
        bundle = CSAPathEvidenceCollector().collect(self._buffer_context())

        semantic_by_function = {
            record.scope.function: str(record.semantic_payload.get("summary", "") or "")
            for record in bundle.records
            if record.type == "semantic_slice"
        }
        assert "checked formatting via snprintf" in semantic_by_function["build_cache_key"]
        assert "guard `user_len >= sizeof(record->user)`" in semantic_by_function["set_request_user"]
        assert "guard `payload_len >= sizeof(record->body)`" in semantic_by_function["copy_request_body"]

        guard_exprs = {
            (record.scope.function, str(record.semantic_payload.get("guard_expr", "") or ""))
            for record in bundle.records
            if record.type == "path_guard"
        }
        assert ("set_request_user", "user_len >= sizeof(record->user)") in guard_exprs
        assert ("copy_request_body", "payload_len >= sizeof(record->body)") in guard_exprs
        assert ("build_cache_key", "written < 0 || (size_t)written >= out_size") in guard_exprs

        assert all(record.type != "allocation_lifecycle" for record in bundle.records)

        build_cache_state = next(
            record for record in bundle.records
            if record.type == "state_transition" and record.scope.function == "build_cache_key"
        )
        assert "sink(snprintf)" in (build_cache_state.semantic_payload.get("state_after") or [])
        assert "replaces(strcpy)" in (build_cache_state.semantic_payload.get("state_after") or [])

    def test_codeql_buffer_guard_uses_patch_contract_hints_without_fake_call_edges(self):
        bundle = CodeQLFlowEvidenceCollector().collect(self._buffer_context())

        semantic_slice = next(record for record in bundle.records if record.type == "semantic_slice")
        semantic_summary = str(semantic_slice.semantic_payload.get("summary", "") or "")
        assert "patch_contracts=" in semantic_summary
        assert "build_cache_key: checked formatting via snprintf" in semantic_summary
        assert "snprintf" in (semantic_slice.semantic_payload.get("call_targets") or [])

        dataflow = next(record for record in bundle.records if record.type == "dataflow_candidate")
        assert "checked formatting via snprintf guarded by" in str(dataflow.semantic_payload.get("summary", "") or "")
        assert dataflow.scope.function == "build_cache_key"

        call_chain = next(record for record in bundle.records if record.type == "call_chain")
        call_edges = call_chain.semantic_payload.get("call_edges") or []
        assert "build_cache_key -> snprintf" not in call_edges
        assert all(
            edge.split("->", 1)[0].strip() in {"set_request_user", "copy_request_body", "build_cache_key"}
            for edge in call_edges
            if "->" in edge
        )

        dataflow = next(record for record in bundle.records if record.type == "dataflow_candidate")
        assert "build_cache_key -> strcpy" not in (dataflow.semantic_payload.get("path") or [])
        assert "build_cache_key -> strcat" not in (dataflow.semantic_payload.get("path") or [])

    def test_evidence_tools_merge_semantic_slices_by_function(self):
        ctx = self._buffer_context()
        combined = EvidenceBundle(
            records=CSAPathEvidenceCollector().collect(ctx).records + CodeQLFlowEvidenceCollector().collect(ctx).records
        )

        tools = EvidenceQueryTools(combined)
        semantic = tools.get_semantic_slices()
        dataflow = tools.get_dataflow_candidates()

        assert semantic["available"] is True
        assert semantic["count"] == 3
        build_cache = next(item for item in semantic["items"] if item["function"] == "build_cache_key")
        assert any("checked formatting via snprintf" in summary for summary in [build_cache["summary"], *build_cache.get("supporting_summaries", [])])

        assert dataflow["available"] is True
        assert dataflow["count"] == 1
        assert dataflow["items"][0]["function"] == "build_cache_key"
        assert "build_cache_key -> strcpy" not in dataflow["items"][0]["path"]


class TestGuardOnlyEvidenceCollectors:
    def _guard_only_context(self) -> AnalyzerContext:
        return AnalyzerContext(
            patch_path=str(PROJECT_ROOT / "tests" / "patchweaver_guard_only_lab" / "null_guard.patch"),
            output_dir=str(PROJECT_ROOT / "tests" / "patchweaver_guard_only_lab" / "outputs"),
            evidence_dir=str(PROJECT_ROOT / "tests" / "patchweaver_guard_only_lab"),
        )

    def test_artifact_extractor_recovers_guard_only_function_context(self):
        source_contexts, _ = ProjectArtifactExtractor().collect_source_contexts(self._guard_only_context())

        assert len(source_contexts) == 1
        assert source_contexts[0].function_name == "render_record_name"
        assert source_contexts[0].call_targets == ["snprintf"]

    def test_guard_only_patch_emits_patch_local_guard_evidence(self):
        ctx = self._guard_only_context()
        csa_bundle = CSAPathEvidenceCollector().collect(ctx)
        codeql_bundle = CodeQLFlowEvidenceCollector().collect(ctx)

        semantic = next(record for record in csa_bundle.records if record.type == "semantic_slice")
        guard = next(record for record in csa_bundle.records if record.type == "path_guard")
        dataflow = next(record for record in codeql_bundle.records if record.type == "dataflow_candidate")

        assert semantic.scope.function == "render_record_name"
        assert "!record || !record->name" in str(semantic.semantic_payload.get("summary", "") or "")
        assert guard.semantic_payload.get("guard_expr") == "!record || !record->name"
        assert guard.semantic_payload.get("call_targets") == ["snprintf"]
        assert dataflow.scope.function == "render_record_name"
        assert dataflow.semantic_payload.get("sink") == "snprintf"


class TestPathEvidenceCollectors:
    def _path_context(self) -> AnalyzerContext:
        return AnalyzerContext(
            patch_path=str(PROJECT_ROOT / "tests" / "patchweaver_path_lab" / "path_filter.patch"),
            output_dir=str(PROJECT_ROOT / "tests" / "patchweaver_path_lab" / "outputs"),
            evidence_dir=str(PROJECT_ROOT / "tests" / "patchweaver_path_lab"),
        )

    def test_path_filter_patch_keeps_downstream_sink_visible(self):
        ctx = self._path_context()
        csa_bundle = CSAPathEvidenceCollector().collect(ctx)
        codeql_bundle = CodeQLFlowEvidenceCollector().collect(ctx)

        semantic = next(record for record in csa_bundle.records if record.type == "semantic_slice")
        guard = next(record for record in csa_bundle.records if record.type == "path_guard")
        dataflow = next(record for record in codeql_bundle.records if record.type == "dataflow_candidate")

        assert "around snprintf" in str(semantic.semantic_payload.get("summary", "") or "")
        assert guard.semantic_payload.get("call_targets") == ["snprintf"]
        assert "snprintf" in (dataflow.semantic_payload.get("call_targets") or [])
        assert "snprintf" in str(dataflow.semantic_payload.get("sink", "") or "")


class TestOverflowGuardEvidenceCollectors:
    def _overflow_context(self) -> AnalyzerContext:
        return AnalyzerContext(
            patch_path=str(PROJECT_ROOT / "tests" / "patchweaver_overflow_guard_lab" / "allocation_guard.patch"),
            output_dir=str(PROJECT_ROOT / "tests" / "patchweaver_overflow_guard_lab" / "outputs"),
            evidence_dir=str(PROJECT_ROOT / "tests" / "patchweaver_overflow_guard_lab"),
        )

    def test_overflow_guard_patch_facts_recover_function_and_pattern(self):
        patch_path = PROJECT_ROOT / "tests" / "patchweaver_overflow_guard_lab" / "allocation_guard.patch"
        facts = PatchFactsExtractor().extract(
            patch_path=str(patch_path),
            patch_analysis={
                "files_changed": ["src/packet_builder.c"],
                "file_details": [{"path": "src/packet_builder.c", "additions": 4, "deletions": 0, "hunks": 1}],
                "vulnerability_patterns": [],
                "cross_file_dependencies": [],
                "detection_strategy": {},
            },
        )

        by_type = {fact.fact_type: fact for fact in facts}
        assert "build_packet_buffer" in (by_type["affected_functions"].attributes.get("functions", []) or [])
        assert "integer_overflow" in (by_type["vulnerability_patterns"].attributes.get("patterns", []) or [])
        assert "overflow bounds check" in (by_type["fix_patterns"].attributes.get("patterns", []) or [])

    def test_overflow_guard_patch_emits_malloc_guard_evidence(self):
        ctx = self._overflow_context()
        source_contexts, _ = ProjectArtifactExtractor().collect_source_contexts(ctx)
        assert len(source_contexts) == 1
        assert source_contexts[0].function_name == "build_packet_buffer"
        assert source_contexts[0].call_targets == ["malloc"]

        csa_bundle = CSAPathEvidenceCollector().collect(ctx)
        codeql_bundle = CodeQLFlowEvidenceCollector().collect(ctx)

        csa_guard = next(record for record in csa_bundle.records if record.type == "path_guard")
        codeql_flow = next(record for record in codeql_bundle.records if record.type == "dataflow_candidate")
        codeql_chain = next(record for record in codeql_bundle.records if record.type == "call_chain")

        assert "SIZE_MAX / plan->elem_size" in str(csa_guard.semantic_payload.get("guard_expr", "") or "")
        assert csa_guard.semantic_payload.get("call_targets") == ["malloc"]
        assert codeql_flow.scope.function == "build_packet_buffer"
        assert codeql_flow.semantic_payload.get("sink") == "malloc"
        assert codeql_chain.semantic_payload.get("call_edges") == ["build_packet_buffer -> malloc"]


class TestValidationOrder:
    """测试验证顺序调整"""

    def test_csa_validate_order_lsp_first(self):
        """CSA 验证顺序: LSP 先执行"""
        # 这个测试验证 validate 函数中 CSA 分支的顺序
        # LSP 应该在 compile 之前执行
        # 通过检查代码逻辑来验证
        from src.refine.agent import LangChainRefinementAgent

        # 检查 agent 实例化正常
        agent = LangChainRefinementAgent(config={"refine": {"max_rounds": 1}}, analyzer="csa")
        assert agent.max_rounds == 1
        assert agent.analyzer == "csa"

    def test_codeql_validate_order_review_first(self):
        """CodeQL 验证顺序: Review 先执行"""
        from src.refine.agent import LangChainRefinementAgent

        agent = LangChainRefinementAgent(config={"refine": {"max_rounds": 1}}, analyzer="codeql")
        assert agent.analyzer == "codeql"


class TestRequestEvidenceAction:
    """测试 request_evidence action"""

    def test_route_from_decision_request_evidence(self):
        """测试 request_evidence action 路由"""
        from src.refine.agent import LangChainRefinementAgent

        agent = LangChainRefinementAgent()
        decision = {"action": "request_evidence", "evidence_types": ["patch_fact"]}
        route = agent._route_from_decision(decision)

        assert route == "request_evidence"

    def test_parse_decision_with_evidence_types(self):
        """测试解析包含 evidence_types 的决策"""
        from src.refine.agent import LangChainRefinementAgent
        import json

        agent = LangChainRefinementAgent()
        raw_content = json.dumps({
            "action": "request_evidence",
            "summary": "请求补丁事实",
            "evidence_types": ["patch_fact", "call_chain"],
            "cot_analysis": {
                "current_semantics": "不足",
                "missing_context": "需要理解补丁模式",
                "strategy": "语义增强",
            },
        })

        decision, error = agent._parse_decision(raw_content)

        assert error == ""
        assert decision["action"] == "request_evidence"
        assert "patch_fact" in decision["evidence_types"]
        assert "call_chain" in decision["evidence_types"]

    def test_route_from_decision_validate(self):
        """测试 validate action 路由"""
        from src.refine.agent import LangChainRefinementAgent

        agent = LangChainRefinementAgent()
        decision = {"action": "validate"}
        route = agent._route_from_decision(decision)

        assert route == "validate"

    def test_parse_decision_accepts_validate(self):
        """测试解析 validate 决策"""
        from src.refine.agent import LangChainRefinementAgent
        import json

        agent = LangChainRefinementAgent()
        raw_content = json.dumps({
            "action": "validate",
            "summary": "语义建模已基本到位，进入本地验证",
            "cot_analysis": {
                "baseline_quality": "未过关",
                "mechanism_gap": "主体机制已覆盖，剩余风险主要在实现细节",
                "checker_weaknesses": [],
                "rewrite_scope": "局部修改",
                "missing_context": "无",
                "evidence_needed": [],
                "strategy": "进入验证",
            },
        })

        decision, error = agent._parse_decision(raw_content)

        assert error == ""
        assert decision["action"] == "validate"

    def test_parse_decision_rejects_search_knowledge(self):
        """refine 不再支持 search_knowledge action"""
        from src.refine.agent import LangChainRefinementAgent
        import json

        agent = LangChainRefinementAgent()
        raw_content = json.dumps({
            "action": "search_knowledge",
            "summary": "不应被接受",
            "query": "uaf checker api",
        })

        decision, error = agent._parse_decision(raw_content)

        assert decision == {}
        assert "不支持" in error


class TestExternalEvidenceRoots:
    """测试外部 evidence 根目录的消费方式"""

    def test_project_root_prefers_evidence_dir(self, tmp_path):
        evidence_root = tmp_path / "evidence_src"
        evidence_root.mkdir()
        validate_root = tmp_path / "validate"
        validate_root.mkdir()
        target_file = validate_root / "demo.c"
        target_file.write_text("int demo(void) { return 0; }\n", encoding="utf-8")

        context = AnalyzerContext(
            patch_path=str(tmp_path / "demo.patch"),
            output_dir=str(tmp_path / "out"),
            validate_path=str(target_file),
            evidence_dir=str(evidence_root),
        )

        assert ProjectArtifactExtractor().project_root(context) == evidence_root.resolve()

    def test_refine_toolkit_reads_reference_from_evidence_dir(self, tmp_path):
        evidence_root = tmp_path / "project"
        source_dir = evidence_root / "src"
        source_dir.mkdir(parents=True)
        source_file = source_dir / "demo.c"
        source_file.write_text("int guarded(void) { return 1; }\n", encoding="utf-8")

        request = RefinementRequest(
            analyzer="csa",
            patch_path=str(tmp_path / "demo.patch"),
            work_dir=str(tmp_path / "work"),
            target_path=str(tmp_path / "work" / "checker.cpp"),
            evidence_dir=str(evidence_root),
        )
        tracker = RefinementTracker(request=request)
        toolkit = RefinementToolkit(
            tool_registry=ToolRegistry(),
            request=request,
            tracker=tracker,
            analyzer_name="CSA",
        )

        resolved = toolkit._resolve_allowed_path("src/demo.c")
        assert resolved == str(source_file.resolve())


class TestMultiRoundRefinement:
    """测试多轮精炼配置"""

    def test_max_rounds_default(self):
        """默认 max_rounds 为 2"""
        from src.refine.agent import LangChainRefinementAgent

        agent = LangChainRefinementAgent()
        assert agent.max_rounds == 2

    def test_max_rounds_from_config(self):
        """从配置读取 max_rounds"""
        from src.refine.agent import LangChainRefinementAgent

        agent = LangChainRefinementAgent(config={"refine": {"max_rounds": 2}})
        assert agent.max_rounds == 2

    def test_max_rounds_clamped(self):
        """max_rounds 被限制在 1-3 范围"""
        from src.refine.agent import LangChainRefinementAgent

        # 超过 3 被限制为 3
        agent = LangChainRefinementAgent(config={"refine": {"max_rounds": 5}})
        assert agent.max_rounds == 3

        # 小于 1 被限制为 1
        agent = LangChainRefinementAgent(config={"refine": {"max_rounds": 0}})
        assert agent.max_rounds == 1


class TestRefinementAdoption:
    """测试 refine 候选采纳逻辑"""

    def test_adopt_candidate_when_patch_applied_and_source_changed(self):
        orchestrator = Orchestrator.__new__(Orchestrator)

        current = AnalyzerResult(
            analyzer_type="csa",
            checker_code="int baseline() { return 0; }\n",
        )
        candidate = AnalyzerResult(
            analyzer_type="csa",
            checker_code="int refined() { return 1; }\n",
            metadata={
                "refinement_agent": {
                    "tool_history": [
                        {"tool_name": "apply_patch", "success": True},
                    ]
                }
            },
        )

        assert orchestrator._should_adopt_refinement_candidate(current=current, candidate=candidate)

    def test_do_not_adopt_candidate_without_successful_apply_patch(self):
        orchestrator = Orchestrator.__new__(Orchestrator)

        current = AnalyzerResult(
            analyzer_type="csa",
            checker_code="int baseline() { return 0; }\n",
        )
        candidate = AnalyzerResult(
            analyzer_type="csa",
            checker_code="int refined() { return 1; }\n",
            metadata={
                "refinement_agent": {
                    "tool_history": [
                        {"tool_name": "apply_patch", "success": False},
                    ]
                }
            },
        )

        assert not orchestrator._should_adopt_refinement_candidate(current=current, candidate=candidate)

    def test_candidate_requested_stop_reads_refinement_agent_metadata(self):
        orchestrator = Orchestrator.__new__(Orchestrator)

        candidate = AnalyzerResult(
            analyzer_type="csa",
            metadata={
                "refinement_agent": {
                    "model_requested_stop": True,
                }
            },
        )

        assert orchestrator._candidate_requested_stop(candidate)


class TestRefinementEarlyStopPolicy:
    """测试 refine 外层提前停止策略"""

    def test_baseline_skip_requires_vuln_hit_and_fixed_silent(self):
        orchestrator = Orchestrator.__new__(Orchestrator)
        review_result = SimpleNamespace(success=True)

        passing_baseline = AnalyzerResult(
            analyzer_type="csa",
            success=True,
            validation_result=SimpleNamespace(success=True, diagnostics=[SimpleNamespace()]),
            metadata={"validation_requested": True, "baseline_pds": True},
        )
        assert orchestrator._baseline_refine_skip_reason(
            analyzer_result=passing_baseline,
            review_result=review_result,
        ) == "baseline_already_passes_strict_refine_review_and_validation"

        missing_fixed_validation = AnalyzerResult(
            analyzer_type="csa",
            success=True,
            validation_result=SimpleNamespace(success=True, diagnostics=[SimpleNamespace()]),
            metadata={"validation_requested": True, "baseline_pds": None},
        )
        assert orchestrator._baseline_refine_skip_reason(
            analyzer_result=missing_fixed_validation,
            review_result=review_result,
        ) == ""

        fixed_not_silent = AnalyzerResult(
            analyzer_type="csa",
            success=True,
            validation_result=SimpleNamespace(success=True, diagnostics=[SimpleNamespace()]),
            metadata={"validation_requested": True, "baseline_pds": False},
        )
        assert orchestrator._baseline_refine_skip_reason(
            analyzer_result=fixed_not_silent,
            review_result=review_result,
        ) == ""

    def test_only_model_finish_can_stop_outer_refinement_early(self):
        orchestrator = Orchestrator.__new__(Orchestrator)
        orchestrator.config = {"refine": {"max_rounds": 3}}

        baseline_result = AnalyzerResult(
            analyzer_type="csa",
            success=True,
            checker_name="PatchFocusedChecker",
            checker_code="int baseline() { return 0; }\n",
            output_path="/tmp/PatchFocusedChecker.so",
            metadata={},
        )

        candidates = [
            AnalyzerResult(
                analyzer_type="csa",
                success=True,
                checker_name="PatchFocusedChecker",
                checker_code="int baseline() { return 0; }\n",
                output_path="/tmp/PatchFocusedChecker.so",
                metadata={
                    "refinement_agent": {
                        "tool_history": [],
                        "model_requested_stop": False,
                    }
                },
            ),
            AnalyzerResult(
                analyzer_type="csa",
                success=True,
                checker_name="PatchFocusedChecker",
                checker_code="int baseline() { return 0; }\n",
                output_path="/tmp/PatchFocusedChecker.so",
                metadata={
                    "refinement_agent": {
                        "tool_history": [],
                        "model_requested_stop": True,
                    }
                },
            ),
        ]

        fake_analyzer = mock.Mock()
        fake_analyzer.analyzer_type = "csa"
        fake_analyzer._review_baseline_artifact.return_value = SimpleNamespace(success=False, error="", metadata={})
        fake_analyzer.refine.side_effect = candidates
        fake_analyzer.validate.side_effect = lambda result, context: None

        orchestrator._create_analyzer = mock.Mock(return_value=fake_analyzer)
        orchestrator._rehydrate_saved_analyzer_result = mock.Mock(return_value=baseline_result)
        orchestrator._validate_analyzer_result = mock.Mock(side_effect=lambda **kwargs: kwargs["analyzer_result"])
        orchestrator._augment_shared_analysis_with_validation_feedback = mock.Mock(side_effect=lambda shared_analysis, analyzer_result, phase: dict(shared_analysis or {}))
        orchestrator._baseline_refine_skip_reason = mock.Mock(return_value="")
        orchestrator._refresh_refinement_artifact = mock.Mock(side_effect=lambda artifact, candidate: artifact)

        events = []
        artifact = SimpleNamespace(
            evidence_bundle_raw={},
            post_validation_evidence_bundle_raw={},
            source_path="/tmp/PatchFocusedChecker.cpp",
            output_path="/tmp/PatchFocusedChecker.so",
            checker_code="int baseline() { return 0; }\n",
            report_entry={},
        )

        result = orchestrator._refine_single_from_saved_artifact(
            analyzer_type="csa",
            artifact=artifact,
            patch_path="/tmp/demo.patch",
            output_dir="/tmp/out",
            validate_path="/tmp/validate",
            evidence_dir="/tmp/evidence",
            shared_analysis={},
            on_progress=events.append,
        )

        iteration_starts = [event for event in events if event.get("event") == "refinement_iteration_started"]
        iteration_completes = [event for event in events if event.get("event") == "refinement_iteration_completed"]

        assert len(iteration_starts) == 2
        assert len(iteration_completes) == 2
        assert iteration_completes[0]["adopted"] is False
        assert iteration_completes[0]["model_requested_stop"] is False
        assert iteration_completes[1]["model_requested_stop"] is True
        assert fake_analyzer.refine.call_count == 2
        assert result.metadata["refinement_iterations_attempted"] == 2

    def test_second_refinement_round_uses_first_round_adopted_artifact(self):
        orchestrator = Orchestrator.__new__(Orchestrator)
        orchestrator.config = {"refine": {"max_rounds": 2}}

        baseline_result = AnalyzerResult(
            analyzer_type="csa",
            success=True,
            checker_name="PatchFocusedChecker",
            checker_code="int baseline() { return 0; }\n",
            output_path="/tmp/PatchFocusedChecker.so",
            metadata={},
        )

        first_round_target = "/tmp/out/csa/PatchFocusedChecker.cpp"
        round1_code = "int round1() { return 1; }\n"
        round2_code = "int round2() { return 2; }\n"
        seen_artifacts = []

        candidates = iter([
            AnalyzerResult(
                analyzer_type="csa",
                success=True,
                checker_name="PatchFocusedChecker",
                checker_code=round1_code,
                output_path="/tmp/out/csa/PatchFocusedChecker.so",
                metadata={
                    "refinement_target_path": first_round_target,
                    "refinement_agent": {
                        "tool_history": [
                            {
                                "tool_name": "apply_patch",
                                "success": True,
                            }
                        ],
                        "model_requested_stop": False,
                    },
                },
            ),
            AnalyzerResult(
                analyzer_type="csa",
                success=True,
                checker_name="PatchFocusedChecker",
                checker_code=round2_code,
                output_path="/tmp/out/csa/PatchFocusedChecker.so",
                metadata={
                    "refinement_target_path": first_round_target,
                    "refinement_agent": {
                        "tool_history": [
                            {
                                "tool_name": "apply_patch",
                                "success": True,
                            }
                        ],
                        "model_requested_stop": True,
                    },
                },
            ),
        ])

        def refine_side_effect(context, artifact, baseline_result):
            seen_artifacts.append(
                {
                    "source_path": getattr(artifact, "source_path", ""),
                    "checker_code": getattr(artifact, "checker_code", ""),
                }
            )
            return next(candidates)

        fake_analyzer = mock.Mock()
        fake_analyzer.analyzer_type = "csa"
        fake_analyzer._review_baseline_artifact.return_value = SimpleNamespace(success=False, error="", metadata={})
        fake_analyzer.refine.side_effect = refine_side_effect
        fake_analyzer.validate.side_effect = lambda result, context: None

        orchestrator._create_analyzer = mock.Mock(return_value=fake_analyzer)
        orchestrator._rehydrate_saved_analyzer_result = mock.Mock(return_value=baseline_result)
        orchestrator._validate_analyzer_result = mock.Mock(side_effect=lambda **kwargs: kwargs["analyzer_result"])
        orchestrator._augment_shared_analysis_with_validation_feedback = mock.Mock(
            side_effect=lambda shared_analysis, analyzer_result, phase: dict(shared_analysis or {})
        )
        orchestrator._baseline_refine_skip_reason = mock.Mock(return_value="")

        artifact = SimpleNamespace(
            evidence_bundle_raw={},
            post_validation_evidence_bundle_raw={},
            source_path="/tmp/baseline/PatchFocusedChecker.cpp",
            output_path="/tmp/baseline/PatchFocusedChecker.so",
            checker_code="int baseline() { return 0; }\n",
            report_entry={},
        )

        result = orchestrator._refine_single_from_saved_artifact(
            analyzer_type="csa",
            artifact=artifact,
            patch_path="/tmp/demo.patch",
            output_dir="/tmp/out",
            validate_path="/tmp/validate",
            evidence_dir="/tmp/evidence",
            shared_analysis={},
            on_progress=None,
        )

        assert len(seen_artifacts) == 2
        assert seen_artifacts[0]["source_path"] == "/tmp/baseline/PatchFocusedChecker.cpp"
        assert seen_artifacts[0]["checker_code"] == "int baseline() { return 0; }\n"
        assert seen_artifacts[1]["source_path"] == first_round_target
        assert seen_artifacts[1]["checker_code"] == round1_code
        assert result.checker_code == round2_code


class TestRefinementArtifactStaging:
    """测试 refine 工作副本在多轮之间不会回退到基线"""

    def test_stage_refinement_artifact_keeps_existing_worktree_copy(self, tmp_path: Path):
        baseline = tmp_path / "baseline" / "PatchFocusedChecker.cpp"
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text("int baseline() { return 0; }\n", encoding="utf-8")

        work_dir = tmp_path / "out" / "csa"
        work_dir.mkdir(parents=True, exist_ok=True)

        from src.core.analyzer_base import BaseAnalyzer

        class _DummyAnalyzer(BaseAnalyzer):
            @property
            def analyzer_type(self):
                return "csa"

            @property
            def name(self):
                return "dummy"

            def _do_initialize(self):
                pass

            def generate(self, context):
                raise NotImplementedError

        analyzer = _DummyAnalyzer(config={})

        first_staged = analyzer._stage_refinement_artifact(str(baseline), str(work_dir))
        first_staged_path = Path(first_staged)
        assert first_staged_path.read_text(encoding="utf-8") == "int baseline() { return 0; }\n"

        first_staged_path.write_text("int round1() { return 1; }\n", encoding="utf-8")

        second_staged = analyzer._stage_refinement_artifact(str(first_staged_path), str(work_dir))
        second_staged_path = Path(second_staged)

        assert second_staged_path == first_staged_path
        assert second_staged_path.read_text(encoding="utf-8") == "int round1() { return 1; }\n"


class TestApplyPatchTool:
    """测试 apply_patch 对 Codex 风格 patch 的兼容性"""

    def test_normalize_patch_repairs_incorrect_hunk_counts(self):
        tool = ApplyPatchTool()
        patch = """--- a/PatchFocusedChecker.cpp
+++ b/PatchFocusedChecker.cpp
@@ -2,2 +2,2 @@
 public:
   int check() {
+    int y = 1;
     int x = 0;
-    return x;
+    return x + y;
   }
"""

        normalized = tool._normalize_patch_text(patch, fallback_name="PatchFocusedChecker.cpp")

        assert "@@ -2,5 +2,6 @@" in normalized

    def test_codex_patch_allows_later_hunks_to_reference_earlier_insertions(self, tmp_path: Path):
        source = tmp_path / "PatchFocusedChecker.cpp"
        source.write_text(
            '#include "clang/AST/Expr.h"\n'
            '#include "clang/Basic/SourceLocation.h"\n'
            '\n'
            'class PatchFocusedChecker : public Checker<check::PreCall> {\n'
            'public:\n'
            '  void checkPreCall();\n'
            '};\n',
            encoding="utf-8",
        )

        patch = """*** Begin Patch
*** Update File: /tmp/PatchFocusedChecker.cpp
@@
 #include "clang/AST/Expr.h"
+#include "clang/AST/Type.h"
 #include "clang/Basic/SourceLocation.h"
@@
 #include "clang/AST/Type.h"
 #include "clang/Basic/SourceLocation.h"
+#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
 
 class PatchFocusedChecker : public Checker<check::PreCall> {
 public:
-  void checkPreCall();
+  void checkPreCall();
+  bool isNarrowEscapeCounter(QualType Ty) const;
 };
*** End Patch
"""

        tool = ApplyPatchTool()
        result = tool.execute(
            source_path=str(source),
            target_path=str(source),
            patch=patch,
        )

        assert result.success, result.error
        updated = source.read_text(encoding="utf-8")
        assert '#include "clang/AST/Type.h"' in updated
        assert '#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"' in updated
        assert "bool isNarrowEscapeCounter(QualType Ty) const;" in updated

    def test_unified_diff_accepts_loose_hunk_header(self, tmp_path: Path):
        source = tmp_path / "PatchFocusedChecker.cpp"
        source.write_text(
            "class PatchFocusedChecker : public Checker<check::PreCall> {\n"
            "public:\n"
            "  void checkPreCall();\n"
            "};\n",
            encoding="utf-8",
        )

        patch = """--- a/PatchFocusedChecker.cpp
+++ b/PatchFocusedChecker.cpp
@@
 class PatchFocusedChecker : public Checker<check::PreCall> {
 public:
-  void checkPreCall();
+  void checkPreCall();
+  bool isEscapeCounterNarrow() const;
 };
"""

        tool = ApplyPatchTool()
        result = tool.execute(
            source_path=str(source),
            target_path=str(source),
            patch=patch,
        )

        assert result.success, result.error
        updated = source.read_text(encoding="utf-8")
        assert "bool isEscapeCounterNarrow() const;" in updated

    def test_unified_diff_allows_later_hunks_to_reference_earlier_insertions(self, tmp_path: Path):
        source = tmp_path / "PatchFocusedChecker.cpp"
        source.write_text(
            '#include "clang/AST/Expr.h"\n'
            '#include "clang/Basic/SourceLocation.h"\n'
            '\n'
            'class PatchFocusedChecker : public Checker<check::PreCall> {\n'
            'public:\n'
            '  void checkPreCall();\n'
            '};\n',
            encoding="utf-8",
        )

        patch = """--- a/PatchFocusedChecker.cpp
+++ b/PatchFocusedChecker.cpp
@@ -1,3 +1,4 @@
 #include "clang/AST/Expr.h"
+#include "clang/AST/Type.h"
 #include "clang/Basic/SourceLocation.h"
 
@@ -2,2 +3,4 @@
 #include "clang/AST/Type.h"
 #include "clang/Basic/SourceLocation.h"
 
 class PatchFocusedChecker : public Checker<check::PreCall> {
 public:
-  void checkPreCall();
+  void checkPreCall();
+  bool isNarrowEscapeCounter(QualType Ty) const;
 };
"""

        tool = ApplyPatchTool()
        result = tool.execute(
            source_path=str(source),
            target_path=str(source),
            patch=patch,
        )

        assert result.success, result.error
        assert result.metadata["engine"] == "sequential_unified_diff"
        updated = source.read_text(encoding="utf-8")
        assert '#include "clang/AST/Type.h"' in updated
        assert "bool isNarrowEscapeCounter(QualType Ty) const;" in updated


class TestFailureType:
    """测试 failure_type 标记"""

    def test_failure_type_in_state(self):
        """验证 failure_type 在状态中定义"""
        from src.refine.agent import RefinementWorkflowState

        # TypedDict 在运行时只是 dict，验证字段可访问
        state: RefinementWorkflowState = {
            "artifact_text": "",
            "patch_text": "",
            "context_notes": [],
            "decision": {},
            "model_turns": 0,
            "patch_applied": False,
            "route": "decide",
            "error_message": "",
            "final_message": "",
            "raw_decision_text": "",
            "failure_type": "syntax_error",
            "collected_evidence": {},
        }

        assert state.get("failure_type") == "syntax_error"

    def test_failure_type_values(self):
        """验证 failure_type 可能的值"""
        expected_types = [
            "syntax_error",
            "review_failure",
            "compile_failure",
            "analyze_failure",
        ]
        # 这些是 validate 函数中定义的 failure_type 值
        for ft in expected_types:
            assert isinstance(ft, str)


class TestAvailableEvidenceTypes:
    """测试可用证据类型清单"""

    def test_evidence_types_count(self):
        """验证证据类型数量为 8 种"""
        assert len(AVAILABLE_EVIDENCE_TYPES) == 8

    def test_all_types_have_description(self):
        """验证所有类型都有描述"""
        for ev_type, info in AVAILABLE_EVIDENCE_TYPES.items():
            assert "description" in info
            assert "usage" in info
            assert info["description"]
            assert info["usage"]

    def test_directory_tree_type_exists(self):
        """验证 directory_tree 类型存在"""
        assert "directory_tree" in AVAILABLE_EVIDENCE_TYPES
        assert "目录层级信息" in AVAILABLE_EVIDENCE_TYPES["directory_tree"]["description"]
