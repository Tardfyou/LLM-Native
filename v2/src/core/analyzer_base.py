"""
分析器抽象基类

提供统一的分析器接口，支持:
- 标准化的生成流程
- 进度回调机制
- 结果数据结构
- 并行执行支持
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Callable, List, Union
from pathlib import Path
from enum import Enum
import os
import re
import shutil
import time


class AnalyzerType(Enum):
    """分析器类型"""
    CSA = "csa"
    CODEQL = "codeql"


AnalyzerId = Union["AnalyzerType", str]


def normalize_analyzer_id(analyzer_type: AnalyzerId) -> str:
    """将分析器类型统一转换为字符串 ID。"""
    if isinstance(analyzer_type, AnalyzerType):
        return analyzer_type.value
    return str(analyzer_type or "").strip().lower()


@dataclass(frozen=True)
class AnalyzerDescriptor:
    """分析器描述信息。"""

    id: str
    name: str
    description: str
    best_for: List[str] = field(default_factory=list)
    evidence_types: List[str] = field(default_factory=list)
    detector_artifacts: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    validation_modes: List[str] = field(default_factory=list)


@dataclass
class AnalyzerContext:
    """分析器运行上下文"""
    patch_path: str
    output_dir: str
    validate_path: Optional[str] = None
    shared_analysis: Dict[str, Any] = field(default_factory=dict)
    work_dir: str = ""

    def __post_init__(self):
        if not self.work_dir:
            self.work_dir = self.output_dir


@dataclass
class AnalyzerResult:
    """分析器执行结果"""
    analyzer_type: AnalyzerId
    success: bool = False
    checker_name: str = ""
    checker_code: str = ""
    output_path: str = ""
    iterations: int = 0
    compile_attempts: int = 0
    error_message: str = ""
    validation_result: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "analyzer_type": normalize_analyzer_id(self.analyzer_type),
            "success": self.success,
            "checker_name": self.checker_name,
            "output_path": self.output_path,
            "iterations": self.iterations,
            "compile_attempts": self.compile_attempts,
            "error_message": self.error_message,
            "execution_time": self.execution_time,
            "metadata": self.metadata,
        }


class BaseAnalyzer(ABC):
    """
    分析器抽象基类

    所有分析器（CSA、CodeQL）都应继承此类并实现抽象方法。
    提供统一的接口以便编排器管理和并行执行。
    """

    def __init__(
        self,
        config: Dict[str, Any],
        llm_client=None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        suppress_output: bool = False
    ):
        """
        初始化分析器

        Args:
            config: 配置字典
            llm_client: LLM 客户端实例（可选，延迟初始化）
            progress_callback: 进度回调函数
            suppress_output: 是否抑制智能体直接输出（并行模式使用）
        """
        self.config = config
        self._llm_client = llm_client
        self.progress_callback = progress_callback
        self._suppress_output = suppress_output

        # 内部状态
        self._agent = None
        self._tool_registry = None
        self._initialized = False

    @property
    @abstractmethod
    def analyzer_type(self) -> AnalyzerId:
        """分析器类型"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """分析器显示名称"""
        pass

    @property
    def llm_client(self):
        """LLM 客户端（延迟初始化）"""
        if self._llm_client is None:
            from ..llm import get_llm_client
            self._llm_client = get_llm_client(self.config.get("llm", {}))
        return self._llm_client

    @abstractmethod
    def _do_initialize(self):
        """
        执行具体的初始化逻辑

        子类应在此方法中初始化智能体和工具注册中心
        """
        pass

    def _ensure_initialized(self):
        """确保分析器已初始化"""
        if self._initialized:
            return
        self._do_initialize()
        self._initialized = True

    @abstractmethod
    def generate(self, context: AnalyzerContext) -> AnalyzerResult:
        """
        生成检测器

        Args:
            context: 分析器运行上下文

        Returns:
            AnalyzerResult 生成结果
        """
        pass

    def validate(
        self,
        result: AnalyzerResult,
        context: AnalyzerContext
    ) -> Any:
        """
        验证检测器

        Args:
            result: 生成结果
            context: 运行上下文

        Returns:
            验证结果
        """
        # 默认实现：不进行验证
        return None

    def validate_detector(
        self,
        result: AnalyzerResult,
        context: AnalyzerContext,
    ) -> Any:
        """PATCHWEAVER-facing validation hook."""
        return self.validate(result, context)

    def run_full_pipeline(
        self,
        context: AnalyzerContext,
        skip_validation: bool = False
    ) -> AnalyzerResult:
        """
        运行完整流程：生成 -> 验证

        Args:
            context: 分析器运行上下文
            skip_validation: 是否跳过验证

        Returns:
            AnalyzerResult
        """
        start_time = time.time()
        self._emit_progress("pipeline_started")

        try:
            # 生成阶段
            self._emit_progress("generation_started")
            result = self.generate(context)
            self._emit_progress(
                "generation_completed",
                success=result.success,
                iterations=result.iterations
            )

            # 验证阶段（仅在生成成功且提供验证路径时）
            if result.success and context.validate_path and not skip_validation:
                self._emit_progress("validation_started")
                result.validation_result = self.validate(result, context)
                validation_success = getattr(
                    result.validation_result, "success", False
                )
                self._emit_progress(
                    "validation_completed",
                    success=validation_success
                )

            result.execution_time = time.time() - start_time
            self._emit_progress(
                "pipeline_completed",
                success=result.success,
                execution_time=result.execution_time
            )

            return result

        except Exception as e:
            result = AnalyzerResult(
                analyzer_type=self.analyzer_type,
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time
            )
            self._emit_progress("pipeline_failed", error=str(e))
            return result

    def _emit_progress(self, event: str, **kwargs):
        """
        发送进度事件

        Args:
            event: 事件类型
            **kwargs: 事件数据
        """
        if self.progress_callback:
            data = {
                "analyzer": normalize_analyzer_id(self.analyzer_type),
                "analyzer_name": self.name,
                "event": event,
                "timestamp": time.time(),
                **kwargs
            }
            try:
                self.progress_callback(data)
            except Exception:
                # 回调失败不应影响主流程
                pass

    def _create_work_dir(self, base_dir: str) -> str:
        """
        创建独立工作目录

        Args:
            base_dir: 基础输出目录

        Returns:
            工作目录路径
        """
        import os
        if not base_dir:
            base_dir = "."

        base_path = Path(base_dir)
        # 若输出目录已是 analyzer 子目录，避免重复嵌套
        analyzer_id = normalize_analyzer_id(self.analyzer_type)
        if base_path.name == analyzer_id:
            work_dir = str(base_path)
        else:
            work_dir = os.path.join(base_dir, analyzer_id)

        os.makedirs(work_dir, exist_ok=True)
        return work_dir

    def _build_extra_context(
        self,
        shared_analysis: Dict[str, Any]
    ) -> str:
        """
        构建额外上下文字符串

        Args:
            shared_analysis: 共享补丁分析结果

        Returns:
            格式化的上下文字符串
        """
        if not shared_analysis:
            return ""

        lines = ["## 共享补丁分析结果（仅供交叉检查，不代替本分析器自己的 `analyze_patch` 推导）"]

        # 漏洞模式
        patterns = shared_analysis.get("vulnerability_patterns", [])
        if patterns:
            pattern_strs = []
            for item in patterns[:5]:
                if isinstance(item, dict):
                    pattern_strs.append(item.get("type", str(item)))
                else:
                    pattern_strs.append(str(item))
            if pattern_strs:
                lines.append(f"- 漏洞模式: {', '.join(pattern_strs)}")

        # 建议名称
        checker_name = shared_analysis.get("checker_name_suggestion")
        if checker_name:
            lines.append(f"- 建议名称: {checker_name}")

        # 检测策略
        strategy = shared_analysis.get("detection_strategy")
        if strategy:
            import json
            if isinstance(strategy, str):
                lines.append(f"- 检测策略: {strategy}")
            else:
                lines.append(f"- 检测策略: {json.dumps(strategy, ensure_ascii=False)}")

        # 关键函数
        key_funcs = shared_analysis.get("key_functions", [])
        if key_funcs:
            lines.append(f"- 关键函数: {', '.join(map(str, key_funcs[:8]))}")

        # 影响函数
        affected_funcs = shared_analysis.get("affected_functions", [])
        if affected_funcs:
            lines.append(f"- 影响函数: {', '.join(map(str, affected_funcs[:8]))}")

        file_details = shared_analysis.get("file_details", []) or []
        if file_details:
            focus_files = [
                str(item.get("path", "")).strip()
                for item in file_details[:6]
                if isinstance(item, dict) and str(item.get("path", "")).strip()
            ]
            if focus_files:
                lines.append(f"- 补丁触及文件: {', '.join(focus_files)}")

        patchweaver = shared_analysis.get("patchweaver", {})
        if patchweaver:
            lines.append("")
            lines.append("## PATCHWEAVER 计划")

            summary = patchweaver.get("summary")
            if summary:
                lines.append(f"- 机制摘要: {summary}")

            evidence_plan = patchweaver.get("evidence_plan", {}) or {}
            recommended = evidence_plan.get("recommended_analyzers", []) or []
            if recommended:
                lines.append(f"- 推荐分析器: {', '.join(map(str, recommended[:4]))}")
            if evidence_plan.get("uncertainty_budget"):
                lines.append(f"- 不确定性预算: {evidence_plan.get('uncertainty_budget')}")
            escalation_triggers = evidence_plan.get("escalation_triggers", []) or []
            if escalation_triggers:
                lines.append(f"- 升级触发器: {', '.join(map(str, escalation_triggers[:5]))}")

            requirements = evidence_plan.get("requirements", []) or []
            if requirements:
                planned_types = [item.get("evidence_type", "") for item in requirements[:6] if item.get("evidence_type")]
                if planned_types:
                    lines.append(f"- 计划证据: {', '.join(planned_types)}")

                current_analyzer = normalize_analyzer_id(self.analyzer_type)
                current_focus = [
                    item.get("evidence_type", "")
                    for item in requirements
                    if current_analyzer in (item.get("preferred_analyzers", []) or [])
                ]
                if current_focus:
                    lines.append(f"- 当前分析器重点证据: {', '.join(current_focus[:5])}")

            graph = patchweaver.get("mechanism_graph", {}) or {}
            primary_patterns = graph.get("primary_patterns", []) or []
            if primary_patterns:
                lines.append(f"- VMG 模式: {', '.join(map(str, primary_patterns[:4]))}")

            patch_facts = patchweaver.get("patch_facts", []) or []
            for fact in patch_facts:
                if not isinstance(fact, dict):
                    continue
                fact_type = str(fact.get("fact_type", "")).strip()
                attributes = fact.get("attributes", {}) or {}
                if fact_type == "fix_patterns":
                    patterns = [str(item).strip() for item in (attributes.get("patterns", []) or []) if str(item).strip()]
                    if patterns:
                        lines.append(f"- 修复模式: {', '.join(patterns[:6])}")
                elif fact_type == "added_guards":
                    guards = [str(item).strip() for item in (attributes.get("guards", []) or []) if str(item).strip()]
                    if guards:
                        lines.append(f"- 补丁新增 Guard: {', '.join(guards[:4])}")
                elif fact_type == "removed_risky_operations":
                    operations = [str(item).strip() for item in (attributes.get("operations", []) or []) if str(item).strip()]
                    if operations:
                        lines.append(f"- 补丁移除风险操作: {', '.join(operations[:4])}")
                elif fact_type == "added_api_calls":
                    apis = [str(item).strip() for item in (attributes.get("apis", []) or []) if str(item).strip()]
                    if apis:
                        lines.append(f"- 补丁新增 API: {', '.join(apis[:8])}")
                elif fact_type == "patch_intent":
                    summary = str(attributes.get("summary", "") or "").strip()
                    if summary:
                        lines.append(f"- 补丁意图: {summary}")
                elif fact_type == "external_references":
                    refs: List[str] = []
                    refs.extend([str(item).strip() for item in (attributes.get("cves", []) or []) if str(item).strip()])
                    refs.extend([str(item).strip() for item in (attributes.get("cwes", []) or []) if str(item).strip()])
                    refs.extend([str(item).strip() for item in (attributes.get("issues", []) or []) if str(item).strip()])
                    if refs:
                        lines.append(f"- 外部参考: {', '.join(refs[:6])}")

            bundle = patchweaver.get("evidence_bundle", {}) or {}
            missing = [str(item).strip() for item in (bundle.get("missing_evidence", []) or []) if str(item).strip()]
            if missing:
                lines.append(f"- 当前缺失证据: {', '.join(missing[:6])}")

            feedback_bundle = patchweaver.get("validation_feedback", {}) or {}
            failure_modes: List[str] = []
            for item in (feedback_bundle.get("records", []) or []):
                if not isinstance(item, dict):
                    continue
                payload = item.get("semantic_payload", {}) or {}
                mode = str(payload.get("failure_mode", "") or "").strip()
                if mode and mode not in failure_modes:
                    failure_modes.append(mode)
            if failure_modes:
                lines.append(f"- 最近失败模式: {', '.join(failure_modes[:4])}")

            evidence_escalation = patchweaver.get("evidence_escalation", {}) or {}
            if evidence_escalation.get("requested"):
                lines.append(f"- 证据升级: {evidence_escalation.get('reason', '')}")

            history = patchweaver.get("validation_feedback_history", []) or []
            if history:
                lines.append("- 最近验证反馈历史:")
                for item in history[-2:]:
                    if not isinstance(item, dict):
                        continue
                    analyzer_id = str(item.get("analyzer", "") or "").strip()
                    phase = str(item.get("phase", "") or "").strip() or "validation"
                    summary = str(item.get("summary", "") or "").strip()
                    if summary:
                        prefix = f"[{analyzer_id}] " if analyzer_id else ""
                        lines.append(f"  - {prefix}phase={phase}: {summary}")

            refinement_targets = patchweaver.get("refinement_targets", {}) or {}
            current_refinement_target = refinement_targets.get(normalize_analyzer_id(self.analyzer_type), {}) or {}
            refinement_bundles = patchweaver.get("refinement_evidence_bundles", {}) or {}
            current_refinement_bundle = refinement_bundles.get(normalize_analyzer_id(self.analyzer_type), {}) or {}
            if current_refinement_target:
                lines.append("")
                lines.append("## 精炼目标")
                baseline_path = str(current_refinement_target.get("artifact_path", "") or "").strip()
                checker_name = str(current_refinement_target.get("checker_name", "") or "").strip()
                if checker_name:
                    lines.append(f"- 当前待精炼产物: {checker_name}")
                if baseline_path:
                    lines.append(f"- 产物路径: {baseline_path}")
                validation_summary = str(current_refinement_target.get("validation_summary", "") or "").strip()
                if validation_summary:
                    lines.append(f"- 当前功能验证摘要: {validation_summary}")
                refinement_summary = str(current_refinement_target.get("refinement_summary", "") or "").strip()
                if refinement_summary:
                    lines.append(f"- 精炼提示: {refinement_summary}")
                records = len((current_refinement_bundle.get("records", []) or [])) if isinstance(current_refinement_bundle, dict) else 0
                missing = len((current_refinement_bundle.get("missing_evidence", []) or [])) if isinstance(current_refinement_bundle, dict) else 0
                if records or missing:
                    lines.append(f"- 已恢复精炼证据: records={records}, missing={missing}")
                lines.append("- 进入精炼前先把该产物复制到当前 refinement 目录，后续只在这份工作副本上修改、验证和保存。")

        return "\n".join(lines)

    def _build_runtime_path_context(
        self,
        context: AnalyzerContext,
        work_dir: str,
    ) -> str:
        """提供运行时路径锚点，避免模型把输出目录误当成源项目。"""
        lines = ["## 运行路径"]
        if context.validate_path:
            lines.append(f"- 验证/源项目路径: {Path(context.validate_path).expanduser().resolve()}")
        if work_dir:
            lines.append(f"- 当前分析器输出目录: {Path(work_dir).expanduser().resolve()}")
        if context.validate_path:
            lines.append("- 该路径主要用于后续验证，不是当前补丁理解阶段的输入；当前阶段不要通过读取源码或目录来推导补丁机制。")
        return "\n".join(lines)

    def _stage_refinement_artifact(
        self,
        source_path: str,
        work_dir: str,
    ) -> str:
        """复制 baseline 产物到当前 refinement work_dir，并返回工作副本路径。"""
        raw_path = str(source_path or "").strip()
        if not raw_path:
            return ""

        source = Path(raw_path).expanduser().resolve()
        if not source.exists():
            raise FileNotFoundError(f"精炼基线产物不存在: {source}")

        if not work_dir:
            return str(source)

        work_root = Path(work_dir).expanduser().resolve()
        work_root.mkdir(parents=True, exist_ok=True)
        staged = work_root / source.name

        if staged.exists() and staged.resolve() == source:
            return str(staged)

        if not staged.exists() or staged.read_bytes() != source.read_bytes():
            shutil.copy2(str(source), str(staged))
        return str(staged)

    def _review_generated_artifact(
        self,
        analyzer_id: AnalyzerId,
        work_dir: str,
        checker_name: str,
        checker_code: str = "",
        review_mode: str = "generate",
    ):
        """对最终落地产物执行一次强制结构审查，避免智能体绕过质量门。"""
        if not self._tool_registry or not checker_name:
            return None

        review_tool = self._tool_registry.get("review_artifact")
        if not review_tool:
            return None

        suffix = ".ql" if normalize_analyzer_id(analyzer_id) == "codeql" else ".cpp"
        artifact_path = str(Path(work_dir) / f"{checker_name}{suffix}")

        try:
            return review_tool.execute(
                artifact_path=artifact_path,
                analyzer=normalize_analyzer_id(analyzer_id),
                source_code=checker_code or "",
                review_mode=review_mode,
            )
        except Exception:
            return None

    def collect_evidence(
        self,
        context: AnalyzerContext,
        plan: Optional[Dict[str, Any]] = None,
    ):
        """Collect analyzer evidence. Subclasses may override."""
        from ..evidence.collectors.patch_semantics import PatchSemanticsCollector

        return PatchSemanticsCollector().collect(context)

    def restore_refinement_evidence_bundle(
        self,
        context: AnalyzerContext,
    ):
        """恢复精炼阶段注入的历史 evidence bundle。"""
        from ..evidence.normalizer import EvidenceNormalizer

        patchweaver = ((context.shared_analysis or {}).get("patchweaver", {}) or {})
        refinement_bundles = patchweaver.get("refinement_evidence_bundles", {}) or {}
        raw_bundle = refinement_bundles.get(normalize_analyzer_id(self.analyzer_type), {}) or {}
        return EvidenceNormalizer.from_raw_bundle(raw_bundle)

    def _collect_patchweaver_evidence(
        self,
        context: AnalyzerContext,
        *,
        analyzer_id: AnalyzerId,
        analyzer_collector: Any,
    ):
        """Collect shared, analyzer-specific, and escalated evidence in one place."""
        from ..evidence.collectors.metadata_intent import MetadataIntentEvidenceCollector
        from ..evidence.collectors.patch_semantics import PatchSemanticsCollector
        from ..evidence.normalizer import EvidenceNormalizer
        from .evidence_escalation import EvidenceEscalationAdvisor
        from .evidence_schema import EvidenceBundle

        normalized_analyzer = normalize_analyzer_id(analyzer_id)
        shared_analysis = context.shared_analysis if isinstance(context.shared_analysis, dict) else {}
        context.shared_analysis = shared_analysis

        baseline_bundle = self.restore_refinement_evidence_bundle(context)
        patch_bundle = PatchSemanticsCollector().collect(context)
        patch_bundle = EvidenceBundle(
            records=list(patch_bundle.records),
            missing_evidence=[],
            collected_analyzers=list(patch_bundle.collected_analyzers),
        )
        analyzer_bundle = analyzer_collector.collect(context)
        merged_bundle = EvidenceNormalizer.merge_bundles(
            baseline_bundle,
            patch_bundle,
            analyzer_bundle,
        )

        escalation = EvidenceEscalationAdvisor().evaluate(
            analyzer_id=normalized_analyzer,
            shared_analysis=shared_analysis,
            evidence_bundle=merged_bundle,
        )
        patchweaver = dict(shared_analysis.get("patchweaver", {}) or {})
        patchweaver["evidence_escalation"] = escalation
        shared_analysis["patchweaver"] = patchweaver

        if escalation.get("requested"):
            metadata_bundle = MetadataIntentEvidenceCollector(normalized_analyzer).collect(context)
            merged_bundle = EvidenceNormalizer.merge_bundles(merged_bundle, metadata_bundle)
            escalation["applied_collectors"] = list(escalation.get("collectors", []))
            escalation["post_slice_metrics"] = EvidenceNormalizer.slice_metrics(
                merged_bundle,
                analyzer=normalized_analyzer,
            )

        patchweaver["evidence_escalation"] = escalation
        patchweaver["evidence_bundle"] = merged_bundle.to_dict()
        shared_analysis["patchweaver"] = patchweaver
        return merged_bundle

    def build_synthesis_input(
        self,
        context: AnalyzerContext,
        evidence_bundle,
    ):
        """Build a structured synthesis contract from evidence."""
        from .detector_synthesizer import DetectorSynthesisInputBuilder

        descriptor = getattr(self.__class__, "DESCRIPTOR", None)
        if descriptor is None:
            descriptor = AnalyzerDescriptor(
                id=normalize_analyzer_id(self.analyzer_type),
                name=self.name,
                description=self.name,
            )
        return DetectorSynthesisInputBuilder().build(
            descriptor=descriptor,
            context=context,
            evidence_bundle=evidence_bundle,
        )

    def _build_evidence_context(self, evidence_bundle) -> str:
        """Format collected evidence for the generation prompt."""
        if not evidence_bundle or not getattr(evidence_bundle, "records", None):
            return ""

        from ..evidence.normalizer import EvidenceNormalizer

        lines = ["## 当前证据摘要"]
        lines.extend(
            EvidenceNormalizer.summarize_bundle(
                evidence_bundle,
                analyzer=normalize_analyzer_id(self.analyzer_type),
                limit=8,
            )
        )
        return "\n".join(lines)

    def _build_synthesis_context(self, synthesis_input) -> str:
        """Render a structured synthesis contract for prompt consumers."""
        if synthesis_input is None:
            return ""
        to_prompt_block = getattr(synthesis_input, "to_prompt_block", None)
        if callable(to_prompt_block):
            return to_prompt_block()
        return ""

    def _build_refinement_context(
        self,
        artifact: Any,
        baseline_result: Optional[AnalyzerResult] = None,
        synthesis_input: Any = None,
    ) -> str:
        """Build refine-specific context around an existing artifact."""
        if artifact is None:
            return ""

        artifact_path = str(
            getattr(artifact, "source_path", "")
            or getattr(artifact, "output_path", "")
            or ""
        ).strip()
        if not artifact_path:
            return ""

        lines = ["## 精炼目标"]
        lines.append(f"- mode: refine")
        lines.append(f"- target_artifact_path: {artifact_path}")
        lines.append("- refinement_workspace_rule: copy baseline into current refinement directory first, then refine only that copied artifact")

        checker_name = str(getattr(artifact, "checker_name", "") or "").strip()
        if checker_name:
            lines.append(f"- target_artifact_name: {checker_name}")

        if baseline_result is not None:
            lines.append(f"- baseline_generation_success: {bool(getattr(baseline_result, 'success', False))}")
            validation_summary = ""
            validation_result = getattr(baseline_result, "validation_result", None)
            if validation_result is not None:
                if bool(getattr(validation_result, "success", False)):
                    diagnostics = len(getattr(validation_result, "diagnostics", []) or [])
                    validation_summary = f"validation_ok diagnostics={diagnostics}"
                else:
                    validation_summary = str(getattr(validation_result, "error_message", "") or "").strip() or "validation_failed"
            if validation_summary:
                lines.append(f"- baseline_validation: {validation_summary}")

        report_entry = getattr(artifact, "report_entry", {}) or {}
        feedback_summary = str(report_entry.get("validation_feedback_summary", "") or "").strip()
        if feedback_summary:
            lines.append("- baseline_feedback_summary:")
            for item in feedback_summary.splitlines()[:6]:
                cleaned = item.strip()
                if cleaned:
                    lines.append(f"  {cleaned}")

        evidence_summary = str(report_entry.get("post_validation_evidence_summary", "") or report_entry.get("evidence_summary", "") or "").strip()
        if evidence_summary:
            lines.append("- baseline_evidence_summary:")
            for item in evidence_summary.splitlines()[:8]:
                cleaned = item.strip()
                if cleaned:
                    lines.append(f"  {cleaned}")

        baseline_review = self._review_baseline_artifact(
            artifact_path=artifact_path,
            analyzer_id=self.analyzer_type,
        )
        if baseline_review is not None and not bool(getattr(baseline_review, "success", False)):
            findings = list((getattr(baseline_review, "metadata", {}) or {}).get("findings", []) or [])
            error_message = str(getattr(baseline_review, "error", "") or "").strip()
            if findings or error_message:
                lines.append("## 基线结构审查失败点")
                if error_message:
                    lines.append(f"- review_error: {error_message}")
                for item in findings[:6]:
                    cleaned = str(item).strip()
                    if cleaned:
                        lines.append(f"- {cleaned}")
                lines.append("- 以上失败点应优先通过最小修改修复，不要重写整个产物。")

        refinement_digest = self._build_refinement_evidence_digest(synthesis_input)
        if refinement_digest:
            lines.append(refinement_digest)

        recommended_queries = self._build_refinement_knowledge_queries(
            artifact=artifact,
            baseline_result=baseline_result,
            synthesis_input=synthesis_input,
            report_entry=report_entry,
        )
        if recommended_queries:
            lines.append("## 推荐首轮 RAG 查询")
            for query in recommended_queries[:3]:
                lines.append(f"- `{query}`")

        lines.append("- 必须先读取 refinement 目录中的工作副本，分析已有 trigger/barrier/guard/状态语义，再在该副本上精炼。")
        lines.append("- 不要创建新文件名，不要绕开现有质量门。")
        return "\n".join(lines)

    def _review_baseline_artifact(
        self,
        artifact_path: str,
        analyzer_id: AnalyzerId,
        review_mode: str = "refine",
    ):
        if not self._tool_registry or not artifact_path:
            return None

        review_tool = self._tool_registry.get("review_artifact")
        if not review_tool:
            return None

        try:
            return review_tool.execute(
                artifact_path=artifact_path,
                analyzer=normalize_analyzer_id(analyzer_id),
                review_mode=review_mode,
            )
        except Exception:
            return None

    def _build_refinement_evidence_digest(self, synthesis_input: Any) -> str:
        """Render an action-oriented digest tailored for refinement loops."""
        synthesis_payload: Dict[str, Any] = {}
        if synthesis_input is not None:
            to_dict = getattr(synthesis_input, "to_dict", None)
            if callable(to_dict):
                synthesis_payload = to_dict() or {}
            elif isinstance(synthesis_input, dict):
                synthesis_payload = dict(synthesis_input)
        if not synthesis_payload:
            return ""

        lines: List[str] = ["## PATCHWEAVER 精炼导图"]

        def append_group(title: str, items: List[str], limit: int = 4):
            normalized = [str(item).strip() for item in items if str(item).strip()]
            if not normalized:
                return
            lines.append(f"- {title}:")
            for item in normalized[:limit]:
                lines.append(f"  - {item}")

        append_group("focus_files", synthesis_payload.get("focus_files", []) or [], limit=4)
        append_group("focus_functions", synthesis_payload.get("focus_functions", []) or [], limit=6)
        append_group("patch_mechanism_signals", synthesis_payload.get("patch_mechanism_signals", []) or [], limit=4)
        append_group("silencing_conditions", synthesis_payload.get("silencing_conditions", []) or [], limit=4)

        semantic_slices = synthesis_payload.get("selected_semantic_slices", []) or []
        if semantic_slices:
            lines.append("- semantic_witnesses:")
            for item in semantic_slices[:3]:
                if not isinstance(item, dict):
                    continue
                scope = item.get("scope", {}) or {}
                target = str(scope.get("function") or scope.get("file") or "repo").strip()
                payload = item.get("semantic_payload", {}) or {}
                summary = str(payload.get("summary", "") or "").strip()
                api_terms = payload.get("call_targets") or payload.get("operations") or payload.get("tracked_symbols") or []
                api_text = ", ".join(str(term) for term in api_terms[:4] if str(term).strip())
                line = f"  - {target}: {summary}" if summary else f"  - {target}"
                if api_text:
                    line += f" | key_terms={api_text}"
                lines.append(line)

        append_group("implementation_hints", synthesis_payload.get("implementation_hints", []) or [], limit=6)
        append_group("validation_expectations", synthesis_payload.get("validation_expectations", []) or [], limit=4)
        lines.append("- 先用这些 witness / barriers / expectations 决定最小必要修改，再进入 write/compile/review。")
        return "\n".join(lines)

    def _build_refinement_knowledge_queries(
        self,
        artifact: Any,
        baseline_result: Optional[AnalyzerResult] = None,
        synthesis_input: Any = None,
        report_entry: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Derive refinement-aware seed queries from structured evidence."""
        report_entry = report_entry or {}
        synthesis_payload: Dict[str, Any] = {}
        if synthesis_input is not None:
            to_dict = getattr(synthesis_input, "to_dict", None)
            if callable(to_dict):
                synthesis_payload = to_dict() or {}
            elif isinstance(synthesis_input, dict):
                synthesis_payload = dict(synthesis_input)

        mechanism_contract = synthesis_payload.get("mechanism_contract", {}) or {}
        primary_pattern = str(synthesis_payload.get("primary_pattern", "") or "").replace("_", " ").strip()
        mechanism_family = str(mechanism_contract.get("mechanism_family", "") or "").replace("_", " ").strip()
        objective = str(synthesis_payload.get("objective", "") or "").strip()
        checker_name = str(getattr(artifact, "checker_name", "") or "").strip()

        focus_functions = synthesis_payload.get("focus_functions", []) or []
        focus_text = " ".join(str(item) for item in focus_functions[:4] if str(item).strip())
        report_text = " ".join(
            str(report_entry.get(key, "") or "").strip()
            for key in (
                "validation_feedback_summary",
                "post_validation_evidence_summary",
                "evidence_summary",
            )
        )
        mechanism_text = " ".join(
            " ".join(str(item) for item in values[:6] if str(item).strip())
            for values in (
                mechanism_contract.get("trigger_invariants", []) or [],
                mechanism_contract.get("silence_invariants", []) or [],
                mechanism_contract.get("evidence_backed_axes", []) or [],
            )
        )
        validation_hint = ""
        if baseline_result is not None and getattr(baseline_result, "validation_result", None) is not None:
            validation_result = getattr(baseline_result, "validation_result", None)
            diagnostics = len(getattr(validation_result, "diagnostics", []) or [])
            validation_hint = (
                f"diagnostics {diagnostics}"
                if bool(getattr(validation_result, "success", False))
                else str(getattr(validation_result, "error_message", "") or "").strip()
            )

        identifier_text = " ".join(
            item
            for item in (
                checker_name,
                primary_pattern,
                mechanism_family,
                objective,
                focus_text,
                mechanism_text,
                report_text,
                validation_hint,
            )
            if item
        )
        identifiers = self._extract_refinement_query_identifiers(identifier_text)

        analyzer_id = normalize_analyzer_id(self.analyzer_type)
        family_terms = self._build_refinement_pattern_terms(primary_pattern)
        shared_focus = " ".join(item for item in (family_terms[0] if family_terms else "", focus_text) if item).strip()
        if not shared_focus:
            shared_focus = checker_name or "same vulnerability class"
        semantic_priority = {
            "authoritative",
            "relookup",
            "cached",
            "pointer",
            "stable",
            "handle",
            "session_id",
            "find_session",
            "programstate",
            "fieldaccess",
            "dataflow",
            "alias",
            "continuity",
        }
        preferred_identifiers = [
            token
            for token in identifiers
            if "_" in token
            or any(ch.isupper() for ch in token[1:])
            or token.lower() in semantic_priority
        ]
        if not preferred_identifiers:
            preferred_identifiers = identifiers
        concrete_terms = " ".join(preferred_identifiers[:6])
        family_focus = " ".join(family_terms[:2]).strip() if family_terms else ""

        if analyzer_id == "codeql":
            candidates = [
                f"CodeQL C++ {family_focus or shared_focus} {concrete_terms} cached pointer authoritative relookup stable handle",
                f"CodeQL C++ {family_focus or shared_focus} {concrete_terms} FieldAccess data flow alias continuity",
            ]
        else:
            candidates = [
                f"CSA {family_focus or shared_focus} {concrete_terms} cached pointer authoritative relookup stable handle",
                f"Clang Static Analyzer {family_focus or shared_focus} {concrete_terms} ProgramState alias continuity same symbolic resource",
            ]

        queries: List[str] = []
        seen = set()
        for item in candidates:
            normalized = " ".join(str(item or "").split()).strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            queries.append(normalized)
        return queries

    def _extract_refinement_query_identifiers(self, text: str) -> List[str]:
        """Pick stable mechanism/API tokens that are useful in RAG queries."""
        stop_words = {
            "current", "baseline", "validation", "diagnostics", "records", "summary",
            "trigger", "barrier", "guard", "state", "semantic", "evidence",
            "patch", "checker", "query", "same", "class", "resource", "lifecycle",
            "violation", "detector", "mode", "refine", "generation", "success",
            "failure", "focus", "function", "functions", "objective", "mechanism",
            "contract", "analysis", "context", "report", "result", "results",
            "after", "before", "added", "removed", "later", "local", "global",
            "path", "sensitive", "primary", "pattern", "family",
            "synthesize", "that", "this", "through", "tracking", "release",
            "dereference", "direct", "continue", "continues", "still",
            "fresh", "freshness", "missing", "stale", "lifetime", "use", "free",
        }
        identifiers: List[str] = []
        seen = set()
        for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_+-]{2,}", text or ""):
            token = str(raw or "").strip()
            lowered = token.lower()
            if lowered in stop_words:
                continue
            if lowered.startswith(("patch_", "validation_", "baseline_")):
                continue
            if lowered in seen:
                continue
            seen.add(lowered)
            identifiers.append(token)
        return identifiers

    def _build_refinement_pattern_terms(self, primary_pattern: str) -> List[str]:
        token = str(primary_pattern or "").strip()
        if not token:
            return []
        variants = [
            token.replace("_", "-"),
            token,
            token.replace("_", " "),
        ]
        output: List[str] = []
        seen = set()
        for item in variants:
            normalized = " ".join(str(item or "").split()).strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            output.append(normalized)
        return output

    def synthesize_detector(
        self,
        context: AnalyzerContext,
        evidence_bundle,
        synthesis_input,
    ) -> AnalyzerResult:
        """Subclasses should implement detector synthesis from evidence."""
        raise NotImplementedError

    def _join_context_blocks(self, *blocks: str) -> str:
        """Join non-empty context blocks with spacing."""
        valid = [block.strip() for block in blocks if isinstance(block, str) and block.strip()]
        return "\n\n".join(valid)


class AnalyzerRegistry:
    """
    分析器注册中心

    管理所有可用的分析器，支持按类型获取分析器实例。
    """

    _analyzers: Dict[str, type] = {}
    _descriptors: Dict[str, AnalyzerDescriptor] = {}

    @classmethod
    def register(cls, analyzer_type: AnalyzerId):
        """
        注册分析器类的装饰器

        Args:
            analyzer_type: 分析器类型
        """
        def decorator(analyzer_class: type):
            analyzer_id = normalize_analyzer_id(analyzer_type)
            cls._analyzers[analyzer_id] = analyzer_class
            descriptor = getattr(analyzer_class, "DESCRIPTOR", None)
            if descriptor is None:
                descriptor = AnalyzerDescriptor(
                    id=analyzer_id,
                    name=analyzer_class.__name__,
                    description="可扩展分析器（未提供详细描述）。",
                    best_for=[],
                    evidence_types=[],
                    detector_artifacts=[],
                    strengths=[],
                    validation_modes=[],
                )
            cls._descriptors[analyzer_id] = descriptor
            return analyzer_class
        return decorator

    @classmethod
    def get(
        cls,
        analyzer_type: AnalyzerId,
        config: Dict[str, Any],
        llm_client=None,
        progress_callback: Optional[Callable] = None,
        suppress_output: bool = False,
    ) -> Optional[BaseAnalyzer]:
        """
        获取分析器实例

        Args:
            analyzer_type: 分析器类型
            config: 配置字典
            llm_client: LLM 客户端
            progress_callback: 进度回调

        Returns:
            分析器实例，如果类型未注册则返回 None
        """
        analyzer_id = normalize_analyzer_id(analyzer_type)
        analyzer_class = cls._analyzers.get(analyzer_id)
        if analyzer_class is None:
            return None

        return analyzer_class(
            config=config,
            llm_client=llm_client,
            progress_callback=progress_callback,
            suppress_output=suppress_output,
        )

    @classmethod
    def list_available(cls) -> List[str]:
        """列出所有可用的分析器类型"""
        return list(cls._analyzers.keys())

    @classmethod
    def list_descriptors(cls) -> List[AnalyzerDescriptor]:
        """列出所有可用分析器的描述。"""
        ordered: List[AnalyzerDescriptor] = []
        for analyzer_id in cls.list_available():
            descriptor = cls._descriptors.get(analyzer_id)
            if descriptor is not None:
                ordered.append(descriptor)
        return ordered

    @classmethod
    def create_by_name(
        cls,
        analyzer_name: str,
        config: Dict[str, Any],
        llm_client=None,
        progress_callback: Optional[Callable] = None,
        suppress_output: bool = False,
    ) -> Optional[BaseAnalyzer]:
        """按分析器名称创建实例。"""
        normalized = normalize_analyzer_id(analyzer_name)
        for analyzer_id in cls.list_available():
            descriptor = cls._descriptors.get(analyzer_id)
            if descriptor and descriptor.id == normalized:
                return cls.get(
                    analyzer_type=analyzer_id,
                    config=config,
                    llm_client=llm_client,
                    progress_callback=progress_callback,
                    suppress_output=suppress_output,
                )
        return None
