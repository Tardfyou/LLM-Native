"""
CodeQL 分析器

封装 CodeQL 查询生成逻辑，包括:
- 智能体初始化
- QL 查询代码生成
- 语法验证
- 语义验证
"""

from typing import Dict, Any, Optional, Callable
from pathlib import Path
import os
import time
import re

from loguru import logger
from ..utils.vulnerability_taxonomy import (
    normalize_vulnerability_type,
    supported_vulnerability_types,
)

from .analyzer_base import (
    BaseAnalyzer,
    AnalyzerType,
    AnalyzerDescriptor,
    AnalyzerContext,
    AnalyzerResult,
    AnalyzerRegistry
)


@AnalyzerRegistry.register(AnalyzerType.CODEQL)
class CodeQLAnalyzer(BaseAnalyzer):
    """
    CodeQL 分析器

    生成 CodeQL 查询文件 (.ql)
    """

    DESCRIPTOR = AnalyzerDescriptor(
        id="codeql",
        name="CodeQL",
        description="全局/跨文件语义查询，擅长污点传播与复杂模式匹配。",
        best_for=["sql_injection", "command_injection", "path_traversal", "taint_tracking"],
        evidence_types=["dataflow_candidate", "call_chain", "api_contract", "context_summary", "semantic_slice", "metadata_hint", "diagnostic"],
        detector_artifacts=["ql_query"],
        strengths=["interprocedural", "global_semantics", "api_modeling"],
        validation_modes=["query_parse", "semantic"],
    )

    # 支持的漏洞类型映射
    SUPPORTED_VULN_TYPES = supported_vulnerability_types(include_extended=True)

    @property
    def analyzer_type(self) -> AnalyzerType:
        return AnalyzerType.CODEQL

    @property
    def name(self) -> str:
        return "CodeQL"

    def _do_initialize(self):
        """初始化工具注册中心；生成智能体延迟到 generate 路径再创建。"""
        from ..tools import ToolProviderOptions, build_tool_registry

        self._tool_registry = build_tool_registry(
            config=self.config,
            options=ToolProviderOptions(
                analyzer="codeql",
                include_analyzer_selector=False,
                include_patch_analysis=True,
                include_project_analyzer=False,
                silent=True,
            ),
            llm_client=self.llm_client,
        )

        # generate agent 需要完整配置树；这里只覆写 agent.verbose。
        agent_config = dict(self.config or {})
        agent_section = dict((agent_config.get("agent", {}) or {}))
        if self._suppress_output:
            agent_section["verbose"] = False
        agent_config["agent"] = agent_section

        self._agent = None
        self._generate_agent_config = agent_config

        logger.info(f"[CodeQL] 分析器初始化完成")

    def _ensure_generate_agent(self):
        if self._agent is not None:
            return

        from ..generate import LangChainGenerateAgent

        self._agent = LangChainGenerateAgent(
            tool_registry=self._tool_registry,
            config=getattr(self, "_generate_agent_config", dict(self.config.get("agent", {}))),
            analyzer="codeql",
            progress_callback=self._wrap_agent_progress,
            llm_override=self._llm_client,
        )

    def _wrap_agent_progress(self, data: Dict[str, Any]):
        """包装智能体进度事件"""
        if self.progress_callback:
            event = data.get("event", "")
            self._emit_progress(
                f"agent_{event}",
                **{k: v for k, v in data.items() if k != "event"}
            )

    def generate(self, context: AnalyzerContext) -> AnalyzerResult:
        """
        生成 CodeQL 查询

        Args:
            context: 分析器运行上下文

        Returns:
            AnalyzerResult
        """
        self._ensure_initialized()
        start_time = time.time()

        self._emit_progress("generation_started")

        # 创建独立工作目录
        work_dir = self._create_work_dir(context.output_dir)

        # 设置工具的工作目录
        self._setup_tool_work_dirs(work_dir, context.validate_path)

        self._emit_progress("evidence_collection_started")
        evidence_bundle = self.collect_evidence(context)
        synthesis_input = self.build_synthesis_input(context, evidence_bundle)
        self._emit_progress(
            "evidence_collection_completed",
            records=len(getattr(evidence_bundle, "records", []) or []),
            missing=len(getattr(evidence_bundle, "missing_evidence", []) or []),
        )
        self._emit_progress(
            "synthesis_input_prepared",
            selected_evidence=len(getattr(synthesis_input, "selected_evidence_ids", []) or []),
        )

        # 推断漏洞类型
        vuln_type = self._infer_vulnerability_type(
            context.shared_analysis,
            context.patch_path
        )

        try:
            result = self.synthesize_detector(
                context=context,
                evidence_bundle=evidence_bundle,
                synthesis_input=synthesis_input,
            )
            result.execution_time = time.time() - start_time
            result.metadata["vulnerability_type"] = vuln_type

            self._emit_progress(
                "generation_completed",
                success=result.success,
                checker_name=result.checker_name,
                iterations=result.iterations,
                output_path=result.output_path,
            )

            return result

        except Exception as e:
            logger.exception(f"[CodeQL] 生成失败: {e}")
            self._emit_progress("generation_failed", error=str(e))

            return AnalyzerResult(
                analyzer_type=AnalyzerType.CODEQL,
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time
            )

    def collect_evidence(self, context: AnalyzerContext, plan: Optional[Dict[str, Any]] = None):
        from ..evidence.collectors.codeql_flow import CodeQLFlowEvidenceCollector
        return self._collect_patchweaver_evidence(
            context,
            analyzer_id=AnalyzerType.CODEQL,
            analyzer_collector=CodeQLFlowEvidenceCollector(),
        )

    def synthesize_detector(
        self,
        context: AnalyzerContext,
        evidence_bundle,
        synthesis_input,
    ) -> AnalyzerResult:
        self._ensure_initialized()
        work_dir = self._create_work_dir(context.output_dir)
        self._setup_tool_work_dirs(work_dir, context.validate_path)
        from ..evidence.normalizer import EvidenceNormalizer

        extra_context = self._join_context_blocks(
            self._build_extra_context(context.shared_analysis),
            self._build_runtime_path_context(context, work_dir),
            self._build_evidence_context(evidence_bundle),
            self._build_synthesis_context(synthesis_input),
        )

        vuln_type = self._infer_vulnerability_type(
            context.shared_analysis,
            context.patch_path,
        )
        self._ensure_generate_agent()
        from ..generate import GenerationRequest

        agent_result = self._agent.run(
            GenerationRequest(
                analyzer="codeql",
                patch_path=context.patch_path,
                work_dir=work_dir,
                validate_path=context.validate_path or "",
                extra_context=extra_context,
                max_iterations=int((self.config.get("agent", {}) or {}).get("max_iterations", 12) or 12),
            )
        )
        review_result = self._review_generated_artifact(
            analyzer_id=AnalyzerType.CODEQL,
            work_dir=work_dir,
            checker_name=agent_result.checker_name,
            checker_code=agent_result.checker_code,
            review_mode="generate",
        )

        slice_metrics = EvidenceNormalizer.slice_metrics(evidence_bundle, analyzer="codeql")
        final_success = bool(agent_result.success)
        final_error = agent_result.error_message
        review_metadata = {
            "success": True,
            "error": "",
            "findings": [],
        }
        if review_result is not None:
            review_metadata = {
                "success": bool(review_result.success),
                "error": review_result.error or "",
                "findings": list((review_result.metadata or {}).get("findings", []) or []),
            }
            if final_success and not review_result.success:
                final_success = False
                final_error = review_result.error or "生成产物结构审查未通过"
                self._emit_progress(
                    "artifact_review_failed",
                    analyzer="codeql",
                    findings=review_metadata["findings"],
                    error=final_error,
                )

        return AnalyzerResult(
            analyzer_type=AnalyzerType.CODEQL,
            success=final_success,
            checker_name=agent_result.checker_name,
            checker_code=agent_result.checker_code,
            output_path=agent_result.output_path,
            iterations=agent_result.iterations,
            compile_attempts=agent_result.compile_attempts,
            error_message=final_error,
            metadata={
                "work_dir": work_dir,
                "patch_path": context.patch_path,
                "vulnerability_type": vuln_type,
                "artifact_review": review_metadata,
                "evidence_bundle": evidence_bundle.to_dict(),
                "evidence_records": len(evidence_bundle.records),
                "missing_evidence": list(evidence_bundle.missing_evidence),
                "evidence_degraded": bool(evidence_bundle.missing_evidence),
                "semantic_slice_records": slice_metrics.get("semantic_slice_count", 0),
                "context_summary_records": slice_metrics.get("context_summary_count", 0),
                "slice_coverage": slice_metrics.get("coverage", ""),
                "verifier_backed_slices": slice_metrics.get("verifier_backed_count", 0),
                "slice_kinds": slice_metrics.get("kinds", {}),
                "evidence_escalation": ((context.shared_analysis or {}).get("patchweaver", {}) or {}).get("evidence_escalation", {}),
                "evidence_summary": self._build_evidence_context(evidence_bundle),
                "synthesis_input": synthesis_input.to_dict(),
                "synthesis_summary": synthesis_input.to_prompt_block(),
            },
        )

    def refine(
        self,
        context: AnalyzerContext,
        artifact,
        baseline_result: AnalyzerResult,
    ) -> AnalyzerResult:
        """Refine an existing CodeQL query with the LangChain-based agent."""
        self._ensure_initialized()
        start_time = time.time()
        self._emit_progress("generation_started")

        work_dir = self._create_work_dir(context.output_dir)
        self._setup_tool_work_dirs(work_dir, context.validate_path)

        evidence_bundle = self.collect_evidence(context)
        synthesis_input = self.build_synthesis_input(context, evidence_bundle)
        self._emit_progress(
            "evidence_collection_completed",
            records=len(getattr(evidence_bundle, "records", []) or []),
            missing=len(getattr(evidence_bundle, "missing_evidence", []) or []),
        )
        self._emit_progress(
            "synthesis_input_prepared",
            selected_evidence=len(getattr(synthesis_input, "selected_evidence_ids", []) or []),
        )
        refinement_baseline_path = str(
            getattr(artifact, "source_path", "")
            or getattr(artifact, "output_path", "")
            or ""
        ).strip()
        if not refinement_baseline_path:
            return AnalyzerResult(
                analyzer_type=AnalyzerType.CODEQL,
                success=False,
                error_message="缺少可精炼的 CodeQL 查询路径",
            )

        staged_target = self._stage_refinement_artifact(
            source_path=refinement_baseline_path,
            work_dir=work_dir,
        )
        extra_context = self._join_context_blocks(
            self._build_extra_context(context.shared_analysis),
            self._build_runtime_path_context(context, work_dir),
            self._build_evidence_context(evidence_bundle),
            self._build_synthesis_context(synthesis_input),
            self._build_refinement_context(
                artifact=artifact,
                baseline_result=baseline_result,
                synthesis_input=synthesis_input,
            ),
        )
        vuln_type = self._infer_vulnerability_type(
            context.shared_analysis,
            context.patch_path,
        )

        from ..evidence.normalizer import EvidenceNormalizer
        from ..refine import LangChainRefinementAgent, RefinementRequest

        refine_agent = LangChainRefinementAgent(
            config=self.config,
            tool_registry=self._tool_registry,
            analyzer="codeql",
            progress_callback=self._wrap_agent_progress,
            llm_override=None,
        )
        agent_result = refine_agent.run(
            RefinementRequest(
                analyzer="codeql",
                patch_path=context.patch_path,
                work_dir=work_dir,
                target_path=staged_target,
                source_path=refinement_baseline_path,
                validate_path=context.validate_path or "",
                checker_name=Path(staged_target).stem,
                extra_context=extra_context,
                max_iterations=int((self.config.get("agent", {}) or {}).get("max_iterations", 12) or 12),
            )
        )

        review_result = self._review_generated_artifact(
            analyzer_id=AnalyzerType.CODEQL,
            work_dir=work_dir,
            checker_name=agent_result.checker_name,
            checker_code=agent_result.checker_code,
            review_mode="refine",
        )

        slice_metrics = EvidenceNormalizer.slice_metrics(evidence_bundle, analyzer="codeql")
        final_success = bool(agent_result.success)
        final_error = agent_result.error_message
        review_metadata = {
            "success": True,
            "error": "",
            "findings": [],
        }
        if review_result is not None:
            review_metadata = {
                "success": bool(review_result.success),
                "error": review_result.error or "",
                "findings": list((review_result.metadata or {}).get("findings", []) or []),
            }
            if final_success and not review_result.success:
                final_success = False
                final_error = review_result.error or "生成产物结构审查未通过"
                self._emit_progress(
                    "artifact_review_failed",
                    analyzer="codeql",
                    findings=review_metadata["findings"],
                    error=final_error,
                )

        result = AnalyzerResult(
            analyzer_type=AnalyzerType.CODEQL,
            success=final_success,
            checker_name=agent_result.checker_name,
            checker_code=agent_result.checker_code,
            output_path=agent_result.output_path,
            iterations=agent_result.iterations,
            compile_attempts=agent_result.compile_attempts,
            error_message=final_error,
            execution_time=time.time() - start_time,
            metadata={
                "work_dir": work_dir,
                "patch_path": context.patch_path,
                "refinement_target_path": staged_target,
                "vulnerability_type": vuln_type,
                "artifact_review": review_metadata,
                "evidence_bundle": evidence_bundle.to_dict(),
                "evidence_records": len(evidence_bundle.records),
                "missing_evidence": list(evidence_bundle.missing_evidence),
                "evidence_degraded": bool(evidence_bundle.missing_evidence),
                "semantic_slice_records": slice_metrics.get("semantic_slice_count", 0),
                "context_summary_records": slice_metrics.get("context_summary_count", 0),
                "slice_coverage": slice_metrics.get("coverage", ""),
                "verifier_backed_slices": slice_metrics.get("verifier_backed_count", 0),
                "slice_kinds": slice_metrics.get("kinds", {}),
                "evidence_escalation": ((context.shared_analysis or {}).get("patchweaver", {}) or {}).get("evidence_escalation", {}),
                "evidence_summary": self._build_evidence_context(evidence_bundle),
                "synthesis_input": synthesis_input.to_dict(),
                "synthesis_summary": synthesis_input.to_prompt_block(),
                "refinement_agent": {
                    "final_message": agent_result.final_message,
                    "tool_history": agent_result.metadata.get("tool_history", []),
                },
            },
        )
        self._emit_progress(
            "generation_completed",
            success=result.success,
            checker_name=result.checker_name,
            iterations=result.iterations,
            output_path=result.output_path,
        )
        return result

    def validate(
        self,
        result: AnalyzerResult,
        context: AnalyzerContext
    ) -> Any:
        """
        验证 CodeQL 查询

        Args:
            result: 生成结果
            context: 运行上下文

        Returns:
            验证结果
        """
        if not result.success or not result.output_path:
            return None

        if not context.validate_path:
            return None

        self._emit_progress("validation_started")

        try:
            from ..validation.unified_validator import UnifiedValidator

            validator_config = self.config.get("validation", {})
            validator = UnifiedValidator(validator_config)

            # 获取或构建数据库路径
            db_path = self._get_database_path(context)

            validation_result = validator.semantic_validator.validate_codeql_query(
                query_path=result.output_path,
                database_path=db_path,
                target_path=context.validate_path
            )

            success = getattr(validation_result, "success", False)
            self._emit_progress(
                "validation_completed",
                success=success,
                bugs_found=len(getattr(validation_result, "diagnostics", []) or []),
                output_path=result.output_path,
            )

            return validation_result

        except Exception as e:
            logger.exception(f"[CodeQL] 验证失败: {e}")
            self._emit_progress("validation_failed", error=str(e))
            return None

    def _setup_tool_work_dirs(self, work_dir: str, validate_path: Optional[str] = None):
        """设置工具的工作目录"""
        if not self._tool_registry:
            return

        # 设置 write_file 工具的工作目录
        write_tool = self._tool_registry.get("write_file")
        if write_tool and hasattr(write_tool, "set_work_dir"):
            write_tool.set_work_dir(work_dir)

        # 设置 codeql_analyze 工具的工作目录
        codeql_tool = self._tool_registry.get("codeql_analyze")
        if codeql_tool and hasattr(codeql_tool, "set_work_dir"):
            codeql_tool.set_work_dir(work_dir)
            if validate_path and hasattr(codeql_tool, "set_target_path"):
                codeql_tool.set_target_path(validate_path)

        review_tool = self._tool_registry.get("review_artifact")
        if review_tool and hasattr(review_tool, "set_work_dir"):
            review_tool.set_work_dir(work_dir)

    def _get_database_path(self, context: AnalyzerContext) -> str:
        """获取 CodeQL 数据库路径"""
        codeql_config = self.config.get("codeql", {})

        # 优先使用配置的数据库路径
        db_base = codeql_config.get("database_path", "./codeql_dbs")

        if context.output_dir:
            # 在输出目录下创建数据库
            output_root = Path(context.output_dir).resolve()
            target_name = ""
            if context.validate_path:
                target_name = Path(context.validate_path).resolve().stem

            safe_name = re.sub(
                r"[^0-9A-Za-z_]+", "_", target_name
            ).strip("_") or "default"

            return str((output_root / "codeql" / "database" / f"{safe_name}_cpp").resolve())

        return db_base

    def _infer_vulnerability_type(
        self,
        shared_analysis: Dict[str, Any],
        patch_path: str
    ) -> str:
        """
        推断漏洞类型

        优先使用共享分析结果，否则从补丁内容推断
        """
        if shared_analysis:
            strategy = shared_analysis.get("detection_strategy", {}) or {}
            primary = normalize_vulnerability_type(str(strategy.get("primary_pattern", "") or ""), default="unknown")
            if primary in self.SUPPORTED_VULN_TYPES:
                return primary

            patterns = shared_analysis.get("vulnerability_patterns", [])
            if patterns:
                first = patterns[0] if isinstance(patterns[0], dict) else {}
                pattern_type = normalize_vulnerability_type(first.get("type") or "", default="unknown")
                if pattern_type in self.SUPPORTED_VULN_TYPES:
                    return pattern_type

        return "unknown"

    def _build_extra_context(self, shared_analysis: Dict[str, Any]) -> str:
        """构建额外上下文"""
        base_context = super()._build_extra_context(shared_analysis)

        if not shared_analysis:
            return base_context

        lines = [base_context] if base_context else []

        # 添加 CodeQL 特定的上下文
        vuln_type = self._infer_vulnerability_type(shared_analysis, "")
        if vuln_type and vuln_type != "unknown":
            lines.append(f"- 推断漏洞类型: {vuln_type}")
        else:
            lines.append("- 漏洞类型暂不确定: 不要根据 patch 关键词强行贴具体标签，应围绕 PATCHWEAVER 给出的证据与语义机制生成自定义查询。")
        lines.append("- CodeQL 生成约束: 使用可复用谓词、AST/数据流关系和 analyzer-native 语义，不要退化成 API 名称或关键词匹配。")
        lines.append("- CodeQL barrier 约束: guard/barrier 必须绑定到同一调用、同一参数或同一关键变量关系，不能因为附近出现任意 if/比较就整体静默。")
        lines.append("- CodeQL 泛化要求: 允许以 patch 为语义锚点，但最终查询必须覆盖同类别漏洞，而不是只命中 patch 点位。")
        lines.append("- CodeQL 结构要求: 保持单个最终 `from ... where ... select ...`，语法修复只改报错核心片段。")
        lines.append("- CodeQL 知识来源: 漏洞族特定谓词、source/sink/barrier 语义应优先从高相关知识库结果中补齐。")

        return "\n".join(lines)
