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
        evidence_types=["patch_fact", "semantic_slice", "dataflow_candidate", "call_chain"],
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

        from .evidence_schema import EvidenceBundle

        evidence_bundle = EvidenceBundle()
        synthesis_input = self.build_synthesis_input(context, evidence_bundle)
        self._emit_progress(
            "evidence_loaded",
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
                "generation_agent": {
                    "final_message": agent_result.final_message,
                    "tool_history": agent_result.metadata.get("tool_history", []),
                    "notes": agent_result.metadata.get("notes", []),
                    "plan": agent_result.metadata.get("plan", {}),
                    "rag_match": agent_result.metadata.get("rag_match", False),
                    "rag_check_result": agent_result.metadata.get("rag_check_result", ""),
                    "llm_usage": agent_result.metadata.get("llm_usage", {}),
                    "llm_usage_by_phase": agent_result.metadata.get("llm_usage_by_phase", {}),
                },
                "llm_usage": agent_result.metadata.get("llm_usage", {}),
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

        evidence_bundle = self.restore_refinement_evidence_bundle(context)
        synthesis_input = self.build_synthesis_input(context, evidence_bundle)
        self._emit_progress(
            "evidence_loaded",
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
                evidence_dir=context.evidence_dir or "",
                evidence_bundle_raw=context.evidence_bundle_raw if isinstance(context.evidence_bundle_raw, dict) else {},
                baseline_validation_summary=str((baseline_result.metadata or {}).get("baseline_validation_summary", "") or ""),
                checker_name=Path(staged_target).stem,
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
                "baseline_source_path": str(getattr(artifact, "source_path", "") or ""),
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
                    "model_requested_stop": bool(agent_result.metadata.get("model_requested_stop", False)),
                    "last_decision_action": str(agent_result.metadata.get("last_decision_action", "") or ""),
                    "last_repair_action": str(agent_result.metadata.get("last_repair_action", "") or ""),
                    "llm_usage": agent_result.metadata.get("llm_usage", {}),
                    "llm_usage_by_phase": agent_result.metadata.get("llm_usage_by_phase", {}),
                },
                "llm_usage": agent_result.metadata.get("llm_usage", {}),
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
