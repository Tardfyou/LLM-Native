"""
CSA (Clang Static Analyzer) 分析器

封装 CSA 检测器生成逻辑，包括:
- 智能体初始化
- 检测器代码生成
- 编译验证
- 语义验证
"""

from typing import Dict, Any, Optional, Callable, Tuple
from pathlib import Path
import os
import time

from loguru import logger

from .analyzer_base import (
    BaseAnalyzer,
    AnalyzerType,
    AnalyzerDescriptor,
    AnalyzerContext,
    AnalyzerResult,
    AnalyzerRegistry
)


@AnalyzerRegistry.register(AnalyzerType.CSA)
class CSAAnalyzer(BaseAnalyzer):
    """
    CSA (Clang Static Analyzer) 分析器

    生成 Clang-18 静态分析检测器插件 (.so 文件)
    """

    DESCRIPTOR = AnalyzerDescriptor(
        id="csa",
        name="CSA (Clang Static Analyzer)",
        description="路径敏感，擅长 C/C++ 内存与状态错误（UAF、空指针、越界等）。",
        best_for=["use_after_free", "null_dereference", "buffer_overflow", "double_free"],
        evidence_types=["patch_fact", "semantic_slice", "path_guard", "state_transition", "allocation_lifecycle"],
        detector_artifacts=["checker_plugin", "shared_object"],
        strengths=["path_sensitive", "stateful", "lifecycle_reasoning"],
        validation_modes=["compile", "semantic"],
    )

    @property
    def analyzer_type(self) -> AnalyzerType:
        return AnalyzerType.CSA

    @property
    def name(self) -> str:
        return "CSA (Clang Static Analyzer)"

    def _do_initialize(self):
        """初始化工具注册中心；生成智能体延迟到 generate 路径再创建。"""
        from ..tools import ToolProviderOptions, build_tool_registry

        self._tool_registry = build_tool_registry(
            config=self.config,
            options=ToolProviderOptions(
                analyzer="csa",
                include_codeql=False,
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

        logger.info(f"[CSA] 分析器初始化完成")

    def _ensure_generate_agent(self):
        if self._agent is not None:
            return

        from ..generate import LangChainGenerateAgent

        self._agent = LangChainGenerateAgent(
            tool_registry=self._tool_registry,
            config=getattr(self, "_generate_agent_config", dict(self.config.get("agent", {}))),
            analyzer="csa",
            progress_callback=self._wrap_agent_progress,
            llm_override=self._llm_client,
        )

    def _wrap_agent_progress(self, data: Dict[str, Any]):
        """包装智能体进度事件，添加分析器标识"""
        if self.progress_callback:
            # 将智能体事件转换为分析器事件
            event = data.get("event", "")
            self._emit_progress(
                f"agent_{event}",
                **{k: v for k, v in data.items() if k != "event"}
            )

    def generate(self, context: AnalyzerContext) -> AnalyzerResult:
        """
        生成 CSA 检测器

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
        self._setup_tool_work_dirs(work_dir)

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

        try:
            result = self.synthesize_detector(
                context=context,
                evidence_bundle=evidence_bundle,
                synthesis_input=synthesis_input,
            )
            result.execution_time = time.time() - start_time

            self._emit_progress(
                "generation_completed",
                success=result.success,
                checker_name=result.checker_name,
                iterations=result.iterations,
                output_path=result.output_path,
            )

            return result

        except Exception as e:
            logger.exception(f"[CSA] 生成失败: {e}")
            self._emit_progress("generation_failed", error=str(e))

            return AnalyzerResult(
                analyzer_type=AnalyzerType.CSA,
                success=False,
                error_message=str(e),
                execution_time=time.time() - start_time
            )

    def collect_evidence(self, context: AnalyzerContext, plan: Optional[Dict[str, Any]] = None):
        from ..evidence.collectors.csa_path import CSAPathEvidenceCollector
        return self._collect_patchweaver_evidence(
            context,
            analyzer_id=AnalyzerType.CSA,
            analyzer_collector=CSAPathEvidenceCollector(),
        )

    def synthesize_detector(
        self,
        context: AnalyzerContext,
        evidence_bundle,
        synthesis_input,
    ) -> AnalyzerResult:
        self._ensure_initialized()
        work_dir = self._create_work_dir(context.output_dir)
        self._setup_tool_work_dirs(work_dir)
        from ..evidence.normalizer import EvidenceNormalizer

        self._ensure_generate_agent()
        from ..generate import GenerationRequest

        agent_result = self._agent.run(
            GenerationRequest(
                analyzer="csa",
                patch_path=context.patch_path,
                work_dir=work_dir,
                validate_path=context.validate_path or "",
                max_iterations=int((self.config.get("agent", {}) or {}).get("max_iterations", 12) or 12),
            )
        )
        review_result = self._review_generated_artifact(
            analyzer_id=AnalyzerType.CSA,
            work_dir=work_dir,
            checker_name=agent_result.checker_name,
            checker_code=agent_result.checker_code,
            review_mode="generate",
        )

        slice_metrics = EvidenceNormalizer.slice_metrics(evidence_bundle, analyzer="csa")
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
                    analyzer="csa",
                    findings=review_metadata["findings"],
                    error=final_error,
                )

        return AnalyzerResult(
            analyzer_type=AnalyzerType.CSA,
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
                "structural_seed": {
                    "enabled": False,
                    "reason": "generate_stage_seed_bootstrap_disabled",
                },
            },
        )

    def _build_structural_seed_block(
        self,
        context: AnalyzerContext,
        synthesis_input,
    ) -> Tuple[str, Dict[str, Any], str]:
        patch_path = str(getattr(context, "patch_path", "") or "").strip()
        if not patch_path:
            return "", {"enabled": False, "reason": "missing_patch_path"}, ""

        try:
            patch_text = Path(patch_path).read_text(encoding="utf-8")
        except Exception:
            return "", {"enabled": False, "reason": "patch_read_failed", "patch_path": patch_path}, ""

        try:
            from ..refine.csa_structural import build_csa_structural_candidate
            from ..refine.structural.csa import infer_csa_structural_family
        except Exception:
            return "", {"enabled": False, "reason": "structural_module_unavailable"}, ""

        candidate = str(build_csa_structural_candidate("", patch_text) or "").strip()
        if not candidate:
            return "", {"enabled": False, "reason": "empty_candidate"}, ""

        family = str(infer_csa_structural_family("", patch_text) or "").strip()
        primary_pattern = str(getattr(synthesis_input, "primary_pattern", "") or "").strip()
        lines = [
            "## 建议初始工件（结构化候选）",
            "- 这是一份基于补丁机制自动生成的 CSA 起始 checker。",
            "- 目标：首版落盘直接使用该候选，再在同一路径上通过 apply_patch 做增量修复，不要反复整文件重写。",
            f"- structural_seed_length: {len(candidate)}",
        ]
        if family:
            lines.append(f"- inferred_family: {family}")
        if primary_pattern:
            lines.append(f"- synthesis_primary_pattern: {primary_pattern}")
        if len(candidate) <= 4000:
            lines.extend(
                [
                    "```cpp",
                    candidate,
                    "```",
                ]
            )
        else:
            lines.append("- 结构化候选会通过 `initial_artifact_code` 直接预置到工作区；为避免重复占用上下文，这里不再内联全文。")

        return "\n".join(lines), {
            "enabled": True,
            "family": family,
            "primary_pattern": primary_pattern,
            "candidate_length": len(candidate),
            "embedded_in_context": len(candidate) <= 4000,
        }, candidate

    def _extract_checker_name_from_code(self, code: str) -> str:
        text = str(code or "")
        if not text:
            return ""
        import re

        match = re.search(r"class\s+([A-Za-z_]\w*)\s*:\s*public\s+Checker<", text)
        if not match:
            return ""
        return str(match.group(1) or "").strip()

    def refine(
        self,
        context: AnalyzerContext,
        artifact,
        baseline_result: AnalyzerResult,
    ) -> AnalyzerResult:
        """Refine an existing CSA checker with the LangChain-based agent."""
        self._ensure_initialized()
        start_time = time.time()
        self._emit_progress("generation_started")

        work_dir = self._create_work_dir(context.output_dir)
        self._setup_tool_work_dirs(work_dir)

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
                analyzer_type=AnalyzerType.CSA,
                success=False,
                error_message="缺少可精炼的 CSA 源文件路径",
            )

        staged_target = self._stage_refinement_artifact(
            source_path=refinement_baseline_path,
            work_dir=work_dir,
        )

        from ..evidence.normalizer import EvidenceNormalizer
        from ..refine import LangChainRefinementAgent, RefinementRequest

        refine_agent = LangChainRefinementAgent(
            config=self.config,
            tool_registry=self._tool_registry,
            analyzer="csa",
            progress_callback=self._wrap_agent_progress,
            llm_override=None,
        )
        agent_result = refine_agent.run(
            RefinementRequest(
                analyzer="csa",
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
            analyzer_id=AnalyzerType.CSA,
            work_dir=work_dir,
            checker_name=agent_result.checker_name,
            checker_code=agent_result.checker_code,
            review_mode="refine",
        )

        slice_metrics = EvidenceNormalizer.slice_metrics(evidence_bundle, analyzer="csa")
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
                    analyzer="csa",
                    findings=review_metadata["findings"],
                    error=final_error,
                )

        compiled_output_path = str(agent_result.output_path or "").strip()
        compile_attempts = int(agent_result.compile_attempts or 0)
        if final_success:
            compiled_output_path, extra_compile_attempts, compile_error = self._ensure_shared_object_output(
                checker_name=agent_result.checker_name,
                checker_code=agent_result.checker_code,
                work_dir=work_dir,
                current_output_path=compiled_output_path,
            )
            compile_attempts += extra_compile_attempts
            if compile_error:
                final_success = False
                final_error = compile_error

        result = AnalyzerResult(
            analyzer_type=AnalyzerType.CSA,
            success=final_success,
            checker_name=agent_result.checker_name,
            checker_code=agent_result.checker_code,
            output_path=compiled_output_path,
            iterations=agent_result.iterations,
            compile_attempts=compile_attempts,
            error_message=final_error,
            execution_time=time.time() - start_time,
            metadata={
                "work_dir": work_dir,
                "patch_path": context.patch_path,
                "refinement_target_path": staged_target,
                "baseline_source_path": str(getattr(artifact, "source_path", "") or ""),
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
        验证 CSA 检测器

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

            validation_result = validator.semantic_validator.validate_csa_checker(
                checker_so_path=result.output_path,
                checker_name=f"custom.{result.checker_name}",
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
            logger.exception(f"[CSA] 验证失败: {e}")
            self._emit_progress("validation_failed", error=str(e))
            return None

    def _setup_tool_work_dirs(self, work_dir: str):
        """设置工具的工作目录"""
        if not self._tool_registry:
            return

        # 设置 write_file 工具的工作目录
        write_tool = self._tool_registry.get("write_file")
        if write_tool and hasattr(write_tool, "set_work_dir"):
            write_tool.set_work_dir(work_dir)

        # 设置 compile_checker 工具的工作目录
        compile_tool = self._tool_registry.get("compile_checker")
        if compile_tool and hasattr(compile_tool, "set_work_dir"):
            compile_tool.set_work_dir(work_dir)

        # 设置 lsp_validate 工具的工作目录
        lsp_tool = self._tool_registry.get("lsp_validate")
        if lsp_tool and hasattr(lsp_tool, "set_work_dir"):
            lsp_tool.set_work_dir(work_dir)

        review_tool = self._tool_registry.get("review_artifact")
        if review_tool and hasattr(review_tool, "set_work_dir"):
            review_tool.set_work_dir(work_dir)

    def _ensure_shared_object_output(
        self,
        checker_name: str,
        checker_code: str,
        work_dir: str,
        current_output_path: str,
    ) -> Tuple[str, int, str]:
        resolved_output = str(current_output_path or "").strip()
        if resolved_output.endswith(".so") and Path(resolved_output).exists():
            return resolved_output, 0, ""

        if not checker_code.strip():
            return resolved_output, 0, "缺少可编译的 checker 源码，无法生成 .so"

        if not self._tool_registry or not self._tool_registry.has("compile_checker"):
            return resolved_output, 0, "未注册 compile_checker，无法为 refine 候选生成 .so"

        compile_tool = self._tool_registry.get("compile_checker")
        compile_result = compile_tool.execute(
            checker_name=checker_name or "BufferOverflowChecker",
            source_code=checker_code,
            output_dir=work_dir,
        )
        if not compile_result.success:
            details = str(compile_result.error or compile_result.output or "编译 refine 候选失败").strip()
            return "", 1, details

        output_file = str((compile_result.metadata or {}).get("output_file", "") or "").strip()
        if not output_file or not Path(output_file).exists():
            return "", 1, "compile_checker 未返回有效的 .so 输出路径"
        return output_file, 1, ""
