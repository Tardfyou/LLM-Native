"""
核心编排器 - 协调分析器完成检测器生成

新架构:
- 模块化分析器设计 (CSA, CodeQL)
- both 模式并行执行
- 实时表格显示

工作流程:
1. 分析补丁，识别漏洞特征
2. 选择分析工具 (CSA/CodeQL/both)
3. 单分析器或并行执行
4. 验证检测器效果
5. 保存结果
"""

import json
import time
import shutil
import re
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable

from loguru import logger

from ..llm.usage import merge_usages, normalize_usage
from ..prompts import PromptRepository
from .analyzer_base import (
    AnalyzerResult,
    AnalyzerContext,
    normalize_analyzer_id,
)
from .analyzer_manager import AnalyzerManager
from .portfolio_controller import PortfolioController
from ..validation.types import AnalyzerType, Diagnostic, ValidationResult, ValidationStage


@dataclass
class GenerationResult:
    """生成结果"""
    success: bool = False
    generation_success: bool = False
    semantic_success: bool = False
    checker_name: str = ""
    checker_code: str = ""
    output_path: str = ""
    total_iterations: int = 0
    repair_iterations: int = 0
    error_message: str = ""
    analyzer_type: str = "csa"
    analyzer_results: Dict[str, Any] = field(default_factory=dict)
    analyzer_artifacts: Dict[str, Any] = field(default_factory=dict)
    validation_result: Any = None
    shared_analysis: Dict[str, Any] = field(default_factory=dict)
    portfolio_decision: Dict[str, Any] = field(default_factory=dict)
    workflow_mode: str = "generate"
    patch_path: str = ""
    validate_path: str = ""
    run_metrics: Dict[str, Any] = field(default_factory=dict)
    report_output_dir: str = ""
    analyzer_output_dirs: Dict[str, str] = field(default_factory=dict)


@dataclass
class EvidenceCollectionResult:
    """独立证据收集结果。"""

    success: bool = False
    patch_path: str = ""
    evidence_dir: str = ""
    output_dir: str = ""
    analyzer_type: str = ""
    error_message: str = ""
    shared_analysis: Dict[str, Any] = field(default_factory=dict)
    analyzer_results: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)


class Orchestrator:
    """
    检测器生成编排器

    协调分析器完成从补丁到检测器的完整生成流程。
    支持 CSA、CodeQL 单独或并行执行。
    """

    def __init__(
        self,
        config_path: str = None,
        analyzer: str = "auto"
    ):
        """
        初始化编排器

        Args:
            config_path: 配置文件路径
            analyzer: 分析器类型 (csa/codeql/both/auto)
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.analyzer = analyzer

        # 延迟初始化组件
        self._llm_client = None
        self._analyzer_manager = None
        self._prompt_repository = PromptRepository(config=self.config)
        self._initialized = False

    def _load_config(self) -> Dict[str, Any]:
        """加载配置"""
        if self.config_path and Path(self.config_path).exists():
            from ..utils import load_config
            return load_config(self.config_path)

        # 默认配置
        return {
            "llm": {
                "primary_model": "deepseek-chat",
                "temperature": 0.3
            },
            "agent": {
                "max_iterations": 30,
                "verbose": True
            },
            "patchweaver": {
                "enabled": True,
                "preflight_analysis": True,
            },
            "validation": {
                "semantic": {
                    "timeout": 120,
                    "codeql_auto_create_db": True,
                },
            }
        }

    def _ensure_initialized(self):
        """确保组件已初始化"""
        if self._initialized:
            return

        from ..llm import get_llm_client

        # 初始化 LLM
        self._llm_client = get_llm_client(self.config.get("llm", {}))
        self._analyzer_manager = AnalyzerManager(
            config=self.config,
            llm_client=self._llm_client,
        )

        self._initialized = True

    def generate(
        self,
        patch_path: str,
        output_dir: str = None,
        validate_path: str = None,
        on_progress: Callable = None
    ) -> GenerationResult:
        """
        生成检测器

        Args:
            patch_path: 补丁文件路径
            output_dir: 输出目录
            validate_path: 验证路径
            on_progress: 进度回调

        Returns:
            GenerationResult
        """
        self._ensure_initialized()

        start_time = time.time()
        result = GenerationResult()
        result.workflow_mode = "generate"
        result.patch_path = patch_path
        result.validate_path = validate_path

        try:
            # 1. 选择分析器
            analyzer_choice = self._select_analyzer(patch_path)
            result.analyzer_type = analyzer_choice
            selected_analyzers = self._resolve_analyzers(analyzer_choice)

            logger.info(f"选择分析器: {analyzer_choice}")

            # 2. PATCHWEAVER 共享分析上下文（generate 默认关闭，避免与独立 evidence 收集重复）
            if self._is_generate_preflight_enabled():
                if on_progress:
                    on_progress({
                        "analyzer": "patchweaver",
                        "event": "preflight_started",
                        "timestamp": time.time(),
                    })
                shared_analysis = self._analyze_patch_shared(
                    patch_path=patch_path,
                    selected_analyzers=selected_analyzers,
                )
                result.shared_analysis = shared_analysis
                if on_progress:
                    patchweaver = shared_analysis.get("patchweaver", {})
                    plan = patchweaver.get("evidence_plan", {}) if isinstance(patchweaver, dict) else {}
                    on_progress({
                        "analyzer": "patchweaver",
                        "event": "preflight_completed",
                        "timestamp": time.time(),
                        "summary": patchweaver.get("summary", ""),
                        "planned_evidence": len(plan.get("requirements", []) or []),
                    })
            else:
                shared_analysis = {}
                result.shared_analysis = {}
                if on_progress:
                    on_progress({
                        "analyzer": "patchweaver",
                        "event": "preflight_skipped",
                        "timestamp": time.time(),
                        "reason": "generate_preflight_disabled",
                    })

            # 3. 执行生成
            if len(selected_analyzers) > 1:
                # 并行执行
                multi_results = self._run_parallel_multi(
                    analyzers=selected_analyzers,
                    patch_path=patch_path,
                    output_dir=output_dir,
                    validate_path=validate_path,
                    shared_analysis=shared_analysis,
                    on_progress=on_progress,
                )
                self._fill_result_from_multi(
                    result,
                    multi_results,
                    selected_analyzers,
                )
            else:
                # 单分析器执行
                analyzer_result = self._run_single(
                    selected_analyzers[0], patch_path, output_dir,
                    validate_path, shared_analysis, on_progress,
                    suppress_output=False,
                )
                self._fill_result_from_single(
                    result,
                    analyzer_result,
                )

            if on_progress and result.portfolio_decision:
                on_progress({
                    "analyzer": "patchweaver",
                    "event": "portfolio_resolved",
                    "timestamp": time.time(),
                    "preferred_analyzer": result.portfolio_decision.get("preferred_analyzer", ""),
                    "confidence": result.portfolio_decision.get("confidence", ""),
                    "summary": result.portfolio_decision.get("summary", ""),
                })

        except Exception as e:
            logger.exception("生成过程出错")
            result.success = False
            result.error_message = str(e)

        return result

    def collect_evidence(
        self,
        patch_path: str,
        evidence_dir: str,
        output_dir: str = None,
        analyzer: str = None,
        on_progress: Callable = None,
    ) -> EvidenceCollectionResult:
        """独立执行证据收集并落盘。"""
        from .refinement_session import (
            EVIDENCE_INPUT_MANIFEST,
            EVIDENCE_INPUT_SCHEMA_VERSION,
        )

        self._ensure_initialized()

        patch_path = str(Path(patch_path).expanduser().resolve())
        evidence_dir = str(Path(evidence_dir).expanduser().resolve())
        output_root = Path(output_dir or "./evidence_output").expanduser().resolve()
        output_root.mkdir(parents=True, exist_ok=True)

        result = EvidenceCollectionResult(
            patch_path=patch_path,
            evidence_dir=evidence_dir,
            output_dir=str(output_root),
        )

        try:
            analyzer_choice = analyzer or self._select_analyzer(patch_path)
            selected_analyzers = self._resolve_analyzers(analyzer_choice)
            result.analyzer_type = (
                ",".join(selected_analyzers)
                if len(selected_analyzers) > 1
                else (selected_analyzers[0] if selected_analyzers else "")
            )

            shared_analysis = self._analyze_patch_shared(
                patch_path=patch_path,
                selected_analyzers=selected_analyzers,
            )
            result.shared_analysis = shared_analysis

            patchweaver_path = output_root / "patchweaver_plan.json"
            patchweaver_path.write_text(
                json.dumps(copy.deepcopy(shared_analysis or {}), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            result.artifacts["patchweaver_plan"] = str(patchweaver_path)

            manifest: Dict[str, Any] = {
                "schema_version": EVIDENCE_INPUT_SCHEMA_VERSION,
                "patch_path": patch_path,
                "evidence_dir": evidence_dir,
                "analyzer_choice": result.analyzer_type,
                "shared_analysis_path": self._manifest_relpath(output_root, str(patchweaver_path)),
                "artifacts": {},
            }

            for analyzer_id in selected_analyzers:
                analyzer_output_dir = (output_root / analyzer_id).resolve()
                analyzer_output_dir.mkdir(parents=True, exist_ok=True)
                if on_progress:
                    on_progress({
                        "analyzer": analyzer_id,
                        "event": "evidence_collection_started",
                        "timestamp": time.time(),
                    })

                context = AnalyzerContext(
                    patch_path=patch_path,
                    output_dir=str(analyzer_output_dir),
                    evidence_dir=evidence_dir,
                    shared_analysis=copy.deepcopy(shared_analysis or {}),
                )
                analyzer_instance = self._create_analyzer(
                    analyzer_type=analyzer_id,
                    progress_callback=on_progress,
                    suppress_output=True,
                )
                evidence_bundle = analyzer_instance.collect_evidence(context)
                synthesis_input = analyzer_instance.build_synthesis_input(context, evidence_bundle)

                evidence_bundle_path = analyzer_output_dir / "evidence_bundle.json"
                evidence_bundle_path.write_text(
                    json.dumps(evidence_bundle.to_dict(), indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                synthesis_input_path = analyzer_output_dir / "synthesis_input.json"
                synthesis_input_path.write_text(
                    json.dumps(synthesis_input.to_dict(), indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

                analyzer_report = {
                    "success": True,
                    "evidence_records": len(getattr(evidence_bundle, "records", []) or []),
                    "missing_evidence": list(getattr(evidence_bundle, "missing_evidence", []) or []),
                    "collected_analyzers": list(getattr(evidence_bundle, "collected_analyzers", []) or []),
                    "evidence_bundle_path": str(evidence_bundle_path),
                    "synthesis_input_path": str(synthesis_input_path),
                }
                result.analyzer_results[analyzer_id] = analyzer_report
                manifest["artifacts"][analyzer_id] = {
                    "analyzer_id": analyzer_id,
                    "evidence_bundle_path": self._manifest_relpath(output_root, str(evidence_bundle_path)),
                    "synthesis_input_path": self._manifest_relpath(output_root, str(synthesis_input_path)),
                    "report_entry": copy.deepcopy(analyzer_report),
                }

                if on_progress:
                    on_progress({
                        "analyzer": analyzer_id,
                        "event": "evidence_collection_completed",
                        "timestamp": time.time(),
                        "records": analyzer_report["evidence_records"],
                        "missing": len(analyzer_report["missing_evidence"]),
                    })

            manifest_path = output_root / EVIDENCE_INPUT_MANIFEST
            manifest_path.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            result.artifacts["manifest"] = str(manifest_path)
            result.success = bool(result.analyzer_results)
            return result
        except Exception as exc:
            logger.exception("证据收集过程出错")
            result.success = False
            result.error_message = str(exc)
            return result

    def refine(
        self,
        input_dir: str,
        validate_path: str = None,
        patch_path: str = None,
        evidence_input_dir: str = None,
        analyzer: str = None,
        on_progress: Callable = None,
        run_id: str = None,
    ) -> GenerationResult:
        """
        基于既有输出目录执行纯精炼。

        Args:
            input_dir: generate 阶段输出目录
            validate_path: 可选，验证路径
            patch_path: 可选，显式覆盖原始补丁路径
            evidence_input_dir: 可选，独立 evidence 收集输出目录
            analyzer: 可选，限制需要执行的分析器
            on_progress: 进度回调

        Returns:
            GenerationResult
        """
        from .refinement_session import RefinementSessionLoader

        self._ensure_initialized()

        loader = RefinementSessionLoader()
        session = loader.load(
            input_dir=input_dir,
            patch_path_override=patch_path,
            evidence_input_dir=evidence_input_dir,
        )
        effective_validate_path = validate_path or session.validate_path or ""
        normalized_run_id = self._normalize_refinement_run_id(run_id)
        report_output_dir = self._build_refinement_report_output_dir(input_dir, normalized_run_id)
        Path(report_output_dir).mkdir(parents=True, exist_ok=True)

        result = GenerationResult(
            workflow_mode="refine",
            patch_path=session.patch_path,
            validate_path=effective_validate_path,
            report_output_dir=report_output_dir,
        )

        requested = analyzer or session.analyzer_choice
        requested_analyzers = self._resolve_analyzers(requested)
        available_analyzers = list(session.artifacts.keys())
        selected_analyzers = [
            item
            for item in requested_analyzers
            if item in session.artifacts
        ]
        skipped_analyzers = [
            item
            for item in requested_analyzers
            if item not in session.artifacts
        ]

        for analyzer_id in skipped_analyzers:
            if on_progress:
                on_progress({
                    "analyzer": analyzer_id,
                    "event": "refinement_analyzer_skipped",
                    "timestamp": time.time(),
                    "reason": "artifact_missing",
                })

        explicit_request = bool(analyzer and str(analyzer).strip())
        if explicit_request and not selected_analyzers:
            result.success = True
            result.generation_success = True
            result.analyzer_type = ""
            skip_summary = (
                "请求的分析器产物不存在，已跳过精炼: "
                + ", ".join(skipped_analyzers or requested_analyzers)
            )
            result.portfolio_decision = {
                "summary": skip_summary,
            }
            return result

        if not selected_analyzers:
            selected_analyzers = available_analyzers

        result.analyzer_type = ",".join(selected_analyzers) if len(selected_analyzers) > 1 else selected_analyzers[0]
        result.shared_analysis = self._build_refinement_shared_analysis(
            base_shared_analysis=session.shared_analysis,
            session=session,
            selected_analyzers=selected_analyzers,
        )

        analyzer_results: Dict[str, AnalyzerResult] = {}
        try:
            for analyzer_id in selected_analyzers:
                analyzer_output_dir = self._build_refinement_analyzer_output_dir(
                    input_dir=input_dir,
                    analyzer_id=analyzer_id,
                    run_id=normalized_run_id,
                )
                Path(analyzer_output_dir).mkdir(parents=True, exist_ok=True)
                result.analyzer_output_dirs[analyzer_id] = analyzer_output_dir
                analyzer_results[analyzer_id] = self._refine_single_from_saved_artifact(
                    analyzer_type=analyzer_id,
                    artifact=session.artifacts[analyzer_id],
                    patch_path=session.patch_path,
                    output_dir=analyzer_output_dir,
                    validate_path=effective_validate_path,
                    evidence_dir=session.evidence_dir,
                    shared_analysis=result.shared_analysis,
                    on_progress=on_progress,
                )
        except Exception as exc:
            logger.exception("精炼过程出错")
            result.success = False
            result.error_message = str(exc)
            return result

        if len(selected_analyzers) > 1:
            self._fill_result_from_multi(
                result,
                analyzer_results,
                selected_analyzers,
            )
        else:
            self._fill_result_from_single(
                result,
                analyzer_results[selected_analyzers[0]],
            )

        return result

    def _normalize_refinement_run_id(self, run_id: Optional[str]) -> str:
        token = str(run_id or "").strip()
        if token:
            return token
        return time.strftime("%Y%m%d_%H%M%S")

    def _build_refinement_report_output_dir(
        self,
        input_dir: str,
        run_id: str,
    ) -> str:
        base_dir = Path(input_dir).expanduser().resolve()
        return str(base_dir / "refinements" / run_id)

    def _build_refinement_analyzer_output_dir(
        self,
        input_dir: str,
        analyzer_id: str,
        run_id: str,
    ) -> str:
        base_dir = Path(input_dir).expanduser().resolve()
        normalized_analyzer = normalize_analyzer_id(analyzer_id)
        return str(base_dir / normalized_analyzer / "refinements" / run_id / normalized_analyzer)

    def _resolve_analyzers(self, analyzer_choice: str) -> List[str]:
        """解析分析器选择字符串，返回去重后的分析器列表。"""
        if not analyzer_choice:
            return ["csa"]

        choice = str(analyzer_choice).lower().strip()

        if choice in {"both", "all"}:
            return ["csa", "codeql"]

        # 支持 csa,codeql / csa+codeql / csa|codeql / csa codeql
        tokens = [t.strip() for t in re.split(r"[,+|\s]+", choice) if t.strip()]

        resolved: List[str] = []
        for token in tokens:
            if token in {"both", "all"}:
                for a in ("csa", "codeql"):
                    if a not in resolved:
                        resolved.append(a)
            elif token == "auto":
                continue
            elif token not in resolved:
                resolved.append(token)

        return resolved or ["csa"]

    def _select_analyzer(self, patch_path: str) -> str:
        """选择分析器"""
        if self.analyzer != "auto":
            return self.analyzer

        # auto 模式：由模型根据“可选分析器列表+说明”返回选用清单
        try:
            self._ensure_initialized()

            with open(patch_path, 'r', encoding='utf-8') as f:
                patch_content = f.read()

            catalog = self._get_analyzer_catalog()
            selected = self._select_analyzers_with_model(
                patch_content=patch_content,
                catalog=catalog,
            )
            if selected:
                return ",".join(selected)

            fallback = [item["id"] for item in catalog if item.get("id")]
            if fallback:
                logger.warning("模型未返回有效分析器清单，回退为全量可用分析器")
                return ",".join(fallback)
        except Exception as e:
            logger.warning(f"auto 选择失败: {e}，回退为全量可用分析器")

        # 最终兜底
        available = self._list_available_analyzer_ids()
        return ",".join(available) if available else "csa"

    def _list_available_analyzer_ids(self) -> List[str]:
        """获取当前可用分析器 ID 列表（支持扩展）。"""
        if self._initialized and self._analyzer_manager is not None:
            return self._analyzer_manager.list_available_ids()
        return AnalyzerManager(config=self.config).list_available_ids()

    def _get_analyzer_catalog(self) -> List[Dict[str, Any]]:
        """构建供模型选择的分析器目录（含说明）。"""
        if self._initialized and self._analyzer_manager is not None:
            return self._analyzer_manager.get_catalog()
        return AnalyzerManager(config=self.config).get_catalog()

    def _select_analyzers_with_model(
        self,
        patch_content: str,
        catalog: List[Dict[str, Any]],
    ) -> List[str]:
        """调用模型选择分析器，返回标准化后的分析器 ID 列表。"""
        allowed = [item["id"] for item in catalog if item.get("id")]
        if not allowed:
            return []

        patch_preview = (patch_content or "")
        if len(patch_preview) > 12000:
            patch_preview = patch_preview[:12000] + "\n...<truncated>"

        prompt = self._prompt_repository.render(
            "orchestrator.analyzer_selection",
            {
                "CATALOG_JSON": json.dumps(catalog, ensure_ascii=False, indent=2),
                "PATCH_PREVIEW": patch_preview,
            },
            strict=True,
        )

        response = self._llm_client.generate(
            prompt=prompt,
            temperature=0.0,
            max_tokens=8192,
        )
        if not response:
            return []

        payload = self._extract_json_object(response)
        if not payload:
            return []

        raw_selected = payload.get("selected_analyzers") or payload.get("analyzers") or []
        if isinstance(raw_selected, str):
            raw_selected = [s.strip() for s in re.split(r"[,+|\s]+", raw_selected) if s.strip()]
        if not isinstance(raw_selected, list):
            return []

        selected: List[str] = []
        for item in raw_selected:
            analyzer_id = str(item).lower().strip()
            if analyzer_id in {"all", "both"}:
                for a in allowed:
                    if a not in selected:
                        selected.append(a)
                continue
            if analyzer_id in allowed and analyzer_id not in selected:
                selected.append(analyzer_id)

        return selected

    def _extract_json_object(self, text: str) -> Dict[str, Any]:
        """从模型输出中提取 JSON 对象。"""
        if not text:
            return {}

        content = text.strip()
        try:
            obj = json.loads(content)
            return obj if isinstance(obj, dict) else {}
        except Exception:
            pass

        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            return {}

        try:
            obj = json.loads(match.group(0))
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _analyze_patch_shared(
        self,
        patch_path: str,
        selected_analyzers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """共享补丁分析"""
        patchweaver_settings = self.config.get("patchweaver", {}) or {}
        if patchweaver_settings.get("enabled", True) is False:
            return {}

        try:
            from ..tools.patch_analysis import PatchAnalysisTool
            from .evidence_planner import PatchWeaverPreflight

            tool = PatchAnalysisTool(
                llm_client=self._llm_client,
                llm_config=self.config.get("llm", {}),
                prompt_config=self.config,
            )
            analysis = tool.execute(patch_path=patch_path, analysis_depth="deep")

            if analysis.success and isinstance(analysis.metadata, dict):
                shared_analysis = dict(analysis.metadata)
                self._normalize_primary_pattern(shared_analysis, patch_path)
                patterns = shared_analysis.get("vulnerability_patterns", []) or []
                affected_functions: List[str] = [
                    str(item).strip()
                    for item in (shared_analysis.get("affected_functions", []) or [])
                    if str(item).strip()
                ]
                for item in patterns:
                    for func_name in (item.get("affected_functions", []) or []):
                        token = str(func_name).strip()
                        if token and token not in affected_functions:
                            affected_functions.append(token)
                shared_analysis["affected_functions"] = affected_functions
                shared_analysis["key_functions"] = list(shared_analysis["affected_functions"])

                if patchweaver_settings.get("preflight_analysis", True):
                    catalog = self._get_analyzer_catalog()
                    patchweaver = PatchWeaverPreflight(self.config).analyze(
                        patch_path=patch_path,
                        patch_analysis=shared_analysis,
                        analyzer_catalog=catalog,
                        selected_analyzers=selected_analyzers or [],
                    )
                    shared_analysis["patchweaver"] = patchweaver
                    if not shared_analysis.get("affected_functions"):
                        patch_functions: List[str] = []
                        for fact in patchweaver.get("patch_facts", []) or []:
                            if str(fact.get("fact_type", "")) != "affected_functions":
                                continue
                            for item in ((fact.get("attributes", {}) or {}).get("functions", []) or []):
                                token = str(item).strip()
                                if token and token not in patch_functions:
                                    patch_functions.append(token)
                        if patch_functions:
                            shared_analysis["affected_functions"] = patch_functions
                            shared_analysis["key_functions"] = list(patch_functions)
                return shared_analysis
        except Exception as e:
            logger.warning(f"共享补丁分析失败: {e}")

        return {}

    def _is_generate_preflight_enabled(self) -> bool:
        """是否在 generate 阶段启用 PATCHWEAVER preflight。"""
        patchweaver_settings = self.config.get("patchweaver", {}) or {}
        return bool(patchweaver_settings.get("generate_preflight_enabled", False))

    def _normalize_primary_pattern(
        self,
        shared_analysis: Dict[str, Any],
        patch_path: str,
    ):
        """Normalize pattern fields without overriding the patch-analysis conclusion."""
        patterns = shared_analysis.get("vulnerability_patterns", []) or []
        strategy = dict(shared_analysis.get("detection_strategy", {}) or {})
        if not strategy.get("primary_pattern"):
            if patterns and isinstance(patterns[0], dict):
                strategy["primary_pattern"] = patterns[0].get("type", "unknown")
            else:
                strategy["primary_pattern"] = "unknown"
        if not strategy.get("check_types"):
            strategy["check_types"] = [
                item.get("type", "")
                for item in patterns
                if isinstance(item, dict) and item.get("type")
            ]
        shared_analysis["detection_strategy"] = strategy

    def _run_single(
        self,
        analyzer_type: str,
        patch_path: str,
        output_dir: str,
        validate_path: str,
        shared_analysis: Dict[str, Any],
        on_progress: Callable,
        suppress_output: bool = False,
        llm_client_override=None,
    ) -> AnalyzerResult:
        """运行单个分析器"""
        current_shared_analysis = copy.deepcopy(shared_analysis or {})
        context = AnalyzerContext(
            patch_path=patch_path,
            output_dir=output_dir or "./output",
            validate_path=validate_path,
            shared_analysis=current_shared_analysis,
        )

        # 创建分析器实例
        analyzer = self._create_analyzer(
            analyzer_type=analyzer_type,
            progress_callback=on_progress,
            suppress_output=suppress_output,
            llm_client_override=llm_client_override,
        )

        # 执行生成
        result = analyzer.generate(context)
        result = self._validate_analyzer_result(
            analyzer_id=analyzer_type,
            analyzer=analyzer,
            analyzer_result=result,
            context=context,
            on_progress=on_progress,
        )
        result.metadata.setdefault(
            "shared_analysis_after_validation",
            current_shared_analysis,
        )

        return result

    def _validate_analyzer_result(
        self,
        analyzer_id: str,
        analyzer,
        analyzer_result: AnalyzerResult,
        context: AnalyzerContext,
        on_progress: Optional[Callable] = None,
    ) -> AnalyzerResult:
        """执行功能验证并回写验证反馈。"""
        analyzer_result.metadata["validation_requested"] = bool(context.validate_path)
        if not analyzer_result.success or not context.validate_path:
            return analyzer_result

        analyzer_result.validation_result = analyzer.validate(analyzer_result, context)
        analyzer_result.validation_result = self._normalize_validation_result(
            analyzer_id=analyzer_id,
            analyzer_result=analyzer_result,
        )
        feedback_status = self._attach_validation_feedback(
            analyzer_id=analyzer_id,
            analyzer_result=analyzer_result,
            context=context,
        )
        current_shared_analysis = self._augment_shared_analysis_with_validation_feedback(
            shared_analysis=context.shared_analysis,
            analyzer_result=analyzer_result,
            phase="initial_validation",
        )
        analyzer_result.metadata["shared_analysis_after_validation"] = current_shared_analysis
        self._emit_validation_feedback_attached(
            analyzer_id=analyzer_id,
            feedback_status=feedback_status,
            on_progress=on_progress,
        )
        return analyzer_result

    def _normalize_validation_result(
        self,
        analyzer_id: str,
        analyzer_result: AnalyzerResult,
    ) -> Any:
        """规范化验证结果，避免将无关诊断传播到后续报告和 refine 输入。"""
        validation_result = getattr(analyzer_result, "validation_result", None)
        if validation_result is None:
            return validation_result

        metadata = copy.deepcopy(getattr(validation_result, "metadata", {}) or {})
        diagnostics = list(getattr(validation_result, "diagnostics", []) or [])
        metadata.setdefault("all_diagnostics_count", len(diagnostics))

        if str(analyzer_id or "").strip().lower() != "csa":
            metadata.setdefault("generated_diagnostics_count", len(diagnostics))
            validation_result.metadata = metadata
            return validation_result

        checker_name = str(getattr(analyzer_result, "checker_name", "") or "").strip()
        filtered = [
            diagnostic for diagnostic in diagnostics
            if self._is_generated_diagnostic(analyzer_id, diagnostic, checker_name)
        ]
        metadata["generated_diagnostics_count"] = len(filtered)
        metadata["diagnostics_filtered"] = len(filtered) != len(diagnostics)
        validation_result.diagnostics = filtered
        validation_result.metadata = metadata
        return validation_result

    def _refine_single_from_saved_artifact(
        self,
        analyzer_type: str,
        artifact,
        patch_path: str,
        output_dir: str,
        validate_path: str,
        evidence_dir: str,
        shared_analysis: Dict[str, Any],
        on_progress: Optional[Callable] = None,
    ) -> AnalyzerResult:
        """以已生成产物为目标执行新的 LangChain refine 流程。"""
        pipeline_started_at = time.time()
        if on_progress:
            on_progress({
                "analyzer": analyzer_type,
                "event": "pipeline_started",
                "timestamp": pipeline_started_at,
            })

        try:
            baseline_shared_analysis = copy.deepcopy(shared_analysis or {})
            baseline_context = AnalyzerContext(
                patch_path=patch_path,
                output_dir=output_dir or "./output",
                validate_path=validate_path,
                evidence_dir=evidence_dir,
                evidence_bundle_raw=(
                    getattr(artifact, "evidence_bundle_raw", {}) or {}
                ) or (
                    getattr(artifact, "post_validation_evidence_bundle_raw", {}) or {}
                ),
                shared_analysis=baseline_shared_analysis,
            )
            analyzer = self._create_analyzer(
                analyzer_type=analyzer_type,
                progress_callback=on_progress,
                suppress_output=False,
            )

            result = self._rehydrate_saved_analyzer_result(
                analyzer_type=analyzer_type,
                artifact=artifact,
                validate_path=validate_path,
            )
            if getattr(result, "validation_result", None) is not None:
                result.metadata["validation_requested"] = bool(validate_path)
                result.metadata["shared_analysis_after_validation"] = self._augment_shared_analysis_with_validation_feedback(
                    shared_analysis=baseline_shared_analysis,
                    analyzer_result=result,
                    phase="baseline_reused_validation",
                )
                if on_progress:
                    on_progress({
                        "analyzer": analyzer_type,
                        "event": "baseline_validation_reused",
                        "timestamp": time.time(),
                        "diagnostics_count": len(getattr(result.validation_result, "diagnostics", []) or []),
                        "summary": str(result.metadata.get("baseline_validation_summary", "") or ""),
                    })
            else:
                result = self._validate_analyzer_result(
                    analyzer_id=analyzer_type,
                    analyzer=analyzer,
                    analyzer_result=result,
                    context=baseline_context,
                    on_progress=on_progress,
                )
            current_shared_analysis = result.metadata.get(
                "shared_analysis_after_validation",
                baseline_shared_analysis,
            )
            baseline_review = analyzer._review_baseline_artifact(
                artifact_path=str(
                    getattr(artifact, "source_path", "")
                    or getattr(artifact, "output_path", "")
                    or ""
                ).strip(),
                analyzer_id=analyzer.analyzer_type,
                review_mode="refine",
            )
            if baseline_review is not None:
                result.metadata["artifact_review"] = {
                    "success": bool(getattr(baseline_review, "success", False)),
                    "error": str(getattr(baseline_review, "error", "") or ""),
                    "findings": list((getattr(baseline_review, "metadata", {}) or {}).get("findings", []) or []),
                }
            skip_reason = self._baseline_refine_skip_reason(
                analyzer_result=result,
                review_result=baseline_review,
            )
            if skip_reason:
                result.metadata["refinement_attempted"] = False
                result.metadata["refinement_adopted"] = False
                result.metadata["refinement_iterations_attempted"] = 0
                result.metadata["refinement_skipped_reason"] = skip_reason
                result.metadata.setdefault("last_refinement_candidate_success", False)
                result.metadata.setdefault("last_refinement_candidate_error", "")
                result.metadata.setdefault("last_refinement_candidate_artifact_review", {})
                result.metadata.setdefault("last_refinement_candidate_output_path", "")
                if on_progress:
                    on_progress({
                        "analyzer": analyzer_type,
                        "event": "refinement_iteration_skipped",
                        "timestamp": time.time(),
                        "reason": skip_reason,
                    })
                    on_progress({
                        "analyzer": analyzer_type,
                        "event": "pipeline_completed",
                        "timestamp": time.time(),
                        "success": bool(result.success),
                        "execution_time": time.time() - pipeline_started_at,
                        "checker_name": str(result.checker_name or ""),
                        "output_path": str(result.output_path or ""),
                    })
                return result

            max_rounds = self._refinement_max_rounds()
            current_result = result
            current_artifact = copy.deepcopy(artifact)
            attempted_rounds = 0
            adopted_any = False
            last_candidate: Optional[AnalyzerResult] = None

            for iteration in range(1, max_rounds + 1):
                if on_progress:
                    on_progress({
                        "analyzer": analyzer_type,
                        "event": "refinement_iteration_started",
                        "timestamp": time.time(),
                        "iteration": iteration,
                        "max_iterations": max_rounds,
                    })

                refinement_shared_analysis = self._augment_shared_analysis_with_validation_feedback(
                    shared_analysis=current_shared_analysis,
                    analyzer_result=current_result,
                    phase="refine_candidate",
                )
                refinement_context = AnalyzerContext(
                    patch_path=patch_path,
                    output_dir=output_dir or "./output",
                    validate_path=validate_path,
                    evidence_dir=evidence_dir,
                    evidence_bundle_raw=(
                        getattr(current_artifact, "evidence_bundle_raw", {}) or {}
                    ) or (
                        getattr(current_artifact, "post_validation_evidence_bundle_raw", {}) or {}
                    ),
                    shared_analysis=refinement_shared_analysis,
                )
                candidate = analyzer.refine(
                    refinement_context,
                    artifact=current_artifact,
                    baseline_result=current_result,
                )
                candidate = self._validate_analyzer_result(
                    analyzer_id=analyzer_type,
                    analyzer=analyzer,
                    analyzer_result=candidate,
                    context=refinement_context,
                    on_progress=on_progress,
                )
                last_candidate = candidate
                attempted_rounds = iteration

                adopted = self._should_adopt_refinement_candidate(
                    current=current_result,
                    candidate=candidate,
                )
                model_requested_stop = self._candidate_requested_stop(candidate)
                if adopted:
                    adopted_any = True
                    current_result = candidate
                    current_shared_analysis = candidate.metadata.get(
                        "shared_analysis_after_validation",
                        refinement_shared_analysis,
                    )
                    current_artifact = self._refresh_refinement_artifact(
                        artifact=current_artifact,
                        candidate=candidate,
                    )

                if on_progress:
                    on_progress({
                        "analyzer": analyzer_type,
                        "event": "refinement_iteration_completed",
                        "timestamp": time.time(),
                        "iteration": iteration,
                        "max_iterations": max_rounds,
                        "adopted": adopted,
                        "model_requested_stop": model_requested_stop,
                        "success": candidate.success,
                    })

                # 只有当当前轮候选已被采纳且模型明确要求收束时，才允许提前结束。
                # 若候选质量不够而被拒绝，后续轮次仍应继续尝试优化基线/当前产物。
                if model_requested_stop and adopted:
                    break

            final_result = current_result
            final_result.metadata["refinement_attempted"] = attempted_rounds > 0
            final_result.metadata["refinement_adopted"] = adopted_any
            final_result.metadata["refinement_iterations_attempted"] = attempted_rounds
            final_result.metadata["refinement_skipped_reason"] = ""
            if last_candidate is not None:
                final_result.metadata["last_refinement_candidate_success"] = bool(last_candidate.success)
                final_result.metadata["last_refinement_candidate_error"] = str(last_candidate.error_message or "")
                final_result.metadata["last_refinement_candidate_artifact_review"] = (
                    (last_candidate.metadata or {}).get("artifact_review", {})
                )
                final_result.metadata["last_refinement_candidate_output_path"] = str(last_candidate.output_path or "")
            else:
                final_result.metadata.setdefault("last_refinement_candidate_success", False)
                final_result.metadata.setdefault("last_refinement_candidate_error", "")
                final_result.metadata.setdefault("last_refinement_candidate_artifact_review", {})
                final_result.metadata.setdefault("last_refinement_candidate_output_path", "")
            final_result.metadata.setdefault(
                "shared_analysis_after_validation",
                current_shared_analysis,
            )

            if on_progress:
                on_progress({
                    "analyzer": analyzer_type,
                    "event": "pipeline_completed",
                    "timestamp": time.time(),
                    "success": bool(final_result.success),
                    "execution_time": time.time() - pipeline_started_at,
                    "checker_name": str(final_result.checker_name or ""),
                    "output_path": str(final_result.output_path or ""),
                })

            return final_result
        except Exception as exc:
            if on_progress:
                on_progress({
                    "analyzer": analyzer_type,
                    "event": "pipeline_failed",
                    "timestamp": time.time(),
                    "error": str(exc),
                })
            raise

    def _rehydrate_saved_analyzer_result(
        self,
        analyzer_type: str,
        artifact,
        validate_path: Optional[str],
    ) -> AnalyzerResult:
        """从已保存产物构造 AnalyzerResult，供精炼复用。"""
        entry = getattr(artifact, "report_entry", {}) or {}
        baseline_evidence_bundle = (
            getattr(artifact, "post_validation_evidence_bundle_raw", {}) or {}
        ) or (
            getattr(artifact, "evidence_bundle_raw", {}) or {}
        ) or (
            entry.get("post_validation_evidence_bundle", {}) or {}
        ) or (
            entry.get("evidence_bundle", {}) or {}
        )
        metadata = {
            "validation_requested": bool(validate_path),
            "evidence_bundle": baseline_evidence_bundle,
            "evidence_records": entry.get("evidence_records", 0),
            "missing_evidence": entry.get("missing_evidence", []),
            "evidence_degraded": entry.get("evidence_degraded", False),
            "semantic_slice_records": entry.get("semantic_slice_records", 0),
            "context_summary_records": entry.get("context_summary_records", 0),
            "slice_coverage": entry.get("slice_coverage", ""),
            "verifier_backed_slices": entry.get("verifier_backed_slices", 0),
            "slice_kinds": entry.get("slice_kinds", {}),
            "evidence_escalation": entry.get("evidence_escalation", {}),
            "validation_feedback_records": entry.get("validation_feedback_records", 0),
            "validation_feedback_summary": entry.get("validation_feedback_summary", ""),
            "validation_feedback_bundle": entry.get("validation_feedback_bundle", {}),
            "post_validation_evidence_records": entry.get("post_validation_evidence_records", 0),
            "post_validation_missing_evidence": entry.get("post_validation_missing_evidence", []),
            "post_validation_semantic_slice_records": entry.get("post_validation_semantic_slice_records", 0),
            "post_validation_context_summary_records": entry.get("post_validation_context_summary_records", 0),
            "post_validation_slice_coverage": entry.get("post_validation_slice_coverage", ""),
            "post_validation_evidence_bundle": entry.get("post_validation_evidence_bundle", {}),
            "synthesis_input": entry.get("synthesis_input", {}),
        }
        fixed_validation = getattr(artifact, "fixed_validation_raw", {}) or {}
        metadata["baseline_fixed_validation"] = fixed_validation
        baseline_metrics = self._baseline_validation_metrics(entry=entry, fixed_validation=fixed_validation)
        metadata.update(baseline_metrics)
        metadata["baseline_validation_summary"] = self._baseline_validation_summary(
            analyzer_type=analyzer_type,
            entry=entry,
            fixed_validation=fixed_validation,
        )

        output_path = str(getattr(artifact, "output_path", "") or "").strip()
        source_path = str(getattr(artifact, "source_path", "") or "").strip()
        success = bool(output_path and Path(output_path).exists())
        if not success and source_path:
            success = Path(source_path).exists()
        validation_result = self._validation_result_from_report_entry(
            analyzer_type=analyzer_type,
            validation=entry.get("validation", {}) if isinstance(entry.get("validation"), dict) else {},
        )

        return AnalyzerResult(
            analyzer_type=analyzer_type,
            success=success,
            checker_name=str(getattr(artifact, "checker_name", "") or "").strip(),
            checker_code=str(getattr(artifact, "checker_code", "") or ""),
            output_path=output_path,
            error_message="" if success else "基线产物不存在，无法执行精炼",
            metadata=metadata,
            validation_result=validation_result,
        )

    def _validation_result_from_report_entry(
        self,
        *,
        analyzer_type: str,
        validation: Dict[str, Any],
    ) -> Optional[ValidationResult]:
        if not validation:
            return None
        diagnostics: List[Diagnostic] = []
        for item in validation.get("diagnostics", []) or []:
            if not isinstance(item, dict):
                continue
            diagnostics.append(Diagnostic(
                file_path=str(item.get("file_path", "") or ""),
                line=int(item.get("line", 0) or 0),
                column=int(item.get("column", 0) or 0),
                severity=str(item.get("severity", "") or ""),
                message=str(item.get("message", "") or ""),
                source=str(item.get("source", analyzer_type) or analyzer_type),
                code=str(item.get("code", "") or ""),
                suggestion=str(item.get("suggestion", "") or ""),
            ))
        analyzer_enum = AnalyzerType.CODEQL if str(analyzer_type).lower() == "codeql" else AnalyzerType.CSA
        return ValidationResult(
            stage=ValidationStage.SEMANTIC,
            analyzer=analyzer_enum,
            success=bool(validation.get("success", False)),
            diagnostics=diagnostics,
            execution_time=float(validation.get("execution_time", 0.0) or 0.0),
            error_message=str(validation.get("error_message", "") or ""),
            metadata={
                "environment_blocked": bool(validation.get("environment_blocked", False)),
                "environment_block_reason": str(validation.get("environment_block_reason", "") or ""),
                "validation_target": str(validation.get("validation_target", "") or ""),
                "reused_from_generation": True,
            },
        )

    def _baseline_validation_summary(
        self,
        *,
        analyzer_type: str,
        entry: Dict[str, Any],
        fixed_validation: Dict[str, Any],
    ) -> str:
        metrics = self._baseline_validation_metrics(entry=entry, fixed_validation=fixed_validation)
        fixed_available = bool(fixed_validation)
        fixed_text = (
            f"修复版误报数={metrics['baseline_fixed_diagnostics']}, fixed_silent={str(metrics['baseline_fixed_silent']).lower()}"
            if fixed_available else
            "修复版误报数=unknown, fixed_silent=unknown"
        )
        return (
            f"Baseline validation ({analyzer_type}): 漏洞版命中={str(metrics['baseline_vuln_hit']).lower()}, "
            f"漏洞版patch-scoped告警数={metrics['baseline_vuln_diagnostics']}, {fixed_text}, "
            f"PDS={str(metrics['baseline_pds']).lower()}. 这些是精炼重要指标：保持漏洞版命中，同时优先降低修复版patch-scoped误报。"
        )

    def _baseline_validation_metrics(
        self,
        *,
        entry: Dict[str, Any],
        fixed_validation: Dict[str, Any],
    ) -> Dict[str, Any]:
        validation = entry.get("validation", {}) if isinstance(entry.get("validation"), dict) else {}
        vuln_count = int(validation.get("diagnostics_count", 0) or 0)
        vuln_hit = bool(entry.get("semantic_target_hit", False) or vuln_count > 0)
        fixed_count = int((fixed_validation or {}).get("diagnostics_count", 0) or 0)
        fixed_available = bool(fixed_validation)
        fixed_silent = fixed_available and fixed_count == 0 and bool(fixed_validation.get("success", False))
        pds = vuln_hit and fixed_silent
        return {
            "baseline_vuln_hit": vuln_hit,
            "baseline_vuln_diagnostics": vuln_count,
            "baseline_fixed_diagnostics": fixed_count if fixed_available else None,
            "baseline_fixed_silent": fixed_silent if fixed_available else None,
            "baseline_pds": pds if fixed_available else None,
        }

    def _build_refinement_shared_analysis(
        self,
        base_shared_analysis: Dict[str, Any],
        session,
        selected_analyzers: List[str],
    ) -> Dict[str, Any]:
        """为精炼补充当前产物与既有反馈上下文。"""
        shared = copy.deepcopy(base_shared_analysis or {})
        patchweaver = dict(shared.get("patchweaver", {}) or {})
        baselines = dict(patchweaver.get("refinement_targets", {}) or {})
        history = list(patchweaver.get("validation_feedback_history", []) or [])

        for analyzer_id in selected_analyzers:
            artifact = session.artifacts.get(analyzer_id)
            if artifact is None:
                continue
            entry = artifact.report_entry or {}
            baseline_path = str(getattr(artifact, "source_path", "") or getattr(artifact, "output_path", "") or "").strip()
            baselines[analyzer_id] = {
                "checker_name": getattr(artifact, "checker_name", "") or "",
                "artifact_path": baseline_path,
                "artifact_kind": "checker_source" if analyzer_id == "csa" else "query",
                "validation_summary": str(entry.get("semantic_acceptance_summary", "") or "").strip(),
                "refinement_summary": str(entry.get("validation_feedback_summary", "") or "").strip(),
            }
            for item in (entry.get("validation_feedback_history", []) or []):
                if isinstance(item, dict):
                    history.append(copy.deepcopy(item))

        if baselines:
            patchweaver["refinement_targets"] = baselines
        if history:
            patchweaver["validation_feedback_history"] = history[-6:]

        shared["patchweaver"] = patchweaver
        shared["patch_path"] = session.patch_path
        return shared

    def _emit_validation_feedback_attached(
        self,
        analyzer_id: str,
        feedback_status: Dict[str, Any],
        on_progress: Optional[Callable] = None,
    ):
        """发出 validation_feedback_attached 事件。"""
        if not on_progress or feedback_status.get("records", 0) <= 0:
            return

        payload = {
            "analyzer": analyzer_id,
            "event": "validation_feedback_attached",
            "timestamp": time.time(),
            "records": feedback_status.get("records", 0),
            "summary": feedback_status.get("summary", ""),
        }
        on_progress(payload)

    def _attach_validation_feedback(
        self,
        analyzer_id: str,
        analyzer_result: AnalyzerResult,
        context: AnalyzerContext,
    ) -> Dict[str, Any]:
        """将验证结果归一化为 validation_outcome 证据并回写 metadata。"""
        try:
            from .validation_feedback import ValidationFeedbackBuilder
            from ..evidence.normalizer import EvidenceNormalizer

            base_bundle = EvidenceNormalizer.from_raw_bundle(
                analyzer_result.metadata.get("evidence_bundle", {}) or {}
            )
            feedback_bundle = ValidationFeedbackBuilder().build(
                analyzer_id=analyzer_id,
                patch_path=context.patch_path,
                validate_path=context.validate_path,
                validation_result=analyzer_result.validation_result,
            )
            merged_bundle = EvidenceNormalizer.merge_bundles(base_bundle, feedback_bundle)

            analyzer_result.metadata["validation_feedback_bundle"] = feedback_bundle.to_dict()
            analyzer_result.metadata["validation_feedback_records"] = len(feedback_bundle.records)
            analyzer_result.metadata["validation_feedback_summary"] = "\n".join(
                EvidenceNormalizer.summarize_bundle(
                    feedback_bundle,
                    analyzer=analyzer_id,
                    limit=6,
                )
            )
            analyzer_result.metadata["post_validation_evidence_bundle"] = merged_bundle.to_dict()
            analyzer_result.metadata["post_validation_evidence_records"] = len(merged_bundle.records)
            analyzer_result.metadata["post_validation_missing_evidence"] = list(merged_bundle.missing_evidence)
            post_slice_metrics = EvidenceNormalizer.slice_metrics(merged_bundle, analyzer=analyzer_id)
            analyzer_result.metadata["post_validation_semantic_slice_records"] = post_slice_metrics.get("semantic_slice_count", 0)
            analyzer_result.metadata["post_validation_context_summary_records"] = post_slice_metrics.get("context_summary_count", 0)
            analyzer_result.metadata["post_validation_slice_coverage"] = post_slice_metrics.get("coverage", "")
            return {
                "records": len(feedback_bundle.records),
                "summary": analyzer_result.metadata.get("validation_feedback_summary", ""),
            }
        except Exception as exc:
            logger.warning(f"归一化验证反馈失败: {exc}")
            return {"records": 0, "summary": ""}

    def _augment_shared_analysis_with_validation_feedback(
        self,
        shared_analysis: Dict[str, Any],
        analyzer_result: AnalyzerResult,
        phase: str,
    ) -> Dict[str, Any]:
        """将 validation_outcome 证据回写到 shared_analysis，供报告与 refine 使用。"""
        enriched = copy.deepcopy(shared_analysis or {})
        patchweaver = dict(enriched.get("patchweaver", {}) or {})

        post_validation_bundle = analyzer_result.metadata.get("post_validation_evidence_bundle", {}) or {}
        validation_feedback_bundle = analyzer_result.metadata.get("validation_feedback_bundle", {}) or {}
        if post_validation_bundle:
            patchweaver["evidence_bundle"] = post_validation_bundle
        if validation_feedback_bundle:
            patchweaver["validation_feedback"] = validation_feedback_bundle

        history = list(patchweaver.get("validation_feedback_history", []) or [])
        history.append({
            "analyzer": normalize_analyzer_id(analyzer_result.analyzer_type),
            "phase": str(phase or "").strip() or "validation",
            "summary": analyzer_result.metadata.get("validation_feedback_summary", ""),
        })
        patchweaver["validation_feedback_history"] = history[-3:]

        enriched["patchweaver"] = patchweaver
        return enriched

    def _refinement_max_rounds(self) -> int:
        refine_config = self.config.get("refine", {}) or {}
        try:
            raw_value = int(refine_config.get("max_rounds", 2))
        except (TypeError, ValueError):
            raw_value = 2
        return max(1, min(raw_value, 3))

    def _candidate_has_applied_patch(self, candidate: Optional[AnalyzerResult]) -> bool:
        metadata = getattr(candidate, "metadata", {}) or {}
        refinement_agent = metadata.get("refinement_agent", {}) or {}
        tool_history = refinement_agent.get("tool_history", []) or []
        for item in tool_history:
            if not isinstance(item, dict):
                continue
            if str(item.get("tool_name", "") or "").strip() != "apply_patch":
                continue
            if bool(item.get("success", False)):
                return True
        return False

    def _candidate_has_source_update(
        self,
        current: AnalyzerResult,
        candidate: AnalyzerResult,
    ) -> bool:
        current_code = str(getattr(current, "checker_code", "") or "")
        candidate_code = str(getattr(candidate, "checker_code", "") or "")
        return bool(candidate_code) and candidate_code != current_code

    def _should_adopt_refinement_candidate(
        self,
        current: AnalyzerResult,
        candidate: AnalyzerResult,
    ) -> bool:
        """refine 只要真实落了 patch 且源码变化，就直接采纳，不再按分数回退。"""
        if candidate is None:
            return False
        if current is None:
            return self._candidate_has_applied_patch(candidate)
        return self._candidate_has_applied_patch(candidate) and self._candidate_has_source_update(
            current=current,
            candidate=candidate,
        )

    def _candidate_requested_stop(self, candidate: Optional[AnalyzerResult]) -> bool:
        metadata = getattr(candidate, "metadata", {}) or {}
        refinement_agent = metadata.get("refinement_agent", {}) or {}
        return bool(refinement_agent.get("model_requested_stop", False))

    def _refresh_refinement_artifact(
        self,
        artifact,
        candidate: AnalyzerResult,
    ):
        refreshed = copy.deepcopy(artifact)
        candidate_meta = getattr(candidate, "metadata", {}) or {}
        source_path = str(
            candidate_meta.get("refinement_target_path", "")
            or getattr(refreshed, "source_path", "")
            or ""
        ).strip()
        output_path = str(getattr(candidate, "output_path", "") or "").strip()
        checker_name = str(getattr(candidate, "checker_name", "") or "").strip()
        checker_code = str(getattr(candidate, "checker_code", "") or "")

        if source_path:
            refreshed.source_path = source_path
        if output_path:
            refreshed.output_path = output_path
        if checker_name:
            refreshed.checker_name = checker_name
        if checker_code:
            refreshed.checker_code = checker_code

        report_entry = dict(getattr(refreshed, "report_entry", {}) or {})
        if source_path:
            report_entry["source_path"] = source_path
        if output_path:
            report_entry["output_path"] = output_path
        if checker_name:
            report_entry["checker_name"] = checker_name
        refreshed.report_entry = report_entry
        return refreshed

    def _baseline_refine_skip_reason(
        self,
        analyzer_result: Optional[AnalyzerResult],
        review_result: Any,
    ) -> str:
        if analyzer_result is None or review_result is None:
            return ""
        if not bool(getattr(review_result, "success", False)):
            return ""
        if self._validation_requested(analyzer_result):
            baseline_pds = (getattr(analyzer_result, "metadata", {}) or {}).get("baseline_pds")
            if baseline_pds is not True:
                return ""
            if self._is_semantically_accepted(analyzer_result):
                return "baseline_already_passes_strict_refine_review_and_validation"
            return ""
        if bool(getattr(analyzer_result, "success", False)):
            return "baseline_already_passes_strict_refine_review"
        return ""

    def _semantic_validation_has_hits(self, analyzer_result: Optional[AnalyzerResult]) -> bool:
        validation_result = getattr(analyzer_result, "validation_result", None)
        if validation_result is None or not bool(getattr(validation_result, "success", False)):
            return False
        return bool(getattr(validation_result, "diagnostics", []) or [])

    def _validation_executed_successfully(self, analyzer_result: Optional[AnalyzerResult]) -> bool:
        validation_result = getattr(analyzer_result, "validation_result", None)
        return bool(getattr(validation_result, "success", False))

    def _functional_validation_passed(self, analyzer_result: Optional[AnalyzerResult]) -> bool:
        return self._validation_executed_successfully(analyzer_result) and self._semantic_target_hit(analyzer_result)

    def _semantic_target_hit(self, analyzer_result: Optional[AnalyzerResult]) -> bool:
        return self._semantic_validation_has_hits(analyzer_result)

    def _validation_requested(self, analyzer_result: Optional[AnalyzerResult]) -> bool:
        metadata = getattr(analyzer_result, "metadata", {}) or {}
        return bool(metadata.get("validation_requested", False))

    def _is_semantically_accepted(self, analyzer_result: Optional[AnalyzerResult]) -> bool:
        if analyzer_result is None or not bool(getattr(analyzer_result, "success", False)):
            return False
        if not self._validation_requested(analyzer_result):
            return True
        return self._functional_validation_passed(analyzer_result)

    def _semantic_acceptance_summary(self, analyzer_result: Optional[AnalyzerResult]) -> str:
        if analyzer_result is None:
            return "无结果"
        if not bool(getattr(analyzer_result, "success", False)):
            return "生成失败"
        if not self._validation_requested(analyzer_result):
            return "未请求验证，仅完成生成"

        if not self._validation_executed_successfully(analyzer_result):
            return "功能验证执行失败"
        if not self._semantic_target_hit(analyzer_result):
            return "功能验证执行成功，但未命中验证目标"

        return "命中验证目标并通过功能验证"

    def _create_analyzer(
        self,
        analyzer_type: str,
        progress_callback: Optional[Callable] = None,
        suppress_output: bool = False,
        llm_client_override=None,
    ):
        """按名称创建分析器实例（支持扩展）。"""
        self._ensure_initialized()
        return self._analyzer_manager.create(
            analyzer_name=analyzer_type,
            llm_client=llm_client_override,
            progress_callback=progress_callback,
            suppress_output=suppress_output,
        )

    def _run_parallel_multi(
        self,
        analyzers: List[str],
        patch_path: str,
        output_dir: str,
        validate_path: str,
        shared_analysis: Dict[str, Any],
        on_progress: Callable,
    ) -> Dict[str, AnalyzerResult]:
        """并行运行多个分析器（可扩展）。

        设计约束：每个分析器任务都调用 `_run_single`，
        保证与单分析器模式使用同一套生成/验证逻辑。
        """
        results: Dict[str, AnalyzerResult] = {}

        selected = [a for a in analyzers if a]
        if not selected:
            return results

        def emit(analyzer: str, event: str, **kwargs):
            if on_progress:
                on_progress({
                    "analyzer": analyzer,
                    "event": event,
                    "timestamp": time.time(),
                    **kwargs,
                })

        emit("parallel", "run_started", analyzers=selected)

        max_workers = max(1, min(len(selected), 4))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {}
            for analyzer_name in selected:
                emit(analyzer_name, "submitted")
                from ..llm import create_llm_client
                llm_config = copy.deepcopy(self.config.get("llm", {}) or {})
                llm_config["log_calls"] = False
                isolated_llm_client = create_llm_client(llm_config)
                future = executor.submit(
                    self._run_single,
                    analyzer_name,
                    patch_path,
                    output_dir,
                    validate_path,
                    shared_analysis,
                    on_progress,
                    True,
                    isolated_llm_client,
                )
                future_map[future] = analyzer_name

            for future in as_completed(future_map):
                analyzer_name = future_map[future]
                try:
                    analyzer_result = future.result()
                    results[analyzer_name] = analyzer_result
                    emit(
                        analyzer_name,
                        "completed",
                        success=analyzer_result.success,
                        iterations=analyzer_result.iterations,
                    )
                except Exception as e:
                    logger.exception(f"[{analyzer_name}] 执行失败: {e}")
                    emit(analyzer_name, "failed", error=str(e))
                    fallback_type = (
                        "csa" if analyzer_name == "csa"
                        else "codeql"
                    )
                    results[analyzer_name] = AnalyzerResult(
                        analyzer_type=fallback_type,
                        success=False,
                        error_message=str(e),
                    )

        emit(
            "parallel",
            "run_completed",
            success=any(r.success for r in results.values()),
            total_time=0.0,
        )

        return results

    def _fill_result_from_multi(
        self,
        result: GenerationResult,
        analyzer_results: Dict[str, AnalyzerResult],
        selected_analyzers: List[str],
    ):
        """从多分析器结果填充主结果。"""
        result.generation_success = any(r.success for r in analyzer_results.values())
        strict_mode = any(self._validation_requested(r) for r in analyzer_results.values())
        result.semantic_success = any(self._is_semantically_accepted(r) for r in analyzer_results.values())
        result.success = result.semantic_success if strict_mode else result.generation_success

        for analyzer_name, analyzer_result in analyzer_results.items():
            result.analyzer_results[analyzer_name] = self._build_analyzer_report_entry(analyzer_result)
            result.analyzer_artifacts[analyzer_name] = {
                "checker_code": analyzer_result.checker_code,
            }

        portfolio = self._resolve_portfolio_decision(
            analyzer_results,
            selected_analyzers,
            result.shared_analysis,
        )
        result.portfolio_decision = portfolio

        preferred_id = str(portfolio.get("preferred_analyzer", "") or "").strip().lower()
        primary = analyzer_results.get(preferred_id) if preferred_id else None
        if primary is not None and not primary.success:
            primary = None

        if primary is None:
            for analyzer_name in selected_analyzers:
                ar = analyzer_results.get(analyzer_name)
                if ar and ar.success:
                    primary = ar
                    break
        if primary is None:
            # 所有失败时取第一个结果用于展示错误上下文
            for analyzer_name in selected_analyzers:
                if analyzer_name in analyzer_results:
                    primary = analyzer_results[analyzer_name]
                    break

        if primary is not None:
            self._apply_primary_analyzer_result(result, primary)

        if not result.success:
            if strict_mode and result.generation_success:
                result.error_message = "检测器已生成，但未通过功能验证"
            else:
                errors = []
                for analyzer_name in selected_analyzers:
                    ar = analyzer_results.get(analyzer_name)
                    if ar and not ar.success:
                        errors.append(f"{analyzer_name}: {ar.error_message or '生成失败'}")
                result.error_message = "; ".join(errors)

    def _fill_result_from_single(
        self,
        result: GenerationResult,
        analyzer_result: AnalyzerResult,
    ):
        """从单分析器结果填充"""
        result.generation_success = analyzer_result.success
        result.semantic_success = self._is_semantically_accepted(analyzer_result)
        result.success = result.semantic_success if self._validation_requested(analyzer_result) else result.generation_success
        result.checker_name = analyzer_result.checker_name
        result.checker_code = analyzer_result.checker_code
        result.output_path = analyzer_result.output_path
        result.total_iterations = analyzer_result.iterations
        result.repair_iterations = analyzer_result.compile_attempts
        result.error_message = analyzer_result.error_message
        result.validation_result = analyzer_result.validation_result

        analyzer_id = normalize_analyzer_id(analyzer_result.analyzer_type)
        result.analyzer_results[analyzer_id] = self._build_analyzer_report_entry(analyzer_result)
        result.analyzer_artifacts[analyzer_id] = {
            "checker_code": analyzer_result.checker_code,
        }
        result.portfolio_decision = self._resolve_portfolio_decision(
            analyzer_results={analyzer_id: analyzer_result},
            selected_analyzers=[analyzer_id],
            shared_analysis=result.shared_analysis,
        )

        if not result.success and self._validation_requested(analyzer_result) and result.generation_success:
            result.error_message = "检测器已生成，但未通过功能验证"

    def _build_analyzer_report_entry(self, analyzer_result: AnalyzerResult) -> Dict[str, Any]:
        """标准化单分析器结果到报告结构，避免 single/multi 模式重复拼装。"""
        metadata = analyzer_result.metadata or {}
        shared_after_validation = metadata.get("shared_analysis_after_validation", {}) or {}
        patchweaver_after_validation = shared_after_validation.get("patchweaver", {}) or {}
        validation_requested = self._validation_requested(analyzer_result)
        functional_validation_passed = self._functional_validation_passed(analyzer_result)
        semantic_target_hit = self._semantic_target_hit(analyzer_result)
        evidence_effectiveness = self._build_evidence_effectiveness(metadata)
        source_path = self._artifact_source_path(analyzer_result)
        llm_usage = normalize_usage(metadata.get("llm_usage", {}))
        return {
            "success": analyzer_result.success,
            "validation_requested": validation_requested,
            "functional_validation_passed": functional_validation_passed,
            "semantic_target_hit": semantic_target_hit,
            "validation_state": self._validation_state(analyzer_result),
            "semantic_acceptance": self._is_semantically_accepted(analyzer_result),
            "semantic_acceptance_summary": self._semantic_acceptance_summary(analyzer_result),
            "checker_name": analyzer_result.checker_name,
            "artifact_display_name": self._artifact_display_name(analyzer_result),
            "output_path": analyzer_result.output_path,
            "source_path": source_path,
            "iterations": analyzer_result.iterations,
            "compile_attempts": analyzer_result.compile_attempts,
            "error": analyzer_result.error_message,
            "validation": self._validation_result_to_dict(analyzer_result.validation_result),
            "llm_usage": llm_usage,
            "artifact_metrics": self._artifact_file_metrics(source_path),
            "artifact_delta": self._artifact_delta_metrics(
                metadata.get("baseline_source_path", ""),
                source_path,
            ),
            "artifact_review": metadata.get("artifact_review", {}),
            "evidence_records": metadata.get("evidence_records", 0),
            "missing_evidence": metadata.get("missing_evidence", []),
            "evidence_degraded": metadata.get("evidence_degraded", False),
            "semantic_slice_records": metadata.get("semantic_slice_records", 0),
            "context_summary_records": metadata.get("context_summary_records", 0),
            "slice_coverage": metadata.get("slice_coverage", ""),
            "verifier_backed_slices": metadata.get("verifier_backed_slices", 0),
            "slice_kinds": metadata.get("slice_kinds", {}),
            "evidence_escalation": metadata.get("evidence_escalation", {}),
            "validation_feedback_records": metadata.get("validation_feedback_records", 0),
            "validation_feedback_summary": metadata.get("validation_feedback_summary", ""),
            "validation_feedback_history": patchweaver_after_validation.get("validation_feedback_history", []),
            "refinement_attempted": metadata.get("refinement_attempted", False),
            "refinement_adopted": metadata.get("refinement_adopted", False),
            "refinement_iterations_attempted": metadata.get("refinement_iterations_attempted", 0),
            "refinement_skipped_reason": metadata.get("refinement_skipped_reason", ""),
            "last_refinement_candidate_success": metadata.get("last_refinement_candidate_success", False),
            "last_refinement_candidate_error": metadata.get("last_refinement_candidate_error", ""),
            "last_refinement_candidate_artifact_review": metadata.get("last_refinement_candidate_artifact_review", {}),
            "last_refinement_candidate_output_path": metadata.get("last_refinement_candidate_output_path", ""),
            "post_validation_evidence_records": metadata.get("post_validation_evidence_records", 0),
            "post_validation_missing_evidence": metadata.get("post_validation_missing_evidence", []),
            "post_validation_semantic_slice_records": metadata.get("post_validation_semantic_slice_records", 0),
            "post_validation_context_summary_records": metadata.get("post_validation_context_summary_records", 0),
            "post_validation_slice_coverage": metadata.get("post_validation_slice_coverage", ""),
            "synthesis_input": metadata.get("synthesis_input", {}),
            "evidence_effectiveness": evidence_effectiveness,
        }

    def _build_evidence_effectiveness(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        baseline_records = int(metadata.get("evidence_records", 0) or 0)
        post_records = int(metadata.get("post_validation_evidence_records", baseline_records) or baseline_records)
        baseline_missing = [str(item).strip() for item in (metadata.get("missing_evidence", []) or []) if str(item).strip()]
        post_missing = [str(item).strip() for item in (metadata.get("post_validation_missing_evidence", baseline_missing) or []) if str(item).strip()]
        resolved = [item for item in baseline_missing if item not in post_missing]
        new_records = max(0, post_records - baseline_records)
        improved = bool(new_records or resolved)

        parts: List[str] = []
        if new_records:
            parts.append(f"新增 {new_records} 条反馈后证据")
        if resolved:
            parts.append(f"补齐缺口: {', '.join(resolved[:4])}")
        if post_missing:
            parts.append(f"仍缺: {', '.join(post_missing[:4])}")
        if not parts:
            parts.append("验证反馈未新增证据或缺口变化")

        return {
            "baseline_records": baseline_records,
            "post_validation_records": post_records,
            "new_records": new_records,
            "baseline_missing": baseline_missing,
            "post_validation_missing": post_missing,
            "resolved_missing": resolved,
            "improved": improved,
            "summary": "；".join(parts),
        }

    def _validation_state(self, analyzer_result: Optional[AnalyzerResult]) -> str:
        if analyzer_result is None:
            return "no_result"
        if not bool(getattr(analyzer_result, "success", False)):
            return "generation_failed"
        if not self._validation_requested(analyzer_result):
            return "not_requested"
        if not self._validation_executed_successfully(analyzer_result):
            return "execution_failed"
        if self._semantic_target_hit(analyzer_result):
            return "target_hit"
        return "executed_no_hit"

    def _artifact_display_name(self, analyzer_result: Optional[AnalyzerResult]) -> str:
        if analyzer_result is None:
            return ""
        raw_name = str(getattr(analyzer_result, "checker_name", "") or "").strip()
        metadata = getattr(analyzer_result, "metadata", {}) or {}
        synthesis_input = metadata.get("synthesis_input", {}) if isinstance(metadata.get("synthesis_input"), dict) else {}
        detector_hint = str(synthesis_input.get("detector_name_hint", "") or "").strip()
        generic_names = {"query", "detector", "checker", "custom"}

        if raw_name and raw_name.lower() not in generic_names:
            return raw_name
        if detector_hint:
            return detector_hint
        return raw_name or "unnamed_artifact"

    def _artifact_source_path(self, analyzer_result: Optional[AnalyzerResult]) -> str:
        if analyzer_result is None:
            return ""

        metadata = getattr(analyzer_result, "metadata", {}) or {}
        explicit = str(
            metadata.get("artifact_source_path")
            or metadata.get("refinement_target_path")
            or ""
        ).strip()
        if explicit:
            return explicit

        analyzer_id = normalize_analyzer_id(getattr(analyzer_result, "analyzer_type", ""))
        output_path = str(getattr(analyzer_result, "output_path", "") or "").strip()
        if analyzer_id == "codeql" and output_path.endswith(".ql"):
            return output_path

        work_dir = str(metadata.get("work_dir", "") or "").strip()
        checker_name = str(getattr(analyzer_result, "checker_name", "") or "").strip()
        if not work_dir or not checker_name:
            return ""

        suffix = ".ql" if analyzer_id == "codeql" else ".cpp"
        return str(Path(work_dir).expanduser().resolve() / f"{checker_name}{suffix}")

    def _artifact_file_metrics(self, path_value: Any) -> Dict[str, Any]:
        raw = str(path_value or "").strip()
        if not raw:
            return {}
        path = Path(raw).expanduser()
        if not path.exists() or not path.is_file():
            return {}
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return {}
        lines = text.splitlines()
        nonempty_lines = sum(1 for line in lines if line.strip())
        return {
            "path": str(path.resolve()),
            "total_lines": len(lines),
            "nonempty_lines": nonempty_lines,
            "char_count": len(text),
            "byte_count": path.stat().st_size,
        }

    def _artifact_delta_metrics(self, baseline_path: Any, current_path: Any) -> Dict[str, Any]:
        baseline = self._artifact_file_metrics(baseline_path)
        current = self._artifact_file_metrics(current_path)
        if not baseline or not current:
            return {}

        delta_total = int(current.get("total_lines", 0) or 0) - int(baseline.get("total_lines", 0) or 0)
        delta_nonempty = int(current.get("nonempty_lines", 0) or 0) - int(baseline.get("nonempty_lines", 0) or 0)
        baseline_nonempty = int(baseline.get("nonempty_lines", 0) or 0)
        growth_ratio = round(delta_nonempty / baseline_nonempty, 6) if baseline_nonempty > 0 else None
        return {
            "baseline_path": baseline.get("path", ""),
            "current_path": current.get("path", ""),
            "baseline_total_lines": baseline.get("total_lines", 0),
            "current_total_lines": current.get("total_lines", 0),
            "baseline_nonempty_lines": baseline.get("nonempty_lines", 0),
            "current_nonempty_lines": current.get("nonempty_lines", 0),
            "delta_total_lines": delta_total,
            "delta_nonempty_lines": delta_nonempty,
            "growth_ratio": growth_ratio,
        }

    def _resolve_portfolio_decision(
        self,
        analyzer_results: Dict[str, AnalyzerResult],
        selected_analyzers: List[str],
        shared_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """运行 PATCHWEAVER 组合决策。"""
        try:
            descriptors = self._analyzer_manager.list_descriptors() if self._analyzer_manager else []
            controller = PortfolioController(descriptors)
            decision = controller.resolve(
                analyzer_results=analyzer_results,
                selected_analyzers=selected_analyzers,
                shared_analysis=shared_analysis or {},
            )
            return decision.to_dict()
        except Exception as exc:
            logger.warning(f"组合决策失败: {exc}")
            return {}

    def _apply_primary_analyzer_result(
        self,
        result: GenerationResult,
        analyzer_result: AnalyzerResult,
    ):
        """将首选分析器结果写回主结果。"""
        result.checker_name = analyzer_result.checker_name
        result.checker_code = analyzer_result.checker_code
        result.output_path = analyzer_result.output_path
        result.total_iterations = analyzer_result.iterations
        result.repair_iterations = analyzer_result.compile_attempts
        result.validation_result = analyzer_result.validation_result

    def _validation_result_to_dict(self, validation_result: Any) -> Dict[str, Any]:
        """将验证结果对象序列化为可写入 JSON 的字典。"""
        if not validation_result:
            return {}

        metadata = copy.deepcopy(getattr(validation_result, "metadata", {}) or {})
        diagnostics = []
        for d in (getattr(validation_result, "diagnostics", []) or []):
            diagnostics.append({
                "file_path": getattr(d, "file_path", ""),
                "line": getattr(d, "line", 0),
                "column": getattr(d, "column", 0),
                "severity": getattr(d, "severity", ""),
                "message": getattr(d, "message", ""),
                "source": getattr(d, "source", ""),
                "code": getattr(d, "code", ""),
                "suggestion": getattr(d, "suggestion", ""),
            })

        diagnostics_count = len(diagnostics)
        all_diagnostics_count = int(metadata.get("all_diagnostics_count", diagnostics_count) or 0)
        generated_diagnostics_count = int(metadata.get("generated_diagnostics_count", diagnostics_count) or 0)
        return {
            "stage": getattr(getattr(validation_result, "stage", None), "value", ""),
            "analyzer": getattr(getattr(validation_result, "analyzer", None), "value", ""),
            "success": bool(getattr(validation_result, "success", False)),
            "execution_time": float(getattr(validation_result, "execution_time", 0.0) or 0.0),
            "error_message": getattr(validation_result, "error_message", ""),
            "diagnostics": diagnostics,
            "diagnostics_count": diagnostics_count,
            "all_diagnostics_count": all_diagnostics_count,
            "generated_diagnostics_count": generated_diagnostics_count,
            "warnings_count": sum(1 for d in diagnostics if d.get("severity") == "warning"),
            "errors_count": sum(1 for d in diagnostics if d.get("severity") == "error"),
            "environment_blocked": bool(metadata.get("environment_blocked", False)),
            "environment_block_reason": str(metadata.get("environment_block_reason", "") or ""),
            "validation_target": str(metadata.get("validation_target", "") or ""),
            "diagnostics_filtered": bool(metadata.get("diagnostics_filtered", False)),
        }

    def _manifest_relpath(
        self,
        output_root: Path,
        path_value: str,
    ) -> str:
        raw = str(path_value or "").strip()
        if not raw:
            return ""

        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (output_root / path)
        try:
            resolved = path.resolve()
        except FileNotFoundError:
            resolved = path

        try:
            return str(resolved.relative_to(output_root))
        except ValueError:
            return str(resolved)

    def _build_refinement_input_manifest(
        self,
        result: GenerationResult,
        output_root: Path,
        patchweaver_path: Path,
        analyzer_dirs: Dict[str, Path],
    ) -> Dict[str, Any]:
        from .refinement_session import REFINEMENT_INPUT_SCHEMA_VERSION

        manifest: Dict[str, Any] = {
            "schema_version": REFINEMENT_INPUT_SCHEMA_VERSION,
            "workflow_mode": str(getattr(result, "workflow_mode", "") or "").strip() or "generate",
            "patch_path": str(getattr(result, "patch_path", "") or "").strip(),
            "validate_path": str(getattr(result, "validate_path", "") or "").strip(),
            "analyzer_choice": str(getattr(result, "analyzer_type", "") or "").strip(),
            "shared_analysis_path": self._manifest_relpath(output_root, str(patchweaver_path)),
            "shared_analysis": copy.deepcopy(result.shared_analysis or {}),
            "artifacts": {},
        }

        for analyzer_id in ("csa", "codeql"):
            analyzer_info = result.analyzer_results.get(analyzer_id, {})
            if not isinstance(analyzer_info, dict) or not analyzer_info:
                continue

            source_path = str(analyzer_info.get("source_path", "") or "").strip()
            output_path = str(analyzer_info.get("output_path", "") or "").strip()
            if not source_path and not output_path:
                continue

            analyzer_dir = analyzer_dirs.get(analyzer_id)
            result_path = analyzer_dir / "result.json" if analyzer_dir is not None else None
            report_entry = self._refinement_report_entry(
                analyzer_id=analyzer_id,
                analyzer_info=analyzer_info,
                patch_path=str(getattr(result, "patch_path", "") or ""),
            )
            manifest["artifacts"][analyzer_id] = {
                "analyzer_id": analyzer_id,
                "checker_name": str(analyzer_info.get("checker_name", "") or "").strip(),
                "source_path": self._manifest_relpath(output_root, source_path),
                "output_path": self._manifest_relpath(output_root, output_path),
                "result_path": self._manifest_relpath(output_root, str(result_path or "")),
                "report_entry": report_entry,
            }

        return manifest

    def _refinement_report_entry(
        self,
        *,
        analyzer_id: str,
        analyzer_info: Dict[str, Any],
        patch_path: str,
    ) -> Dict[str, Any]:
        entry = copy.deepcopy(analyzer_info or {})
        validation = entry.get("validation", {}) if isinstance(entry.get("validation"), dict) else {}
        diagnostics = validation.get("diagnostics", []) if isinstance(validation.get("diagnostics"), list) else []
        patch_targets = self._extract_patch_targets(Path(str(patch_path or "")).expanduser())
        checker_name = str(entry.get("checker_name", "") or "").strip()
        scoped_diagnostics = [
            diagnostic for diagnostic in diagnostics
            if self._diagnostic_in_patch_targets(diagnostic, patch_targets)
            and self._is_generated_diagnostic(analyzer_id, diagnostic, checker_name)
        ]
        if validation:
            validation["all_diagnostics_count"] = len(diagnostics)
            validation["generated_diagnostics_count"] = self._count_generated_diagnostics(
                analyzer_id,
                diagnostics,
                checker_name,
            )
            validation["patch_targets"] = patch_targets
            validation["diagnostics"] = scoped_diagnostics
            validation["diagnostics_count"] = len(scoped_diagnostics)
            validation["warnings_count"] = sum(1 for item in scoped_diagnostics if str(item.get("severity", "")) == "warning")
            validation["errors_count"] = sum(1 for item in scoped_diagnostics if str(item.get("severity", "")) == "error")
            entry["validation"] = validation
        return entry

    def _count_generated_diagnostics(
        self,
        analyzer_id: str,
        diagnostics: List[Any],
        checker_name: str = "",
    ) -> int:
        return sum(
            1 for diagnostic in diagnostics
            if self._is_generated_diagnostic(analyzer_id, diagnostic, checker_name)
        )

    def _is_generated_diagnostic(self, analyzer_id: str, diagnostic: Any, checker_name: str = "") -> bool:
        if str(analyzer_id or "").strip().lower() != "csa":
            return True
        if isinstance(diagnostic, dict):
            values = [(diagnostic or {}).get(key, "") for key in ("message", "code", "checker", "check_name")]
        else:
            values = [getattr(diagnostic, key, "") for key in ("message", "code", "checker", "check_name")]
        text = " ".join(str(value or "") for value in values)
        expected = f"custom.{checker_name.strip()}" if checker_name.strip() else "custom."
        return expected in text

    def _diagnostic_in_patch_targets(self, diagnostic: Any, patch_targets: List[str]) -> bool:
        targets = [str(target or "").strip().replace("\\", "/") for target in (patch_targets or []) if str(target or "").strip()]
        if not targets:
            return True
        raw_path = str((diagnostic or {}).get("file_path", (diagnostic or {}).get("path", "")) or "")
        normalized = raw_path.replace("\\", "/")
        return any(normalized == target or normalized.endswith("/" + target) for target in targets)

    def _extract_patch_targets(self, patch_path: Path) -> List[str]:
        targets: List[str] = []
        try:
            text = patch_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return targets
        for line in text.splitlines():
            if line.startswith("+++ b/"):
                rel = line[len("+++ b/"):].strip()
                if rel and rel != "/dev/null" and rel not in targets:
                    targets.append(rel)
            elif line.startswith("diff --git "):
                parts = line.split()
                if len(parts) >= 4 and parts[3].startswith("b/"):
                    rel = parts[3][2:].strip()
                    if rel and rel not in targets:
                        targets.append(rel)
        return targets

    def _resolve_result_output_root(
        self,
        result: GenerationResult,
        output_dir: str,
    ) -> Path:
        configured = str(getattr(result, "report_output_dir", "") or "").strip()
        root = Path(configured or output_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _resolve_analyzer_result_dir(
        self,
        result: GenerationResult,
        analyzer_id: str,
        output_root: Path,
        analyzer_info: Dict[str, Any],
    ) -> Path:
        configured_dirs = getattr(result, "analyzer_output_dirs", {}) or {}
        configured = str(configured_dirs.get(analyzer_id, "") or "").strip()
        if configured:
            analyzer_dir = Path(configured).expanduser().resolve()
            analyzer_dir.mkdir(parents=True, exist_ok=True)
            return analyzer_dir

        output_path = str(analyzer_info.get("output_path", "") or "").strip()
        if str(getattr(result, "workflow_mode", "") or "").strip() == "refine" and output_path:
            analyzer_dir = Path(output_path).expanduser().resolve().parent
            analyzer_dir.mkdir(parents=True, exist_ok=True)
            return analyzer_dir

        analyzer_dir = (output_root / analyzer_id).resolve()
        analyzer_dir.mkdir(parents=True, exist_ok=True)
        return analyzer_dir

    def _load_existing_saved_analyzer_results(
        self,
        output_root: Path,
    ) -> Dict[str, Dict[str, Any]]:
        """恢复同一输出目录下已保存的分析器结果，避免单分析器重跑时覆盖其他分析器条目。"""
        existing: Dict[str, Dict[str, Any]] = {}

        final_report_path = output_root / "final_report.json"
        if final_report_path.exists():
            try:
                final_report = json.loads(final_report_path.read_text(encoding="utf-8"))
                for analyzer_id in ("csa", "codeql"):
                    payload = final_report.get(analyzer_id, {})
                    if isinstance(payload, dict) and payload:
                        existing[analyzer_id] = copy.deepcopy(payload)
            except Exception:
                pass

        for analyzer_id in ("csa", "codeql"):
            if analyzer_id in existing:
                continue
            result_path = output_root / analyzer_id / "result.json"
            if not result_path.exists():
                continue
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                if isinstance(payload, dict) and payload:
                    existing[analyzer_id] = payload
            except Exception:
                continue

        return existing

    def _merge_analyzer_results_for_save(
        self,
        result: GenerationResult,
        output_root: Path,
    ) -> Dict[str, Dict[str, Any]]:
        """将本轮结果与输出目录中已有结果合并。"""
        merged: Dict[str, Dict[str, Any]] = {}
        existing = self._load_existing_saved_analyzer_results(output_root)

        for analyzer_id in ("csa", "codeql"):
            current = result.analyzer_results.get(analyzer_id, {})
            if isinstance(current, dict) and current:
                merged[analyzer_id] = copy.deepcopy(current)
                continue

            previous = existing.get(analyzer_id, {})
            if isinstance(previous, dict) and previous:
                merged[analyzer_id] = copy.deepcopy(previous)

        return merged

    def _compute_merged_session_status(
        self,
        analyzer_results: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        normalized = [
            payload
            for payload in analyzer_results.values()
            if isinstance(payload, dict) and payload
        ]
        validation_requested = any(bool(item.get("validation_requested", False)) for item in normalized)
        generation_success = any(bool(item.get("success", False)) for item in normalized)
        semantic_success = any(bool(item.get("semantic_acceptance", False)) for item in normalized)
        success = semantic_success if validation_requested else generation_success
        analyzer_ids = [analyzer_id for analyzer_id in ("csa", "codeql") if analyzer_results.get(analyzer_id)]
        return {
            "analyzer_type": ",".join(analyzer_ids),
            "generation_success": generation_success,
            "semantic_success": semantic_success,
            "success": success,
        }

    def save_result(self, result: GenerationResult, output_dir: str):
        """保存生成结果 - 包含完整的整合报告"""
        from .refinement_session import REFINEMENT_INPUT_MANIFEST

        output_path = self._resolve_result_output_root(result, output_dir)
        merged_analyzer_results = self._merge_analyzer_results_for_save(result, output_path)
        merged_session_status = self._compute_merged_session_status(merged_analyzer_results)

        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # 1) 保存 CSA 产物
        csa_info = merged_analyzer_results.get("csa", {}) if isinstance(merged_analyzer_results.get("csa"), dict) else {}
        csa_dir = self._resolve_analyzer_result_dir(result, "csa", output_path, csa_info)
        csa_artifacts = result.analyzer_artifacts.get("csa", {}) if isinstance(result.analyzer_artifacts.get("csa"), dict) else {}
        csa_checker_code = csa_artifacts.get("checker_code", "") or ""
        csa_checker_name = csa_info.get("checker_name", "") or result.checker_name
        csa_output_path = csa_info.get("output_path", "") or ""
        if csa_checker_code and csa_checker_name:
            code_path = csa_dir / f"{csa_checker_name}.cpp"
            code_path.write_text(csa_checker_code, encoding='utf-8')
            csa_info["source_path"] = str(code_path)
            logger.info(f"检测器代码已保存: {code_path}")

        if csa_output_path.endswith(".so"):
            so_src = Path(csa_output_path)
            if so_src.exists():
                so_dst = csa_dir / so_src.name
                if so_src.resolve() != so_dst.resolve():
                    shutil.copy2(so_src, so_dst)
                csa_info["output_path"] = str(so_dst)
                logger.info(f"CSA 检测器已保存: {so_dst}")

        # 2) 保存 CodeQL 产物
        codeql_info = merged_analyzer_results.get("codeql", {})
        codeql_dir = self._resolve_analyzer_result_dir(
            result,
            "codeql",
            output_path,
            codeql_info if isinstance(codeql_info, dict) else {},
        )
        if isinstance(codeql_info, dict) and codeql_info.get("output_path"):
            qsrc = Path(codeql_info["output_path"])
            if qsrc.exists() and qsrc.suffix == ".ql":
                qdst = codeql_dir / qsrc.name
                if qsrc.resolve() != qdst.resolve():
                    shutil.copy2(qsrc, qdst)
                codeql_info["output_path"] = str(qdst)
                codeql_info["source_path"] = str(qdst)
                logger.info(f"CodeQL 查询已保存: {qdst}")

        # 3) 保存结果 JSON
        csa_validation = merged_analyzer_results.get("csa", {}).get("validation", {})
        if not csa_validation:
            # 兜底：主验证结果恰好是 CSA 时也写入
            vr = self._validation_result_to_dict(result.validation_result)
            if vr.get("analyzer") == "csa":
                csa_validation = vr

        csa_result = dict(csa_info) if isinstance(csa_info, dict) else {}
        if csa_validation and not csa_result.get("validation"):
            csa_result["validation"] = csa_validation
        (csa_dir / "result.json").write_text(
            json.dumps(csa_result, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        codeql_result = codeql_info if isinstance(codeql_info, dict) else {}
        (codeql_dir / "result.json").write_text(
            json.dumps(codeql_result, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        # 4) 保存验证反馈产物
        original_analyzer_results = result.analyzer_results
        original_analyzer_type = result.analyzer_type
        result.analyzer_results = merged_analyzer_results
        if merged_session_status.get("analyzer_type"):
            result.analyzer_type = str(merged_session_status.get("analyzer_type", "") or "")
        validation_feedback_report = self._collect_validation_feedback_report(result)
        validation_feedback_path = output_path / "validation_feedback.json"
        validation_feedback_path.write_text(
            json.dumps(validation_feedback_report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"验证反馈报告已保存: {validation_feedback_path}")

        # 5) 保存整合报告
        patchweaver_report = self._build_patchweaver_report_context(result)
        run_metrics = self._build_run_metrics(output_path)
        result.run_metrics = run_metrics
        report_data = {
            "meta": {
                "generated_at": timestamp,
                "analyzer_type": merged_session_status.get("analyzer_type", "") or result.analyzer_type,
                "workflow_mode": result.workflow_mode,
                "patch_path": result.patch_path,
                "validate_path": result.validate_path,
                "success": merged_session_status.get("success", result.success),
                "generation_success": merged_session_status.get("generation_success", result.generation_success),
                "semantic_success": merged_session_status.get("semantic_success", result.semantic_success),
                "error_message": result.error_message if not merged_session_status.get("success", result.success) else None,
                "preferred_analyzer": (result.portfolio_decision or {}).get("preferred_analyzer", ""),
                "run_metrics_summary": run_metrics.get("summary", ""),
            },
            "csa": merged_analyzer_results.get("csa", {}),
            "codeql": merged_analyzer_results.get("codeql", {}),
            "patchweaver": patchweaver_report,
            "validation_feedback": validation_feedback_report,
            "portfolio": result.portfolio_decision,
            "run_metrics": run_metrics,
            "artifacts": {
                "csa_dir": str(csa_dir),
                "codeql_dir": str(codeql_dir),
                "patchweaver_plan": str(output_path / "patchweaver_plan.json"),
                "validation_feedback": str(validation_feedback_path),
                "final_report": str(output_path / "final_report.json"),
                "refinement_input": str(output_path / REFINEMENT_INPUT_MANIFEST),
            }
        }

        patchweaver_path = output_path / "patchweaver_plan.json"
        patchweaver_dump = dict(result.shared_analysis or {})
        patchweaver_section = patchweaver_dump.get("patchweaver", {}) if isinstance(patchweaver_dump.get("patchweaver"), dict) else {}
        if isinstance(patchweaver_section, dict):
            for transient_key in ("evidence_bundle", "refinement_evidence_bundles", "validation_feedback"):
                patchweaver_section.pop(transient_key, None)
            patchweaver_dump["patchweaver"] = patchweaver_section
        for key in ("summary", "patch_facts", "mechanism_graph", "evidence_plan"):
            if key not in patchweaver_dump and key in patchweaver_section:
                patchweaver_dump[key] = patchweaver_section.get(key)
        patchweaver_path.write_text(
            json.dumps(patchweaver_dump, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"PATCHWEAVER 计划已保存: {patchweaver_path}")

        refinement_input_path = output_path / REFINEMENT_INPUT_MANIFEST
        refinement_input = self._build_refinement_input_manifest(
            result=result,
            output_root=output_path,
            patchweaver_path=patchweaver_path,
            analyzer_dirs={
                "csa": csa_dir,
                "codeql": codeql_dir,
            },
        )
        refinement_input_path.write_text(
            json.dumps(refinement_input, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"Refine 输入契约已保存: {refinement_input_path}")

        report_path = output_path / "final_report.json"
        report_path.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )
        logger.info(f"整合报告已保存: {report_path}")
        result.analyzer_results = original_analyzer_results
        result.analyzer_type = original_analyzer_type

        # 6) 生成 Markdown 报告
        self._generate_markdown_report(report_data, output_path)

    def _collect_validation_feedback_report(
        self,
        result: GenerationResult,
    ) -> Dict[str, Any]:
        """汇总各分析器的验证反馈产物，便于报告与后续调试。"""
        report: Dict[str, Any] = {}
        for analyzer_id in ("csa", "codeql"):
            analyzer_info = result.analyzer_results.get(analyzer_id, {})
            if not isinstance(analyzer_info, dict):
                continue
            report[analyzer_id] = {
                "success": analyzer_info.get("success", False),
                "validation_requested": analyzer_info.get("validation_requested", False),
                "functional_validation_passed": analyzer_info.get("functional_validation_passed", False),
                "semantic_target_hit": analyzer_info.get("semantic_target_hit", False),
                "validation_state": analyzer_info.get("validation_state", ""),
                "semantic_acceptance": analyzer_info.get("semantic_acceptance", False),
                "semantic_acceptance_summary": analyzer_info.get("semantic_acceptance_summary", ""),
                "missing_evidence": analyzer_info.get("missing_evidence", []),
                "evidence_degraded": analyzer_info.get("evidence_degraded", False),
                "semantic_slice_records": analyzer_info.get("semantic_slice_records", 0),
                "context_summary_records": analyzer_info.get("context_summary_records", 0),
                "slice_coverage": analyzer_info.get("slice_coverage", ""),
                "evidence_escalation": analyzer_info.get("evidence_escalation", {}),
                "validation_feedback_records": analyzer_info.get("validation_feedback_records", 0),
                "validation_feedback_summary": analyzer_info.get("validation_feedback_summary", ""),
                "validation_feedback_history": analyzer_info.get("validation_feedback_history", []),
                "post_validation_evidence_records": analyzer_info.get("post_validation_evidence_records", 0),
                "post_validation_missing_evidence": analyzer_info.get("post_validation_missing_evidence", []),
                "post_validation_semantic_slice_records": analyzer_info.get("post_validation_semantic_slice_records", 0),
                "post_validation_context_summary_records": analyzer_info.get("post_validation_context_summary_records", 0),
                "post_validation_slice_coverage": analyzer_info.get("post_validation_slice_coverage", ""),
            }
        return report

    def _build_patchweaver_report_context(
        self,
        result: GenerationResult,
    ) -> Dict[str, Any]:
        """为最终报告补齐 PATCHWEAVER 的验证反馈历史。"""
        patchweaver = copy.deepcopy(
            result.shared_analysis.get("patchweaver", {}) if isinstance(result.shared_analysis, dict) else {}
        )
        for key in ("evidence_bundle", "refinement_evidence_bundles", "validation_feedback"):
            patchweaver.pop(key, None)

        combined_history: List[Dict[str, Any]] = list(patchweaver.get("validation_feedback_history", []) or [])
        for analyzer_id in ("csa", "codeql"):
            analyzer_info = result.analyzer_results.get(analyzer_id, {})
            if not isinstance(analyzer_info, dict):
                continue
            history = analyzer_info.get("validation_feedback_history", []) or []
            for item in history:
                if isinstance(item, dict):
                    combined_history.append(copy.deepcopy(item))

        if combined_history:
            deduped: List[Dict[str, Any]] = []
            seen = set()
            for item in combined_history:
                key = (
                    str(item.get("analyzer", "") or "").strip(),
                    str(item.get("phase", "") or "").strip(),
                    str(item.get("summary", "") or "").strip(),
                )
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(item)
            patchweaver["validation_feedback_history"] = deduped[-6:]

        return patchweaver

    def _build_run_metrics(self, output_path: Path) -> Dict[str, Any]:
        """从 run_events.jsonl 提取阶段耗时与 agent 漂移指标。"""
        event_log_path = output_path / "run_events.jsonl"
        if not event_log_path.exists():
            return {}

        events: List[Dict[str, Any]] = []
        try:
            for line in event_log_path.read_text(encoding="utf-8").splitlines():
                raw = line.strip()
                if not raw:
                    continue
                payload = json.loads(raw)
                if isinstance(payload, dict):
                    events.append(payload)
        except Exception as exc:
            logger.warning(f"读取运行事件日志失败: {exc}")
            return {}

        if not events:
            return {}

        events.sort(key=lambda item: float(item.get("timestamp", 0.0) or 0.0))
        first_ts = float(events[0].get("timestamp", 0.0) or 0.0)
        last_ts = float(events[-1].get("timestamp", first_ts) or first_ts)

        metrics: Dict[str, Any] = {
            "event_count": len(events),
            "total_seconds": round(max(0.0, last_ts - first_ts), 3),
            "preflight_seconds": self._event_window_seconds(events, "patchweaver", "preflight_started", "preflight_completed"),
            "analyzers": {},
        }

        for analyzer_id in ("csa", "codeql"):
            analyzer_events = [item for item in events if str(item.get("analyzer", "")).strip() == analyzer_id]
            analyzer_metrics = self._build_analyzer_run_metrics(analyzer_events)
            if analyzer_metrics:
                metrics["analyzers"][analyzer_id] = analyzer_metrics

        overall_usage = self._aggregate_llm_usage_from_events(events)
        if overall_usage["call_count"] > 0:
            metrics["llm_usage"] = overall_usage

        summaries: List[str] = []
        if metrics.get("preflight_seconds") is not None:
            summaries.append(f"preflight={metrics['preflight_seconds']:.1f}s")
        for analyzer_id in ("csa", "codeql"):
            analyzer_info = metrics["analyzers"].get(analyzer_id, {})
            if not analyzer_info:
                continue
            total_seconds = analyzer_info.get("total_seconds")
            bottleneck = analyzer_info.get("bottleneck")
            if total_seconds is None:
                continue
            if bottleneck:
                summaries.append(f"{analyzer_id}={total_seconds:.1f}s({bottleneck})")
            else:
                summaries.append(f"{analyzer_id}={total_seconds:.1f}s")
        if metrics.get("llm_usage", {}).get("available"):
            summaries.append(f"tokens={metrics['llm_usage'].get('total_tokens', 0)}")
        if summaries:
            metrics["summary"] = " | ".join(summaries)

        return metrics

    def _build_analyzer_run_metrics(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not events:
            return {}

        metrics: Dict[str, Any] = {}
        events.sort(key=lambda item: float(item.get("timestamp", 0.0) or 0.0))

        first_ts = float(events[0].get("timestamp", 0.0) or 0.0)
        last_ts = float(events[-1].get("timestamp", first_ts) or first_ts)
        metrics["total_seconds"] = round(max(0.0, last_ts - first_ts), 3)

        for key, start_event, end_event in (
            ("queue_wait_seconds", "submitted", "generation_started"),
            ("evidence_seconds", "evidence_collection_started", "evidence_collection_completed"),
            ("synthesis_seconds", "evidence_collection_completed", "synthesis_input_prepared"),
            ("agent_seconds", "agent_run_started", "agent_run_completed"),
            ("validation_seconds", "validation_started", "validation_completed"),
        ):
            window = self._event_window_seconds(events, None, start_event, end_event)
            if window is not None:
                metrics[key] = window

        think_seconds = self._sum_event_pairs(events, "agent_think_started", "agent_think_completed")
        if think_seconds is not None:
            metrics["agent_think_seconds"] = think_seconds
        tool_seconds = self._sum_event_pairs(events, "agent_tool_called", "agent_tool_result")
        if tool_seconds is not None:
            metrics["agent_tool_seconds"] = tool_seconds
        llm_seconds = self._sum_event_pairs(events, "agent_llm_call_started", "agent_llm_call_completed")
        if llm_seconds is not None:
            metrics["agent_llm_seconds"] = llm_seconds
        agent_usage = self._aggregate_llm_usage_from_events(events, event_name="agent_llm_call_completed")
        tool_usage = self._aggregate_llm_usage_from_events(events, event_name="tool_result")
        total_usage = merge_usages([agent_usage, tool_usage])
        if total_usage["call_count"] > 0:
            metrics["llm_usage"] = {
                "agent": agent_usage,
                "tool": tool_usage,
                "total": total_usage,
            }
            metrics["llm_calls"] = total_usage["call_count"]

        early_search_count = 0
        deferred_patch_reads = 0
        deferred_knowledge_searches = 0
        first_material_ts: Optional[float] = None
        agent_start_ts = self._first_event_timestamp(events, "agent_run_started")

        for item in events:
            event = str(item.get("event", "")).strip()
            tool_name = str(item.get("tool_name", "")).strip()
            iteration = int(item.get("iteration", 0) or 0)
            ts = float(item.get("timestamp", 0.0) or 0.0)

            if event == "agent_tool_called" and tool_name == "search_knowledge" and iteration <= 2:
                early_search_count += 1
            if event == "agent_tool_result" and tool_name == "read_file":
                summary = str(item.get("summary", "") or "")
                if "shared context already includes patch analysis" in summary:
                    deferred_patch_reads += 1
            if event == "agent_tool_result" and tool_name == "search_knowledge":
                summary = str(item.get("summary", "") or "")
                if "Do not search the knowledge base before you have drafted" in summary:
                    deferred_knowledge_searches += 1
            if event == "agent_tool_called" and tool_name in {"write_file", "generate_codeql_query", "compile_checker", "codeql_analyze", "review_artifact"}:
                if first_material_ts is None:
                    first_material_ts = ts

        metrics["early_search_knowledge_calls"] = early_search_count
        metrics["deferred_patch_reads"] = deferred_patch_reads
        metrics["deferred_knowledge_searches"] = deferred_knowledge_searches
        if agent_start_ts is not None and first_material_ts is not None:
            metrics["first_material_action_seconds"] = round(max(0.0, first_material_ts - agent_start_ts), 3)

        stage_candidates = {
            "queue_wait": metrics.get("queue_wait_seconds"),
            "evidence": metrics.get("evidence_seconds"),
            "agent": metrics.get("agent_seconds"),
            "validation": metrics.get("validation_seconds"),
        }
        valid_candidates = {key: value for key, value in stage_candidates.items() if isinstance(value, (int, float))}
        if valid_candidates:
            metrics["bottleneck"] = max(valid_candidates, key=valid_candidates.get)

        return metrics

    def _event_window_seconds(
        self,
        events: List[Dict[str, Any]],
        analyzer_id: Optional[str],
        start_event: str,
        end_event: str,
    ) -> Optional[float]:
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        for item in events:
            if analyzer_id and str(item.get("analyzer", "")).strip() != analyzer_id:
                continue
            event = str(item.get("event", "")).strip()
            ts = float(item.get("timestamp", 0.0) or 0.0)
            if start_ts is None and event == start_event:
                start_ts = ts
            if event == end_event:
                end_ts = ts
                if start_ts is not None:
                    break
        if start_ts is None or end_ts is None:
            return None
        return round(max(0.0, end_ts - start_ts), 3)

    def _first_event_timestamp(self, events: List[Dict[str, Any]], event_name: str) -> Optional[float]:
        for item in events:
            if str(item.get("event", "")).strip() == event_name:
                return float(item.get("timestamp", 0.0) or 0.0)
        return None

    def _sum_event_pairs(
        self,
        events: List[Dict[str, Any]],
        start_event: str,
        end_event: str,
    ) -> Optional[float]:
        total = 0.0
        pending: Optional[float] = None
        matched = False
        for item in events:
            event = str(item.get("event", "")).strip()
            ts = float(item.get("timestamp", 0.0) or 0.0)
            if event == start_event and pending is None:
                pending = ts
                continue
            if event == end_event and pending is not None:
                total += max(0.0, ts - pending)
                pending = None
                matched = True
        if not matched:
            return None
        return round(total, 3)

    def _aggregate_llm_usage_from_events(
        self,
        events: List[Dict[str, Any]],
        event_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        usages: List[Dict[str, Any]] = []
        for item in events:
            if event_name and str(item.get("event", "")).strip() != event_name:
                continue
            raw_usage = item.get("llm_usage", {})
            if not isinstance(raw_usage, dict):
                continue
            usage = normalize_usage(raw_usage)
            if usage["call_count"] <= 0 and usage["available"]:
                usage["call_count"] = 1
            if usage["call_count"] > 0 or usage["available"]:
                usages.append(usage)
        return merge_usages(usages)

    def _generate_markdown_report(
        self,
        report_data: Dict[str, Any],
        output_path: Path
    ):
        """生成 Markdown 格式的可读报告"""
        md_path = output_path / "report.md"

        lines = [
            "# 检测器精炼报告" if str(report_data.get("meta", {}).get("workflow_mode", "") or "") == "refine" else "# 检测器生成报告",
            "",
            f"**生成时间**: {report_data['meta']['generated_at']}",
            f"**分析器模式**: {report_data['meta']['analyzer_type']}",
        ]
        workflow_mode = str(report_data.get("meta", {}).get("workflow_mode", "generate") or "generate").strip()
        generation_success = bool(report_data.get("meta", {}).get("generation_success", report_data["meta"]["success"]))
        semantic_success = bool(report_data.get("meta", {}).get("semantic_success", report_data["meta"]["success"]))
        if workflow_mode == "refine":
            if self._report_has_unadopted_refinement(report_data):
                lines.append("**状态**: ⚠️ 保持当前产物；本轮精炼未产生可采纳更新")
            elif semantic_success and self._report_has_target_hit(report_data):
                lines.append("**状态**: ✅ 精炼后命中验证目标并通过功能验证")
            elif semantic_success:
                lines.append("**状态**: ⚠️ 精炼完成，但当前未命中验证目标")
            elif generation_success:
                lines.append("**状态**: ⚠️ 精炼已执行，但未通过功能验证")
            else:
                lines.append("**状态**: ❌ 精炼失败")
        elif semantic_success and self._report_has_target_hit(report_data):
            lines.append("**状态**: ✅ 命中验证目标并通过功能验证")
        elif semantic_success:
            lines.append("**状态**: ⚠️ 功能验证执行成功，但当前未命中验证目标")
        elif generation_success:
            lines.append("**状态**: ⚠️ 已生成但未通过功能验证")
        else:
            lines.append("**状态**: ❌ 生成失败")
        preferred_analyzer = report_data.get("meta", {}).get("preferred_analyzer", "")
        if preferred_analyzer:
            lines.append(f"**首选分析器**: {preferred_analyzer}")
        lines.extend([
            "",
            "---",
            "",
        ])
        lines.extend(self._build_markdown_overview(report_data))

        # CSA 结果
        csa = report_data.get("csa", {})
        lines.append("## CSA (Clang Static Analyzer)")
        lines.append("")
        lines.append(f"- **生成状态**: {'✅ 已生成' if csa.get('success') else '❌ 失败'}")
        if csa.get("validation_requested"):
            lines.append(f"- **功能验证**: {self._validation_state_label(csa.get('validation_state'))}")
        if csa.get("semantic_acceptance_summary"):
            lines.append(f"- **功能验证摘要**: {csa.get('semantic_acceptance_summary')}")
        lines.append(f"- **检测器名称**: {csa.get('artifact_display_name') or csa.get('checker_name', 'N/A')}")
        lines.append(f"- **迭代次数**: {csa.get('iterations', 0)}")
        if workflow_mode == "refine" and csa.get("refinement_attempted"):
            lines.append(f"- **精炼尝试**: {csa.get('refinement_iterations_attempted', 0)} 轮")
            lines.append(
                f"- **精炼采纳**: {'✅ 已采纳新产物' if csa.get('refinement_adopted') else '⚠️ 未采纳，当前保持原产物'}"
            )
            if not csa.get("refinement_adopted") and csa.get("last_refinement_candidate_error"):
                lines.append(f"- **最近候选失败**: {csa.get('last_refinement_candidate_error')}")
        elif workflow_mode == "refine" and csa.get("refinement_skipped_reason"):
            lines.append("- **精炼决策**: 跳过，当前基线已满足严格精炼质量门")
            lines.append(f"- **跳过原因**: {csa.get('refinement_skipped_reason')}")
        if csa.get("evidence_records") is not None:
            lines.append(f"- **证据数量**: {csa.get('evidence_records', 0)}")
        if csa.get("semantic_slice_records") is not None:
            lines.append(f"- **语义切片**: {csa.get('semantic_slice_records', 0)}")
        if csa.get("context_summary_records"):
            lines.append(f"- **上下文摘要**: {csa.get('context_summary_records', 0)}")
        if csa.get("slice_coverage"):
            lines.append(f"- **切片覆盖**: {csa.get('slice_coverage')}")
        csa_escalation = csa.get("evidence_escalation", {}) if isinstance(csa.get("evidence_escalation"), dict) else {}
        if csa_escalation.get("requested"):
            lines.append(f"- **证据升级**: {csa_escalation.get('reason', '')}")
        if csa.get("evidence_degraded"):
            lines.append("- **证据状态**: ⚠️ 降级")
        csa_missing = csa.get("missing_evidence", []) or []
        if csa_missing:
            lines.append(f"- **缺失证据**: {', '.join(map(str, csa_missing[:6]))}")
        csa_synthesis = csa.get("synthesis_input", {}) if isinstance(csa, dict) else {}
        if csa_synthesis.get("primary_pattern"):
            lines.append(f"- **合成目标模式**: {csa_synthesis.get('primary_pattern')}")
        if csa_synthesis.get("selected_semantic_slice_ids"):
            lines.append(f"- **已选语义切片**: {len(csa_synthesis.get('selected_semantic_slice_ids', []) or [])}")
        if csa_synthesis.get("selected_context_summary_ids"):
            lines.append(f"- **已选上下文摘要**: {len(csa_synthesis.get('selected_context_summary_ids', []) or [])}")
        if csa_synthesis.get("repair_directives"):
            lines.append(f"- **修复指令**: {len(csa_synthesis.get('repair_directives', []) or [])}")
        if csa_synthesis.get("missing_evidence_types"):
            lines.append(f"- **合成输入缺口**: {', '.join(map(str, csa_synthesis.get('missing_evidence_types', [])[:6]))}")
        if csa.get("validation_feedback_records") is not None:
            lines.append(f"- **验证反馈数量**: {csa.get('validation_feedback_records', 0)}")
        csa_effectiveness = csa.get("evidence_effectiveness", {}) if isinstance(csa.get("evidence_effectiveness"), dict) else {}
        if csa_effectiveness.get("summary"):
            lines.append(f"- **证据反馈成效**: {csa_effectiveness.get('summary')}")

        csa_validation = csa.get("validation", {}) if isinstance(csa, dict) else {}
        if csa_validation:
            lines.append(f"- **验证阶段**: {csa_validation.get('stage', 'N/A')}")
            lines.append(f"- **验证状态**: {'✅ 成功' if csa_validation.get('success') else '❌ 失败'}")
            lines.append(f"- **诊断数量**: {csa_validation.get('diagnostics_count', 0)}")
            lines.append(f"- **Warning 数量**: {csa_validation.get('warnings_count', 0)}")

            diagnostics = csa_validation.get("diagnostics", []) or []
            if diagnostics:
                lines.append("")
                lines.append("### CSA 验证诊断（最多10条）")
                for d in diagnostics[:10]:
                    file_path = d.get("file_path", "")
                    line_no = d.get("line", 0)
                    sev = d.get("severity", "warning")
                    msg = d.get("message", "")
                    lines.append(f"- [{sev}] {file_path}:{line_no} - {msg}")
        csa_feedback_summary = str(csa.get("validation_feedback_summary", "") or "").strip()
        if csa_feedback_summary:
            lines.append("")
            lines.append("### CSA 验证反馈")
            for item in csa_feedback_summary.splitlines()[:6]:
                lines.append(item if item.startswith("- ") else f"- {item}")
        lines.append("")

        # CodeQL 结果
        codeql = report_data.get("codeql", {})
        lines.append("## CodeQL")
        lines.append("")
        lines.append(f"- **生成状态**: {'✅ 已生成' if codeql.get('success') else '❌ 失败'}")
        if codeql.get("validation_requested"):
            lines.append(f"- **功能验证**: {self._validation_state_label(codeql.get('validation_state'))}")
        if codeql.get("semantic_acceptance_summary"):
            lines.append(f"- **功能验证摘要**: {codeql.get('semantic_acceptance_summary')}")
        lines.append(f"- **查询名称**: {codeql.get('artifact_display_name') or codeql.get('checker_name', 'N/A')}")
        if workflow_mode == "refine" and codeql.get("refinement_attempted"):
            lines.append(f"- **精炼尝试**: {codeql.get('refinement_iterations_attempted', 0)} 轮")
            lines.append(
                f"- **精炼采纳**: {'✅ 已采纳新产物' if codeql.get('refinement_adopted') else '⚠️ 未采纳，当前保持原产物'}"
            )
            if not codeql.get("refinement_adopted") and codeql.get("last_refinement_candidate_error"):
                lines.append(f"- **最近候选失败**: {codeql.get('last_refinement_candidate_error')}")
        elif workflow_mode == "refine" and codeql.get("refinement_skipped_reason"):
            lines.append("- **精炼决策**: 跳过，当前基线已满足严格精炼质量门")
            lines.append(f"- **跳过原因**: {codeql.get('refinement_skipped_reason')}")
        if codeql.get("evidence_records") is not None:
            lines.append(f"- **证据数量**: {codeql.get('evidence_records', 0)}")
        if codeql.get("semantic_slice_records") is not None:
            lines.append(f"- **语义切片**: {codeql.get('semantic_slice_records', 0)}")
        if codeql.get("context_summary_records"):
            lines.append(f"- **上下文摘要**: {codeql.get('context_summary_records', 0)}")
        if codeql.get("slice_coverage"):
            lines.append(f"- **切片覆盖**: {codeql.get('slice_coverage')}")
        codeql_escalation = codeql.get("evidence_escalation", {}) if isinstance(codeql.get("evidence_escalation"), dict) else {}
        if codeql_escalation.get("requested"):
            lines.append(f"- **证据升级**: {codeql_escalation.get('reason', '')}")
        if codeql.get("evidence_degraded"):
            lines.append("- **证据状态**: ⚠️ 降级")
        codeql_missing = codeql.get("missing_evidence", []) or []
        if codeql_missing:
            lines.append(f"- **缺失证据**: {', '.join(map(str, codeql_missing[:6]))}")
        codeql_synthesis = codeql.get("synthesis_input", {}) if isinstance(codeql, dict) else {}
        if codeql_synthesis.get("primary_pattern"):
            lines.append(f"- **合成目标模式**: {codeql_synthesis.get('primary_pattern')}")
        if codeql_synthesis.get("selected_semantic_slice_ids"):
            lines.append(f"- **已选语义切片**: {len(codeql_synthesis.get('selected_semantic_slice_ids', []) or [])}")
        if codeql_synthesis.get("selected_context_summary_ids"):
            lines.append(f"- **已选上下文摘要**: {len(codeql_synthesis.get('selected_context_summary_ids', []) or [])}")
        if codeql_synthesis.get("repair_directives"):
            lines.append(f"- **修复指令**: {len(codeql_synthesis.get('repair_directives', []) or [])}")
        if codeql_synthesis.get("missing_evidence_types"):
            lines.append(f"- **合成输入缺口**: {', '.join(map(str, codeql_synthesis.get('missing_evidence_types', [])[:6]))}")
        if codeql.get("validation_feedback_records") is not None:
            lines.append(f"- **验证反馈数量**: {codeql.get('validation_feedback_records', 0)}")
        codeql_effectiveness = codeql.get("evidence_effectiveness", {}) if isinstance(codeql.get("evidence_effectiveness"), dict) else {}
        if codeql_effectiveness.get("summary"):
            lines.append(f"- **证据反馈成效**: {codeql_effectiveness.get('summary')}")
        codeql_validation = codeql.get("validation", {}) if isinstance(codeql, dict) else {}
        if codeql_validation:
            lines.append(f"- **验证状态**: {'✅ 成功' if codeql_validation.get('success') else '❌ 失败'}")
            lines.append(f"- **诊断数量**: {codeql_validation.get('diagnostics_count', 0)}")
        codeql_feedback_summary = str(codeql.get("validation_feedback_summary", "") or "").strip()
        if codeql_feedback_summary:
            lines.append("")
            lines.append("### CodeQL 验证反馈")
            for item in codeql_feedback_summary.splitlines()[:6]:
                lines.append(item if item.startswith("- ") else f"- {item}")
        lines.append("")

        # 产物位置
        artifacts = report_data.get("artifacts", {})
        lines.append("## 产物位置")
        lines.append("")
        lines.append(f"- CSA 目录: `{self._short_report_path(artifacts.get('csa_dir', 'N/A'), output_path)}`")
        lines.append(f"- CodeQL 目录: `{self._short_report_path(artifacts.get('codeql_dir', 'N/A'), output_path)}`")
        lines.append(f"- PATCHWEAVER 计划: `{self._short_report_path(artifacts.get('patchweaver_plan', 'N/A'), output_path)}`")
        lines.append(f"- 验证反馈: `{self._short_report_path(artifacts.get('validation_feedback', 'N/A'), output_path)}`")
        lines.append(f"- 整合报告: `{self._short_report_path(artifacts.get('final_report', 'N/A'), output_path)}`")
        lines.append("")

        patchweaver = report_data.get("patchweaver", {}) if isinstance(report_data.get("patchweaver"), dict) else {}
        evidence_plan = patchweaver.get("evidence_plan", {}) if isinstance(patchweaver, dict) else {}
        if evidence_plan:
            lines.append("## PATCHWEAVER")
            lines.append("")
            if patchweaver.get("summary"):
                lines.append(f"- **机制摘要**: {patchweaver.get('summary')}")
            requirements = evidence_plan.get("requirements", []) or []
            if requirements:
                planned = ", ".join(
                    item.get("evidence_type", "")
                    for item in requirements[:6]
                    if item.get("evidence_type")
                )
                if planned:
                    lines.append(f"- **计划证据**: {planned}")
            recommended = evidence_plan.get("recommended_analyzers", []) or []
            if recommended:
                lines.append(f"- **推荐分析器**: {', '.join(map(str, recommended))}")
            coverage_gaps = evidence_plan.get("coverage_gaps", []) or []
            if coverage_gaps:
                lines.append("- **覆盖缺口**:")
                for item in coverage_gaps[:5]:
                    lines.append(f"  - {item}")
            escalation = patchweaver.get("evidence_escalation", {}) or {}
            if escalation.get("requested"):
                lines.append(f"- **证据升级**: {escalation.get('reason', '')}")
            feedback_history = patchweaver.get("validation_feedback_history", []) or []
            if feedback_history:
                lines.append("- **验证反馈历史**:")
                for item in feedback_history[-3:]:
                    if not isinstance(item, dict):
                        continue
                    analyzer_id = str(item.get("analyzer", "") or "").strip()
                    phase = str(item.get("phase", "") or "").strip() or "validation"
                    summary = str(item.get("summary", "") or "").strip().replace("\n", " | ")
                    if summary:
                        prefix = f"[{analyzer_id}] " if analyzer_id else ""
                        lines.append(f"  - {prefix}phase={phase}: {summary}")
            lines.append("")

        portfolio = report_data.get("portfolio", {}) if isinstance(report_data.get("portfolio"), dict) else {}
        if portfolio:
            lines.append("## Portfolio")
            lines.append("")
            if portfolio.get("preferred_analyzer"):
                lines.append(f"- **首选分析器**: {portfolio.get('preferred_analyzer')}")
            if portfolio.get("preferred_checker_name"):
                lines.append(f"- **首选产物**: {portfolio.get('preferred_checker_name')}")
            if portfolio.get("confidence"):
                lines.append(f"- **决策置信度**: {portfolio.get('confidence')}")
            if portfolio.get("summary"):
                lines.append(f"- **决策摘要**: {portfolio.get('summary')}")
            bundle = portfolio.get("recommended_bundle", []) or []
            if bundle:
                lines.append(f"- **推荐组合**: {', '.join(map(str, bundle))}")
            usage = portfolio.get("complementary_usage", []) or []
            if usage:
                lines.append("- **组合建议**:")
                for item in usage[:4]:
                    lines.append(f"  - {item}")
            candidates = portfolio.get("candidates", []) or []
            if candidates:
                lines.append("")
                lines.append("### 候选排序")
                for item in candidates[:5]:
                    lines.append(
                        f"- {item.get('analyzer_id', 'unknown')}: "
                        f"score={item.get('score', 0)}, "
                        f"accepted={'Y' if item.get('accepted') else 'N'}, "
                        f"semantic={'Y' if item.get('semantic_success') else 'N'}, "
                        f"evidence={item.get('evidence_records', 0)}, "
                        f"missing={item.get('missing_evidence', 0)}, "
                        f"degraded={'Y' if item.get('evidence_degraded') else 'N'}"
                    )
            lines.append("")

        # 错误信息
        if not report_data['meta']['success'] and report_data['meta'].get('error_message'):
            lines.append("## 错误信息")
            lines.append("")
            lines.append(f"```\n{report_data['meta']['error_message']}\n```")
            lines.append("")

        md_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info(f"Markdown 报告已保存: {md_path}")

    def _report_has_unadopted_refinement(self, report_data: Dict[str, Any]) -> bool:
        if str(report_data.get("meta", {}).get("workflow_mode", "") or "").strip() != "refine":
            return False
        for analyzer_id in ("csa", "codeql"):
            analyzer_info = report_data.get(analyzer_id, {})
            if not isinstance(analyzer_info, dict):
                continue
            if analyzer_info.get("refinement_attempted") and not analyzer_info.get("refinement_adopted"):
                return True
        return False

    def _build_markdown_overview(self, report_data: Dict[str, Any]) -> List[str]:
        """构建报告顶部总览表，让读者先看到结果矩阵，再进入细节。"""
        metrics = report_data.get("run_metrics", {}) if isinstance(report_data.get("run_metrics"), dict) else {}
        rows: List[str] = []
        for analyzer_id, label in (("csa", "CSA"), ("codeql", "CodeQL")):
            info = report_data.get(analyzer_id, {})
            if not isinstance(info, dict) or not info:
                continue
            validation = info.get("validation", {}) if isinstance(info.get("validation"), dict) else {}
            note = self._first_report_highlight(info)
            rows.append(
                "| {label} | {gen} | {accept} | {diag} | {note} |".format(
                    label=label,
                    gen=self._markdown_status(info.get("success")),
                    accept=self._validation_state_label(info.get("validation_state")),
                    diag=validation.get("diagnostics_count", 0) if validation else "-",
                    note=note or "—",
                )
            )

        if not rows:
            return []

        lines = [
            "## 总览",
            "",
        ]
        if metrics.get("summary"):
            lines.append(f"- 运行摘要: {metrics.get('summary')}")
        if isinstance(metrics.get("analyzers"), dict):
            for analyzer_id, label in (("csa", "CSA"), ("codeql", "CodeQL")):
                analyzer_metrics = metrics["analyzers"].get(analyzer_id, {})
                if not analyzer_metrics:
                    continue
                parts: List[str] = []
                for key, display in (
                    ("evidence_seconds", "evidence"),
                    ("agent_seconds", "agent"),
                    ("validation_seconds", "validation"),
                ):
                    value = analyzer_metrics.get(key)
                    if isinstance(value, (int, float)):
                        parts.append(f"{display}={value:.1f}s")
                if isinstance(analyzer_metrics.get("first_material_action_seconds"), (int, float)):
                    parts.append(f"first_action={analyzer_metrics['first_material_action_seconds']:.1f}s")
                llm_usage = ((analyzer_metrics.get("llm_usage") or {}).get("total", {}) if isinstance(analyzer_metrics.get("llm_usage"), dict) else {})
                if isinstance(llm_usage, dict) and llm_usage.get("available"):
                    parts.append(f"tokens={llm_usage.get('total_tokens', 0)}")
                if analyzer_metrics.get("deferred_patch_reads") or analyzer_metrics.get("deferred_knowledge_searches"):
                    parts.append(
                        "deferrals={patch}/{knowledge}".format(
                            patch=analyzer_metrics.get("deferred_patch_reads", 0),
                            knowledge=analyzer_metrics.get("deferred_knowledge_searches", 0),
                        )
                    )
                if parts:
                    lines.append(f"- {label} 阶段耗时: {', '.join(parts)}")
        lines.extend([
            "",
            "| 分析器 | 生成 | 验证状态 | 诊断数 | 关键提示 |",
            "| --- | --- | --- | --- | --- |",
            *rows,
            "",
        ])
        return lines

    def _first_report_highlight(self, analyzer_info: Dict[str, Any]) -> str:
        """从反馈摘要/验收摘要中抽取第一条最值得先看的信息。"""
        feedback_summary = str(analyzer_info.get("validation_feedback_summary", "") or "").strip()
        for line in feedback_summary.splitlines():
            cleaned = line.strip()
            if cleaned:
                return cleaned.removeprefix("- ").replace("|", "/")[:120]

        semantic_summary = str(analyzer_info.get("semantic_acceptance_summary", "") or "").strip()
        if semantic_summary:
            return semantic_summary.replace("|", "/")[:120]

        error = str(analyzer_info.get("error", "") or "").strip()
        if error:
            return error.replace("\n", " ")[:120]
        return ""

    def _markdown_status(self, value: Any) -> str:
        if value is True:
            return "✅"
        if value is False:
            return "❌"
        return "—"

    def _validation_state_label(self, state: Any) -> str:
        normalized = str(state or "").strip()
        labels = {
            "target_hit": "✅ 命中目标",
            "executed_no_hit": "⚠️ 仅执行成功",
            "execution_failed": "❌ 执行失败",
            "not_requested": "— 未验证",
            "generation_failed": "❌ 未生成",
            "no_result": "—",
        }
        return labels.get(normalized, "—")

    def _report_has_target_hit(self, report_data: Dict[str, Any]) -> bool:
        for analyzer_id in ("csa", "codeql"):
            analyzer_info = report_data.get(analyzer_id, {})
            if isinstance(analyzer_info, dict) and analyzer_info.get("semantic_target_hit"):
                return True
        return False

    def _short_report_path(self, path_value: Any, output_path: Path) -> str:
        """尽量将绝对路径收缩为相对路径，减少报告里的视觉噪声。"""
        text = str(path_value or "").strip()
        if not text:
            return "N/A"
        if text == "N/A":
            return text
        try:
            path = Path(text)
            if path.is_absolute():
                try:
                    return str(path.relative_to(output_path))
                except ValueError:
                    return str(path)
        except Exception:
            return text
        return text
