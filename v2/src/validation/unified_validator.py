"""
统一验证器 - 聚合 LSP 与语义验证
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from loguru import logger

from .lsp_validator import LSPValidator
from .semantic_validator import SemanticValidator
from .types import AnalyzerType, UnifiedValidationResult


class UnifiedValidator:
    """
    统一验证器

    整合 LSP 和语义验证，支持 CSA 和 CodeQL 并行验证。
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.lsp_validator = LSPValidator(config.get("lsp", {}))
        self.semantic_validator = SemanticValidator(config.get("semantic", {}))
        self.max_workers = config.get("max_workers", 4)

    def validate_all(
        self,
        csa_code: str = None,
        csa_so_path: str = None,
        csa_checker_name: str = None,
        codeql_query: str = None,
        codeql_query_path: str = None,
        codeql_database_path: str = None,
        target_path: str = None,
        analyzers: AnalyzerType = AnalyzerType.BOTH,
        on_progress: callable = None,
    ) -> UnifiedValidationResult:
        start_time = time.time()
        result = UnifiedValidationResult()

        lsp_tasks = []
        semantic_tasks = []
        required_tasks: List[str] = []

        if analyzers in [AnalyzerType.CSA, AnalyzerType.BOTH]:
            if csa_code:
                lsp_tasks.append(("csa_lsp", self.lsp_validator.validate_csa_code, csa_code, []))
                required_tasks.append("csa_lsp")
            if csa_so_path and csa_checker_name and target_path:
                semantic_tasks.append((
                    "csa_semantic",
                    self.semantic_validator.validate_csa_checker,
                    (csa_so_path, csa_checker_name, target_path),
                    ["csa_lsp"] if csa_code else [],
                ))
                required_tasks.append("csa_semantic")

        if analyzers in [AnalyzerType.CODEQL, AnalyzerType.BOTH]:
            if codeql_query:
                lsp_tasks.append(("codeql_lsp", self.lsp_validator.validate_codeql_query, codeql_query, []))
                required_tasks.append("codeql_lsp")
            if codeql_query_path and codeql_database_path:
                semantic_tasks.append((
                    "codeql_semantic",
                    self.semantic_validator.validate_codeql_query,
                    (codeql_query_path, codeql_database_path, target_path),
                    ["codeql_lsp"] if codeql_query else [],
                ))
                required_tasks.append("codeql_semantic")

        self._execute_validation_tasks(result, lsp_tasks, on_progress)

        runnable_semantic_tasks = []
        for task_name, func, args, dependencies in semantic_tasks:
            if dependencies and not self._check_task_group_success(result.task_status, dependencies):
                result.task_status[task_name] = False
                continue
            runnable_semantic_tasks.append((task_name, func, args, dependencies))

        self._execute_validation_tasks(result, runnable_semantic_tasks, on_progress)

        lsp_task_names = [task for task in required_tasks if task.endswith("_lsp")]
        semantic_task_names = [task for task in required_tasks if task.endswith("_semantic")]
        result.syntax_valid = self._check_task_group_success(result.task_status, lsp_task_names)
        result.lsp_valid = result.syntax_valid
        result.semantic_valid = self._check_task_group_success(result.task_status, semantic_task_names)
        result.overall_success = self._check_task_group_success(result.task_status, required_tasks)
        result.execution_time = time.time() - start_time
        result.summary = self._generate_summary(result)
        return result

    def _execute_validation_tasks(
        self,
        result: UnifiedValidationResult,
        tasks: List[Tuple[str, Any, Any, List[str]]],
        on_progress: callable = None,
    ):
        if not tasks:
            return

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for task in tasks:
                task_name, func, args, _dependencies = task
                if not isinstance(args, tuple):
                    args = (args,)
                if on_progress:
                    on_progress(task_name, "started")
                future = executor.submit(func, *args)
                futures[future] = task_name

            for future in as_completed(futures):
                task_name = futures[future]
                try:
                    validation_result = future.result()
                    if task_name.startswith("csa_"):
                        result.csa_results[task_name] = validation_result
                    elif task_name.startswith("codeql_"):
                        result.codeql_results[task_name] = validation_result

                    result.all_diagnostics.extend(validation_result.diagnostics)
                    result.task_status[task_name] = bool(validation_result.success)

                    if on_progress:
                        on_progress(task_name, "completed" if validation_result.success else "failed")
                except Exception as exc:
                    logger.error(f"验证任务失败 {task_name}: {exc}")
                    result.task_status[task_name] = False
                    if on_progress:
                        on_progress(task_name, "error")

    def _check_task_group_success(self, task_status: Dict[str, bool], task_names: List[str]) -> bool:
        if not task_names:
            return False
        return all(task_status.get(name, False) for name in task_names)

    def _generate_summary(self, result: UnifiedValidationResult) -> str:
        lines = [
            "=" * 50,
            "验证结果摘要",
            "=" * 50,
            f"总体状态: {'✅ 成功' if result.overall_success else '❌ 失败'}",
            f"语法验证: {'✅' if result.syntax_valid else '❌'}",
            f"语义验证: {'✅' if result.semantic_valid else '❌'}",
            f"总诊断数: {len(result.all_diagnostics)}",
            f"执行时间: {result.execution_time:.2f}秒",
        ]

        if result.task_status:
            lines.append("\n任务状态:")
            for name in sorted(result.task_status.keys()):
                lines.append(f"  - {name}: {'✅' if result.task_status[name] else '❌'}")

        errors = [diag for diag in result.all_diagnostics if diag.severity == "error"]
        warnings = [diag for diag in result.all_diagnostics if diag.severity == "warning"]

        if errors:
            lines.append(f"\n❌ 错误 ({len(errors)}):")
            for item in errors[:5]:
                lines.append(f"  - {item.file_path}:{item.line}: {item.message}")

        if warnings:
            lines.append(f"\n⚠️ 警告 ({len(warnings)}):")
            for item in warnings[:5]:
                lines.append(f"  - {item.file_path}:{item.line}: {item.message}")

        return "\n".join(lines)


def create_validator(config: Dict[str, Any] = None) -> UnifiedValidator:
    """创建统一验证器。"""
    return UnifiedValidator(config)

