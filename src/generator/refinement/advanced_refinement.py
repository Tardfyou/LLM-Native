"""
Advanced Refinement System
高级精炼系统 - 参考KNighter的checker_refine.py实现

提供基于FP报告的迭代精炼功能
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

# 使用绝对导入（PYTHONPATH 包含 src/）
from generator.refinement.report_triage import ReportTriage, ReportData
from generator.models.refinement_models import (
    RefinementResult,
    RefineAttempt,
    GenerationProgress
)
from model.llm_client import LLMClient
from generator.utils.code_utils import (
    extract_checker_code,
    error_formatting,
    grab_error_message
)

logger = logging.getLogger(__name__)


class AdvancedRefinement:
    """
    高级精炼系统

    特性:
    - 基于FP报告的迭代精炼
    - 对象级验证
    - Code change tracking
    - 详细的日志记录
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        triage: Optional[ReportTriage] = None,
        max_attempts: int = 3
    ):
        """
        初始化高级精炼系统

        Args:
            llm_client: LLM客户端
            triage: 报告分类器
            max_attempts: 最大精炼尝试次数
        """
        self.llm_client = llm_client
        self.triage = triage or ReportTriage(llm_client)
        self.max_attempts = max_attempts

        # 加载修复模板
        self._repair_template = self._load_repair_template()

    def _load_repair_template(self) -> str:
        """加载修复提示词模板"""
        return """You are a static analysis checker refinement expert. Your task is to fix false positive issues in a checker.

# Current Checker Code:
```cpp
{{checker_code}}
```

# Vulnerability Pattern to Detect:
{{pattern}}

# False Positive Report:
```
{{fp_report}}
```

# Analysis of the False Positive:
{{fp_analysis}}

# Task:
Modify the checker code to eliminate this false positive while still detecting the actual vulnerability pattern. Your modifications should:

1. Add additional constraints to avoid the false positive case
2. Preserve the ability to detect the real vulnerability
3. Maintain code clarity and efficiency

# Utility Functions Available:
{{utility_functions}}

# Suggestions:
- Consider adding path sensitivity analysis
- Add state tracking to distinguish valid from invalid cases
- Use context information to refine the detection logic

Please provide:
1. Analysis of why this false positive occurs
2. Specific code changes to fix it
3. The complete fixed checker code

Provide your response below:
"""

    def refine_with_feedback(
        self,
        checker_code: str,
        pattern: str,
        fp_reports: List[ReportData],
        patch: str = "",
        output_dir: Optional[Path] = None,
        progress: Optional[GenerationProgress] = None
    ) -> RefinementResult:
        """
        基于FP报告的迭代精炼

        Args:
            checker_code: 原始检测器代码
            pattern: 漏洞模式
            fp_reports: 误报报告列表
            patch: 可选的补丁
            output_dir: 输出目录
            progress: 进度跟踪器

        Returns:
            精炼结果
        """
        result = RefinementResult(
            refined=False,
            checker_code=checker_code,
            original_checker_code=checker_code,
            attempt_id=0
        )

        logger.info(f"Starting refinement with {len(fp_reports)} FP reports")

        for report in fp_reports:
            try:
                # 对报告进行分类确认
                triage_result = self.triage.triage_report(
                    report, pattern, patch, temperature=0.01
                )

                if not triage_result.is_fp:
                    # 不是FP，跳过
                    result.num_TP += 1
                    continue

                # 这是FP，尝试修复
                result.num_FP += 1
                result.error_objects.update(report.report_objects)

                refine_attempt = RefineAttempt(
                    refine_id=f"refine-{len(result.refine_attempt_list)}",
                    report_data=report,
                    original_code=checker_code
                )

                # 执行修复
                refined_code = self._attempt_fp_repair(
                    checker_code, pattern, report, patch, progress
                )

                if refined_code and refined_code != checker_code:
                    # 验证修复后的代码
                    if self._validate_refined_code(refined_code, report, pattern):
                        result.checker_code = refined_code
                        result.refined = True
                        result.result = "Refined"

                        # 记录成功的修复
                        refine_attempt.semantic_correct_refine_code = refined_code
                        refine_attempt.killed_objects = set(report.report_objects)

                        logger.info(f"Successfully refined for report {report.report_id}")

                result.refine_attempt_list.append(refine_attempt)

                # 如果成功修复，使用新代码作为下次迭代的起点
                if result.refined:
                    checker_code = refined_code

            except Exception as e:
                logger.error(f"Error processing report {report.report_id}: {e}")
                continue

        # 设置最终状态
        if result.num_FP == 0:
            result.result = "Perfect"
        elif result.num_TP / (result.num_TP + result.num_FP) >= 0.75:
            result.result = "High-TP"
        elif result.refined:
            result.result = "Refined"

        result.num_reports = len(fp_reports)

        # 保存结果
        if output_dir:
            result.save_refined_code(output_dir, "refined")

        return result

    def _attempt_fp_repair(
        self,
        checker_code: str,
        pattern: str,
        fp_report: ReportData,
        patch: str,
        progress: Optional[GenerationProgress]
    ) -> Optional[str]:
        """
        尝试修复单个FP

        Args:
            checker_code: 当前检测器代码
            pattern: 漏洞模式
            fp_report: FP报告
            patch: 补丁
            progress: 进度跟踪

        Returns:
            修复后的代码，失败返回None
        """
        if not self.llm_client:
            logger.warning("No LLM client available for FP repair")
            return None

        step_name = None
        if progress:
            step_name = progress.start_step(f"🔧 Repairing FP: {fp_report.report_id}")

        try:
            # 构建修复提示词
            prompt = self._repair_template.replace("{{checker_code}}", checker_code)
            prompt = prompt.replace("{{pattern}}", pattern)
            prompt = prompt.replace("{{fp_report}}", fp_report.report_content)

            # 添加FP分析
            fp_analysis = f"This report from {fp_report.report_id} was classified as a false positive. "
            fp_analysis += f"It involves the following objects: {', '.join(fp_report.report_objects)}"
            prompt = prompt.replace("{{fp_analysis}}", fp_analysis)

            # 添加工具函数（如果有）
            utility = self._get_utility_functions()
            prompt = prompt.replace("{{utility_functions}}", utility)

            # 调用LLM - 使用配置中的 max_tokens
            max_tokens = getattr(self.llm_client.config, 'max_tokens', 10000)
            response = self.llm_client.generate(
                prompt,
                temperature=0.1,
                max_tokens=max_tokens
            )

            if not response:
                logger.error("Empty response from LLM")
                if progress:
                    progress.fail_step(step_name, "Empty LLM response")
                return None

            # 提取代码
            refined_code = extract_checker_code(response)

            if not refined_code or refined_code == checker_code:
                logger.warning("Failed to extract refined code or code unchanged")
                if progress:
                    progress.fail_step(step_name, "Code extraction failed")
                return None

            # 验证代码语法
            from ..utils.code_utils import validate_cpp_syntax
            is_valid, error_msg = validate_cpp_syntax(refined_code)

            if not is_valid:
                logger.warning(f"Refined code has syntax errors: {error_msg}")
                if progress:
                    progress.fail_step(step_name, f"Syntax error: {error_msg}")
                return None

            if progress:
                progress.complete_step(step_name, f"Generated {len(refined_code.splitlines())} lines")

            return refined_code

        except Exception as e:
            logger.error(f"Error during FP repair: {e}")
            if progress:
                progress.fail_step(step_name, str(e))
            return None

    def _validate_refined_code(
        self,
        refined_code: str,
        fp_report: ReportData,
        pattern: str
    ) -> bool:
        """
        验证修复后的代码

        基本验证：代码不同且包含必要元素

        Args:
            refined_code: 修复后的代码
            fp_report: FP报告
            pattern: 漏洞模式

        Returns:
            是否有效
        """
        # 检查代码包含基本元素
        required_elements = ["registerChecker", "class", "check"]
        if not all(elem in refined_code for elem in required_elements):
            logger.warning("Refined code missing required elements")
            return False

        # 简单验证：代码长度合理
        if len(refined_code) < 200:
            logger.warning("Refined code too short")
            return False

        return True

    def _get_utility_functions(self) -> str:
        """获取工具函数文本"""
        # 这里可以加载实际的工具函数文档
        return "Common Clang SA APIs: clang::ast_matchers, clang::ast_context, ProgramPointRef"

    def batch_refine(
        self,
        checkers_dir: Path,
        pattern: str,
        patch: str = "",
        max_fp_reports: int = 10
    ) -> List[RefinementResult]:
        """
        批量精炼检测器

        Args:
            checkers_dir: 检测器目录
            pattern: 漏洞模式
            patch: 补丁
            max_fp_reports: 每个检测器最多处理的FP报告数

        Returns:
            精炼结果列表
        """
        results = []
        progress = GenerationProgress()

        # 查找所有检测器
        checker_dirs = [d for d in checkers_dir.iterdir() if d.is_dir()]

        for i, checker_dir in enumerate(checker_dirs):
            logger.info(f"Processing checker {i+1}/{len(checker_dirs)}: {checker_dir.name}")

            try:
                # 加载检测器代码
                checker_file = checker_dir / "checker.cpp"
                if not checker_file.exists():
                    continue

                checker_code = checker_file.read_text()

                # 模拟FP报告（实际应从扫描结果获取）
                fp_reports = self._load_mock_fp_reports(checker_dir, max_fp_reports)

                if not fp_reports:
                    logger.info(f"No FP reports for {checker_dir.name}")
                    continue

                # 执行精炼
                result = self.refine_with_feedback(
                    checker_code, pattern, fp_reports, patch,
                    output_dir=checker_dir,
                    progress=progress
                )

                results.append(result)

            except Exception as e:
                logger.error(f"Error processing {checker_dir.name}: {e}")
                continue

        # 生成总结
        total_time = progress.get_total_time()
        logger.info(f"Batch refinement complete: {len(results)} checkers in {total_time:.1f}s")

        return results

    def _load_mock_fp_reports(self, checker_dir: Path, count: int) -> List[ReportData]:
        """
        加载模拟FP报告（用于测试）

        实际应从扫描结果文件读取
        """
        # 这里可以读取实际的报告文件
        report_file = checker_dir / "fp_reports.json"
        if report_file.exists():
            try:
                data = json.loads(report_file.read_text())
                return [ReportData(**r) for r in data[:count]]
            except Exception as e:
                logger.warning(f"Failed to load FP reports: {e}")

        # 返回空列表
        return []

    def set_llm_client(self, client: LLMClient):
        """设置LLM客户端"""
        self.llm_client = client
        self.triage.set_llm_client(client)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "max_attempts": self.max_attempts,
            "has_llm_client": self.llm_client is not None,
            "has_triage": self.triage is not None
        }
