"""
自愈修复引擎

实现检查器的自动修复机制，包括：
1. 语法修复 - 编译错误的自动修复
2. 语义修复 - 逻辑错误的自动修复
3. 多轮迭代修复 - 最多尝试N次修复
4. 修复历史跟踪

参考Knighter的repair_checker.py设计。
"""

import json
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

from loguru import logger

from ..models.checker_data import RepairResult, CheckerData, CheckerStatus
from ..prompts.prompt_manager import EnhancedPromptManager, PromptContext
from ..utils.tools import (
    extract_checker_code,
    grab_error_message,
    error_formatting,
    compile_checker
)


@dataclass
class RepairConfig:
    """修复配置"""
    max_syntax_attempts: int = 4
    max_semantic_attempts: int = 3
    enable_syntax_repair: bool = True
    enable_semantic_repair: bool = True
    save_intermediate: bool = True


class RepairEngine:
    """
    自愈修复引擎

    负责自动修复检查器代码中的语法和语义错误。
    """

    def __init__(
        self,
        prompt_manager: EnhancedPromptManager,
        llm_client,
        config: Optional[RepairConfig] = None
    ):
        self.prompt_manager = prompt_manager
        self.llm_client = llm_client
        self.config = config or RepairConfig()

    async def repair_checker(
        self,
        checker_data: CheckerData,
        llvm_dir: Path
    ) -> Tuple[bool, CheckerData]:
        """
        修复检查器

        Args:
            checker_data: 检查器数据
            llvm_dir: LLVM安装目录

        Returns:
            (是否成功, 更新后的检查器数据)
        """
        logger.info(f"Starting repair process for {checker_data.checker_id}")

        # 初始代码
        current_code = checker_data.initial_checker_code
        if not current_code:
            logger.error("No initial code to repair")
            return False, checker_data

        # 阶段1: 语法修复
        if self.config.enable_syntax_repair:
            success, current_code = await self._syntax_repair_phase(
                checker_data, current_code, llvm_dir
            )

            if not success:
                checker_data.update_status(CheckerStatus.NON_COMPILABLE)
                return False, checker_data

        # 更新修复后的代码
        checker_data.repaired_checker_code = current_code
        checker_data.update_status(CheckerStatus.SYNTAX_REPAIRED)

        logger.info(f"Repair completed for {checker_data.checker_id}")
        return True, checker_data

    async def _syntax_repair_phase(
        self,
        checker_data: CheckerData,
        initial_code: str,
        llvm_dir: Path
    ) -> Tuple[bool, str]:
        """
        语法修复阶段

        尝试编译检查器，如果失败则使用LLM修复。
        """
        current_code = initial_code
        context = PromptContext(
            clang_version="18",
            enable_lsp=False,
            enable_rag=False
        )

        for attempt in range(1, self.config.max_syntax_attempts + 1):
            logger.info(f"Syntax repair attempt {attempt}/{self.config.max_syntax_attempts}")

            # 尝试编译
            success, stdout, stderr = compile_checker(
                current_code,
                checker_data.checker_id,
                llvm_dir,
                checker_data.output_dir
            )

            if success:
                logger.info(f"Compilation successful on attempt {attempt}")
                return True, current_code

            # 编译失败，提取错误
            errors = grab_error_message(stderr)

            if not errors:
                logger.warning(f"No errors extracted from stderr, using raw stderr")
                errors_list = [stderr]
            else:
                errors_list = errors

            logger.info(f"Compilation failed with {len(errors_list)} errors")

            # 构建修复提示词
            repair_prompt = self.prompt_manager.build_syntax_repair_prompt(
                checker_code=current_code,
                errors=errors_list,
                context=context,
                error_details=stderr
            )

            # 保存中间结果
            if self.config.save_intermediate:
                self._save_repair_attempt(
                    checker_data, attempt, "syntax", current_code, repair_prompt, stderr
                )

            # 调用LLM修复
            try:
                response = await self.llm_client.generate(repair_prompt)

                # 提取修复后的代码
                repaired_code = extract_checker_code(response)

                if not repaired_code:
                    logger.error(f"Failed to extract code from LLM response")
                    # 使用原响应作为代码
                    repaired_code = response

                # 记录修复结果
                result = RepairResult(
                    attempt_id=attempt,
                    repair_type="syntax",
                    original_code=current_code,
                    repaired_code=repaired_code,
                    error_message=stderr[:500],  # 截断过长的错误信息
                    success=False  # 还未验证
                )

                checker_data.add_syntax_repair(result)

                current_code = repaired_code

            except Exception as e:
                logger.error(f"Error during LLM repair: {e}")
                # 继续尝试

        # 所有尝试都失败了
        logger.error(f"Failed to repair after {self.config.max_syntax_attempts} attempts")
        return False, current_code

    async def semantic_repair(
        self,
        checker_data: CheckerData,
        bug_pattern: str,
        implementation_plan: str,
        issues: Dict[str, List[str]]
    ) -> Tuple[bool, str]:
        """
        语义修复

        修复检查器的逻辑问题（误报、漏报等）。

        Args:
            checker_data: 检查器数据
            bug_pattern: 漏洞模式
            implementation_plan: 实现计划
            issues: 问题字典

        Returns:
            (是否成功, 修复后的代码)
        """
        current_code = checker_data.repaired_checker_code or checker_data.initial_checker_code

        if not current_code:
            return False, current_code

        context = PromptContext(
            clang_version="18",
            enable_lsp=True,
            enable_rag=True
        )

        for attempt in range(1, self.config.max_semantic_attempts + 1):
            logger.info(f"Semantic repair attempt {attempt}/{self.config.max_semantic_attempts}")

            # 构建语义修复提示词
            repair_prompt = self.prompt_manager.build_semantic_repair_prompt(
                checker_code=current_code,
                bug_pattern=bug_pattern,
                implementation_plan=implementation_plan,
                context=context,
                issues=issues
            )

            # 调用LLM修复
            try:
                response = await self.llm_client.generate(repair_prompt)

                # 提取修复后的代码
                repaired_code = extract_checker_code(response)

                if not repaired_code:
                    logger.error(f"Failed to extract code from LLM response")
                    continue

                # 记录修复结果
                result = RepairResult(
                    attempt_id=attempt,
                    repair_type="semantic",
                    original_code=current_code,
                    repaired_code=repaired_code,
                    success=True
                )

                checker_data.add_semantic_repair(result)

                current_code = repaired_code

                # 语义修复成功，返回
                return True, current_code

            except Exception as e:
                logger.error(f"Error during semantic repair: {e}")

        return False, current_code

    def _save_repair_attempt(
        self,
        checker_data: CheckerData,
        attempt_id: int,
        repair_type: str,
        code: str,
        prompt: str,
        error_output: str
    ):
        """保存修复尝试的详细信息"""
        intermediate_dir = checker_data.intermediate_dir
        intermediate_dir.mkdir(parents=True, exist_ok=True)

        repair_dir = intermediate_dir / f"repair_{repair_type}_{attempt_id:02d}"
        repair_dir.mkdir(exist_ok=True)

        # 保存代码
        (repair_dir / "code.cpp").write_text(code)

        # 保存提示词
        (repair_dir / "repair_prompt.md").write_text(prompt)

        # 保存错误
        (repair_dir / "errors.txt").write_text(error_output)

    async def validate_and_repair(
        self,
        checker_data: CheckerData,
        validation_result: Dict[str, Any],
        bug_pattern: str,
        implementation_plan: str
    ) -> Tuple[bool, CheckerData]:
        """
        验证检查器并在需要时进行语义修复

        Args:
            checker_data: 检查器数据
            validation_result: 验证结果
            bug_pattern: 漏洞模式
            implementation_plan: 实现计划

        Returns:
            (是否最终有效, 更新后的检查器数据)
        """
        # 检查是否需要语义修复
        needs_repair = False
        issues = {
            "false_positives": [],
            "false_negatives": [],
            "crashes": []
        }

        # 分析验证结果，判断是否需要修复
        if validation_result.get("fp_count", 0) > 0:
            needs_repair = True
            issues["false_positives"] = [
                f"Found {validation_result['fp_count']} false positive(s)"
            ]

        if validation_result.get("fn_count", 0) > 0:
            needs_repair = True
            issues["false_negatives"] = [
                f"Missed {validation_result['fn_count']} true positive(s)"
            ]

        if not needs_repair:
            # 检查器已经有效
            logger.info(f"Checker {checker_data.checker_id} is valid, no repair needed")
            return True, checker_data

        logger.info(f"Checker {checker_data.checker_id} needs semantic repair")

        # 执行语义修复
        if self.config.enable_semantic_repair:
            success, repaired_code = await self.semantic_repair(
                checker_data,
                bug_pattern,
                implementation_plan,
                issues
            )

            if success:
                checker_data.repaired_checker_code = repaired_code
                checker_data.update_status(CheckerStatus.SEMANTIC_REPAIRED)
            else:
                logger.warning(f"Semantic repair failed for {checker_data.checker_id}")

        # 重新验证
        # 这里需要调用验证系统
        # 暂时返回当前状态
        return False, checker_data


class SimpleRepairEngine:
    """
    简化版修复引擎

    用于不使用LLM的简单语法修复场景。
    """

    @staticmethod
    def fix_common_issues(code: str) -> Tuple[bool, str, List[str]]:
        """
        修复常见的编译问题

        Args:
            code: 源代码

        Returns:
            (是否修改, 修复后的代码, 修改列表)
        """
        modifications = []
        fixed_code = code

        # 1. 修复 Optional -> std::optional
        if "Optional<" in fixed_code and "std::optional" not in fixed_code:
            fixed_code = fixed_code.replace("Optional<", "std::optional<")
            modifications.append("Replaced Optional with std::optional")

            # 添加头文件
            if "#include <optional>" not in fixed_code:
                # 在第一个 #include 后添加
                lines = fixed_code.split("\n")
                for i, line in enumerate(lines):
                    if line.startswith("#include"):
                        lines.insert(i + 1, "#include <optional>")
                        modifications.append("Added #include <optional>")
                        break
                fixed_code = "\n".join(lines)

        # 2. 修复 make_unique -> std::make_unique
        if "make_unique" in fixed_code:
            fixed_code = fixed_code.replace("make_unique", "std::make_unique")
            modifications.append("Added std:: prefix to make_unique")

        # 3. 修复未限定的 unique_ptr
        if "unique_ptr<" in fixed_code and "std::unique_ptr" not in fixed_code:
            fixed_code = fixed_code.replace("unique_ptr<", "std::unique_ptr<")
            modifications.append("Replaced unique_ptr with std::unique_ptr")

        # 4. 移除不存在的头文件
        bad_headers = [
            "clang/StaticAnalyzer/Core/PathDiagnostic.h",
            "clang/StaticAnalyzer/Core/AnalysisManager.h"
        ]

        for header in bad_headers:
            if f'"{header}"' in fixed_code:
                fixed_code = fixed_code.replace(f'#include "{header}"', "")
                modifications.append(f"Removed non-existent header: {header}")

        return len(modifications) > 0, fixed_code, modifications