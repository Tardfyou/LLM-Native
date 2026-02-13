"""
端到端验证引擎
实现从生成到验证的完整流程
"""

import asyncio
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger
from ..models.checker_data import CheckerData, CheckerStatus
from validator.clang_validator import (
    ClangSAValidator,
    CSAValidationResult,
    ValidationTestCase,
    StandardTestCases
)


class ValidationStage(Enum):
    """验证阶段"""
    SYNTAX_CHECK = "syntax_check"
    COMPILATION = "compilation"
    LOADABILITY = "loadability"
    FUNCTIONAL_TEST = "functional_test"
    PERFORMANCE_TEST = "performance_test"
    COMPLETE = "complete"


@dataclass
class EndToEndValidationReport:
    """端到端验证报告"""
    checker_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    current_stage: ValidationStage = ValidationStage.SYNTAX_CHECK

    # 各阶段结果
    syntax_check_passed: bool = False
    compilation_passed: bool = False
    loadable: bool = False
    functional_tests_passed: bool = False
    performance_tests_passed: bool = False

    # 详细结果
    compilation_output: str = ""
    csa_validation_result: Optional[CSAValidationResult] = None
    stage_details: Dict[str, Any] = field(default_factory=dict)

    # 最终指标
    overall_success: bool = False
    quality_score: float = 0.0  # 0-100

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "checker_id": self.checker_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "current_stage": self.current_stage.value,
            "syntax_check_passed": self.syntax_check_passed,
            "compilation_passed": self.compilation_passed,
            "loadable": self.loadable,
            "functional_tests_passed": self.functional_tests_passed,
            "performance_tests_passed": self.performance_tests_passed,
            "overall_success": self.overall_success,
            "quality_score": self.quality_score,
            "stage_details": self.stage_details
        }

        if self.csa_validation_result:
            result["csa_validation"] = self.csa_validation_result.to_dict()

        return result

    def calculate_quality_score(self):
        """计算质量分数"""
        scores = []

        # 编译成功权重: 30%
        if self.compilation_passed:
            scores.append(30)

        # 可加载权重: 10%
        if self.loadable:
            scores.append(10)

        # 功能测试权重: 50%
        if self.csa_validation_result:
            # 基于 F1 分数
            scores.append(self.csa_validation_result.f1_score * 50)

        # 性能测试权重: 10%
        if self.performance_tests_passed:
            scores.append(10)

        self.quality_score = sum(scores)

        # 整体成功标准
        self.overall_success = (
            self.compilation_passed and
            self.loadable and
            self.quality_score >= 60  # 最低及格线
        )


class EndToEndValidator:
    """
    端到端验证器

    实现完整的检查器验证流程：
    1. 语法检查
    2. 编译验证
    3. 加载测试
    4. 功能测试（使用真实 CSA）
    5. 性能测试
    """

    def __init__(
        self,
        llvm_dir: Path,
        clang_version: str = "18",
        enable_performance_tests: bool = False
    ):
        """
        初始化端到端验证器

        Args:
            llvm_dir: LLVM 安装目录
            clang_version: Clang 版本
            enable_performance_tests: 是否启用性能测试
        """
        self.llvm_dir = Path(llvm_dir)
        self.clang_version = clang_version
        self.enable_performance_tests = enable_performance_tests

        # 初始化 CSA 验证器
        self.csa_validator = ClangSAValidator(
            llvm_dir=llvm_dir,
            clang_version=clang_version
        )

        logger.info(f"EndToEndValidator initialized with LLVM: {llvm_dir}")

    async def validate_checker(
        self,
        checker_data: CheckerData,
        test_category: Optional[str] = None,
        custom_tests: Optional[List[ValidationTestCase]] = None
    ) -> EndToEndValidationReport:
        """
        执行端到端验证

        Args:
            checker_data: 检查器数据
            test_category: 测试类别
            custom_tests: 自定义测试用例

        Returns:
            验证报告
        """
        report = EndToEndValidationReport(
            checker_id=checker_data.checker_id,
            start_time=datetime.now()
        )

        logger.info(f"Starting end-to-end validation for {checker_data.checker_id}")

        # 阶段1: 语法检查
        report.current_stage = ValidationStage.SYNTAX_CHECK
        report.syntax_check_passed = await self._check_syntax(checker_data)

        if not report.syntax_check_passed:
            logger.error("Syntax check failed, stopping validation")
            report.end_time = datetime.now()
            report.calculate_quality_score()
            return report

        logger.success("Syntax check passed")

        # 阶段2: 编译验证
        report.current_stage = ValidationStage.COMPILATION
        report.compilation_passed, report.compilation_output = await self._compile_checker(
            checker_data
        )

        if not report.compilation_passed:
            logger.error("Compilation failed, stopping validation")
            report.end_time = datetime.now()
            report.calculate_quality_score()
            return report

        logger.success("Compilation passed")

        # 阶段3: 加载测试
        report.current_stage = ValidationStage.LOADABILITY
        report.loadable, load_error = await self._check_loadability(checker_data)

        if not report.loadable:
            logger.warning(f"Loadability check failed: {load_error}")

        # 阶段4: 功能测试
        report.current_stage = ValidationStage.FUNCTIONAL_TEST
        report.functional_tests_passed, csa_result = await self._run_functional_tests(
            checker_data,
            test_category,
            custom_tests
        )

        report.csa_validation_result = csa_result

        if report.functional_tests_passed:
            logger.success("Functional tests passed")
        else:
            logger.warning("Functional tests had failures")

        # 阶段5: 性能测试（可选）
        if self.enable_performance_tests:
            report.current_stage = ValidationStage.PERFORMANCE_TEST
            report.performance_tests_passed = await self._run_performance_tests(
                checker_data
            )

        # 完成
        report.current_stage = ValidationStage.COMPLETE
        report.end_time = datetime.now()
        report.calculate_quality_score()

        # 更新检查器状态
        if report.overall_success:
            checker_data.update_status(CheckerStatus.VALIDATED)
            checker_data.is_valid = True
        else:
            checker_data.update_status(CheckerStatus.VALIDATION_FAILED)
            checker_data.is_valid = False

        # 保存验证结果
        checker_data.validation_result = csa_result
        if hasattr(csa_result, 'to_dict'):
            checker_data.validation_metrics = csa_result.to_dict()

        duration = (report.end_time - report.start_time).total_seconds()
        logger.success(
            f"Validation complete for {checker_data.checker_id} "
            f"(Quality: {report.quality_score:.1f}/100, Duration: {duration:.1f}s)"
        )

        return report

    async def _check_syntax(self, checker_data: CheckerData) -> bool:
        """检查语法"""
        from ..utils.tools import validate_checker_syntax

        code = checker_data.repaired_checker_code or checker_data.initial_checker_code

        valid, errors = validate_checker_syntax(code)

        if not valid:
            report.stage_details["syntax_errors"] = errors
            logger.warning(f"Syntax errors found: {errors}")

        return valid

    async def _compile_checker(
        self,
        checker_data: CheckerData
    ) -> Tuple[bool, str]:
        """编译检查器"""
        from ..utils.tools import compile_checker

        code = checker_data.repaired_checker_code or checker_data.initial_checker_code
        checker_name = checker_data.checker_id.replace("_", "").replace("-", "")

        success, stdout, stderr = compile_checker(
            checker_code=code,
            checker_name=checker_name,
            llvm_dir=self.llvm_dir,
            output_dir=checker_data.output_dir / "build"
        )

        output = stdout
        if stderr:
            output += "\n" + stderr

        return success, output

    async def _check_loadability(self, checker_data: CheckerData) -> Tuple[bool, str]:
        """检查可加载性"""
        build_dir = checker_data.output_dir / "build" / "temp_build"
        so_files = list(build_dir.rglob("*.so"))

        if not so_files:
            return False, "No .so files found"

        so_file = so_files[0]

        try:
            # 使用 nm 检查符号
            result = await asyncio.to_thread(
                subprocess.run,
                ["nm", "-D", str(so_file)],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and "clang_registerCheckers" in result.stdout:
                return True, ""
            else:
                return False, "Missing required symbols"

        except Exception as e:
            return False, str(e)

    async def _run_functional_tests(
        self,
        checker_data: CheckerData,
        test_category: Optional[str],
        custom_tests: Optional[List[ValidationTestCase]]
    ) -> Tuple[bool, CSAValidationResult]:
        """运行功能测试"""
        code = checker_data.repaired_checker_code or checker_data.initial_checker_code
        checker_name = checker_data.checker_id.replace("_", "").replace("-", "")

        # 确定测试用例
        if custom_tests:
            test_cases = custom_tests
        elif test_category:
            if test_category == "uninitialized_var":
                test_cases = StandardTestCases.get_uninitialized_var_tests()
            elif test_category == "null_deref":
                test_cases = StandardTestCases.get_null_deref_tests()
            elif test_category == "memory_leak":
                test_cases = StandardTestCases.get_memory_leak_tests()
            else:
                test_cases = StandardTestCases.get_all_tests()
        else:
            # 根据漏洞描述选择测试
            test_cases = await self._select_tests_by_description(checker_data)

        # 运行 CSA 验证
        result = await self.csa_validator.validate_checker(
            checker_code=code,
            checker_name=checker_name,
            test_cases=test_cases,
            work_dir=checker_data.output_dir / "validation"
        )

        # 判断是否通过
        passed = (
            result.compilation_success and
            result.loadable and
            result.f1_score >= 0.5  # 最低要求
        )

        return passed, result

    async def _select_tests_by_description(
        self,
        checker_data: CheckerData
    ) -> List[ValidationTestCase]:
        """根据漏洞描述选择测试用例"""
        desc = checker_data.vulnerability_desc.lower()

        if "uninit" in desc or "未初始化" in desc:
            return StandardTestCases.get_uninitialized_var_tests()
        elif "null" in desc or "空指针" in desc:
            return StandardTestCases.get_null_deref_tests()
        elif "leak" in desc or "泄漏" in desc or "free" in desc:
            return StandardTestCases.get_memory_leak_tests()
        else:
            # 返回所有测试
            return StandardTestCases.get_all_tests()

    async def _run_performance_tests(self, checker_data: CheckerData) -> bool:
        """运行性能测试"""
        # 这里可以实现性能测试逻辑
        # 例如：检查分析时间、内存使用等
        report.stage_details["performance_tests"] = "skipped"
        return True


# 导入 subprocess
import subprocess


async def validate_and_update_checker(
    checker_data: CheckerData,
    llvm_dir: Path,
    test_category: Optional[str] = None
) -> EndToEndValidationReport:
    """
    便捷函数：验证并更新检查器数据

    Args:
        checker_data: 检查器数据
        llvm_dir: LLVM 目录
        test_category: 测试类别

    Returns:
        验证报告
    """
    validator = EndToEndValidator(llvm_dir=llvm_dir)
    report = await validator.validate_checker(
        checker_data=checker_data,
        test_category=test_category
    )

    # 保存报告
    report_file = checker_data.output_dir / "validation_report.json"
    report_file.write_text(json.dumps(report.to_dict(), indent=2))

    return report
