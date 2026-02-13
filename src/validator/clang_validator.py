"""
Clang Static Analyzer 验证器
实现完整的 CSA 检查器验证流程
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import shutil

from loguru import logger


class ScanBuildResult(Enum):
    """scan-build 执行结果"""
    SUCCESS = "success"
    COMPILATION_FAILED = "compilation_failed"
    NO_ISSUES_FOUND = "no_issues"
    ANALYSIS_ERROR = "analysis_error"


@dataclass
class ValidationTestCase:
    """验证测试用例"""
    name: str
    vulnerability_type: str
    test_code: str
    should_detect: bool  # True=应该检测到漏洞, False=不应该检测到
    expected_line: Optional[int] = None
    description: str = ""


@dataclass
class CSAValidationResult:
    """CSA 验证结果"""
    checker_name: str
    checker_path: Path
    compilation_success: bool
    compilation_output: str = ""
    loadable: bool = False
    load_error: str = ""
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    detected_issues: List[Dict[str, Any]] = field(default_factory=list)

    # 验证指标
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    # 计算的指标
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    def calculate_metrics(self):
        """计算验证指标"""
        total_predictions = self.true_positives + self.false_positives
        total_actual = self.true_positives + self.false_negatives

        if total_predictions > 0:
            self.precision = self.true_positives / total_predictions

        if total_actual > 0:
            self.recall = self.true_positives / total_actual

        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        self.calculate_metrics()
        return {
            "checker_name": self.checker_name,
            "checker_path": str(self.checker_path),
            "compilation_success": self.compilation_success,
            "loadable": self.loadable,
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "detected_issues": self.detected_issues,
            "test_results": self.test_results
        }


class ClangSAValidator:
    """
    Clang Static Analyzer 验证器

    功能：
    1. 编译检查器为共享库
    2. 使用 scan-build 运行检查器
    3. 解析分析结果
    4. 计算验证指标
    """

    def __init__(self, llvm_dir: Path, clang_version: str = "18"):
        """
        初始化验证器

        Args:
            llvm_dir: LLVM 安装目录
            clang_version: Clang 版本
        """
        self.llvm_dir = Path(llvm_dir)
        self.clang_version = clang_version

        # 验证 LLVM 目录
        if not self.llvm_dir.exists():
            raise FileNotFoundError(f"LLVM directory not found: {llvm_dir}")

        # 设置路径
        self.clang_bin = self._find_clang()
        self.scan_build = self._find_scan_build()
        self.clang_lib_dir = self.llvm_dir / "lib"

        logger.info(f"ClangSAValidator initialized with LLVM: {llvm_dir}")
        logger.info(f"Clang: {self.clang_bin}")
        logger.info(f"scan-build: {self.scan_build}")

    def _find_clang(self) -> Path:
        """查找 Clang 可执行文件"""
        possible_paths = [
            self.llvm_dir / "bin" / f"clang-{self.clang_version}",
            self.llvm_dir / "bin" / "clang",
            Path("/usr/bin") / f"clang-{self.clang_version}",
            Path("/usr/bin") / "clang",
        ]

        for path in possible_paths:
            if path.exists():
                return path

        raise FileNotFoundError(f"Clang not found in {possible_paths}")

    def _find_scan_build(self) -> Path:
        """查找 scan-build 脚本"""
        possible_paths = [
            self.llvm_dir / "bin" / "scan-build",
            Path("/usr/bin") / "scan-build",
            Path("/usr/lib") / "llvm" / f"llvm-{self.clang_version}" / "bin" / "scan-build",
        ]

        for path in possible_paths:
            if path.exists():
                return path

        # 尝试使用 which
        try:
            result = subprocess.run(
                ["which", "scan-build"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except Exception:
            pass

        raise FileNotFoundError(f"scan-build not found in {possible_paths}")

    async def validate_checker(
        self,
        checker_code: str,
        checker_name: str,
        test_cases: List[ValidationTestCase],
        work_dir: Optional[Path] = None
    ) -> CSAValidationResult:
        """
        验证检查器

        Args:
            checker_code: 检查器 C++ 代码
            checker_name: 检查器名称
            test_cases: 测试用例列表
            work_dir: 工作目录

        Returns:
            验证结果
        """
        if work_dir is None:
            work_dir = Path(tempfile.mkdtemp(prefix=f"clang_validate_{checker_name}_"))

        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)

        result = CSAValidationResult(
            checker_name=checker_name,
            checker_path=work_dir
        )

        logger.info(f"Validating checker: {checker_name}")
        logger.info(f"Work directory: {work_dir}")

        # 步骤1: 编译检查器为共享库
        logger.info("Step 1: Compiling checker...")
        compilation_success, compilation_output = await self._compile_checker(
            checker_code, checker_name, work_dir
        )

        result.compilation_success = compilation_success
        result.compilation_output = compilation_output

        if not compilation_success:
            logger.error(f"Compilation failed: {compilation_output}")
            return result

        logger.success("Compilation successful")

        # 步骤2: 验证共享库可加载性
        logger.info("Step 2: Checking library loadability...")
        result.loadable, result.load_error = await self._check_loadable(
            work_dir, checker_name
        )

        if not result.loadable:
            logger.warning(f"Library not loadable: {result.load_error}")
        else:
            logger.success("Library is loadable")

        # 步骤3: 运行测试用例
        logger.info(f"Step 3: Running {len(test_cases)} test cases...")
        for test_case in test_cases:
            test_result = await self._run_test_case(
                checker_name, test_case, work_dir
            )
            result.test_results.append(test_result)

            # 更新指标
            if test_case.should_detect:
                if test_result["detected"]:
                    result.true_positives += 1
                else:
                    result.false_negatives += 1
            else:
                if test_result["detected"]:
                    result.false_positives += 1
                else:
                    result.true_negatives += 1

            if test_result["detected"]:
                result.detected_issues.append(test_result)

        # 计算最终指标
        result.calculate_metrics()

        logger.success(f"Validation complete: F1={result.f1_score:.3f}")
        logger.info(f"  TP={result.true_positives}, TN={result.true_negatives}")
        logger.info(f"  FP={result.false_positives}, FN={result.false_negatives}")

        return result

    async def _compile_checker(
        self,
        checker_code: str,
        checker_name: str,
        work_dir: Path
    ) -> Tuple[bool, str]:
        """
        编译检查器为共享库

        Args:
            checker_code: 检查器代码
            checker_name: 检查器名称
            work_dir: 工作目录

        Returns:
            (是否成功, 输出)
        """
        # 写入检查器源文件
        checker_file = work_dir / f"{checker_name}.cpp"
        checker_file.write_text(checker_code)

        # 创建 CMakeLists.txt
        cmake_content = f"""
cmake_minimum_required(VERSION 3.13)
project({checker_name}Plugin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVM in ${LLVM_DIR}")

include_directories(${{LLVM_INCLUDE_DIRS}})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${{LLVM_DEFINITIONS}})
add_definitions(${{LLVM_DEFINITIONS_LIST}}}}

llvm_map_components_to_libnames(llvm_support clangStaticAnalyzerCheckers clangStaticAnalyzerCore clangAST clangAnalysis clangFrontend clangBasic)

add_library(${{PROJECT_NAME}} SHARED
    {checker_name}.cpp
)

target_link_libraries(${{PROJECT_NAME}} ${{llvm_libs}})
"""
        cmake_file = work_dir / "CMakeLists.txt"
        cmake_file.write_text(cmake_content)

        # 创建构建目录
        build_dir = work_dir / "build"
        build_dir.mkdir(exist_ok=True)

        try:
            # 配置 CMake
            cmake_cmd = [
                "cmake",
                f"-DLLVM_DIR={self.llvm_dir}/lib/cmake/llvm",
                f"-DClang_DIR={self.llvm_dir}/lib/cmake/clang",
                "-G", "Unix", "Makefiles",
                ".."
            ]

            result = subprocess.run(
                cmake_cmd,
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                return False, f"CMake configure failed:\n{result.stderr}"

            # 编译
            build_cmd = ["make", "-j4"]
            result = subprocess.run(
                build_cmd,
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=300,
                env={**os.environ, "CXX": str(self.clang_bin)}
            )

            if result.returncode != 0:
                return False, f"Compilation failed:\n{result.stderr}"

            # 检查输出文件
            so_file = build_dir / f"lib{checker_name}.so"
            if not so_file.exists():
                return False, f"Shared library not found: {so_file}"

            return True, result.stdout

        except subprocess.TimeoutExpired:
            return False, "Compilation timeout"
        except Exception as e:
            return False, f"Compilation error: {e}"

    async def _check_loadable(
        self,
        work_dir: Path,
        checker_name: str
    ) -> Tuple[bool, str]:
        """
        检查共享库是否可加载

        Args:
            work_dir: 工作目录
            checker_name: 检查器名称

        Returns:
            (是否可加载, 错误信息)
        """
        so_file = work_dir / "build" / f"lib{checker_name}.so"

        if not so_file.exists():
            return False, f"Shared library not found: {so_file}"

        try:
            # 尝试使用 nm 检查符号
            result = subprocess.run(
                ["nm", "-D", str(so_file)],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # 检查是否有必要的符号
                if "clang_registerCheckers" in result.stdout:
                    return True, ""
                else:
                    return False, "Missing clang_registerCheckers symbol"
            else:
                return False, f"nm failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, "Symbol check timeout"
        except Exception as e:
            return False, f"Load check error: {e}"

    async def _run_test_case(
        self,
        checker_name: str,
        test_case: ValidationTestCase,
        work_dir: Path
    ) -> Dict[str, Any]:
        """
        运行单个测试用例

        Args:
            checker_name: 检查器名称
            test_case: 测试用例
            work_dir: 工作目录

        Returns:
            测试结果
        """
        test_file = work_dir / f"test_{test_case.name}.c"
        test_file.write_text(test_case.test_code)

        # 创建输出目录
        output_dir = work_dir / "scan_output"
        output_dir.mkdir(exist_ok=True)

        try:
            # 构建 scan-build 命令
            # 注意：这需要自定义的 checker 加载机制
            scan_cmd = [
                str(self.scan_build),
                "-o", str(output_dir),
                "--use-analyzer=/usr/bin/clang",
                "-load-plugin", str(work_dir / "build" / f"lib{checker_name}.so"),
                "-enable-checker", checker_name,
                str(self.clang_bin),
                "-c", str(test_file),
                "-o", str(test_file.with_suffix(".o"))
            ]

            result = subprocess.run(
                scan_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=work_dir
            )

            # 检查是否有报告生成
            detected = False
            issue_details = None

            # 查找 HTML 报告
            html_files = list(output_dir.rglob("*.html"))
            if html_files:
                detected = True
                # 解析报告
                issue_details = self._parse_html_report(html_files[0])

            # 或者检查 stderr 中的警告
            if not detected and result.stderr:
                if f"{checker_name}" in result.stderr or "warning" in result.stderr.lower():
                    detected = True
                    issue_details = {"output": result.stderr}

            return {
                "test_name": test_case.name,
                "vulnerability_type": test_case.vulnerability_type,
                "should_detect": test_case.should_detect,
                "detected": detected,
                "correct": detected == test_case.should_detect,
                "issue_details": issue_details,
                "output": result.stdout,
                "errors": result.stderr
            }

        except subprocess.TimeoutExpired:
            return {
                "test_name": test_case.name,
                "vulnerability_type": test_case.vulnerability_type,
                "should_detect": test_case.should_detect,
                "detected": False,
                "correct": False,
                "error": "Test timeout"
            }
        except Exception as e:
            return {
                "test_name": test_case.name,
                "vulnerability_type": test_case.vulnerability_type,
                "should_detect": test_case.should_detect,
                "detected": False,
                "correct": False,
                "error": str(e)
            }

    def _parse_html_report(self, html_file: Path) -> Dict[str, Any]:
        """解析 HTML 报告文件"""
        try:
            content = html_file.read_text()

            # 提取关键信息
            bug_type = self._extract_bug_type(content)
            file_path = self._extract_file_path(content)
            line_number = self._extract_line_number(content)

            return {
                "bug_type": bug_type,
                "file": file_path,
                "line": line_number,
                "report_file": str(html_file)
            }
        except Exception as e:
            logger.warning(f"Failed to parse HTML report: {e}")
            return {"raw_file": str(html_file)}

    def _extract_bug_type(self, html_content: str) -> str:
        """从 HTML 中提取 bug 类型"""
        match = re.search(r'<h3[^>]*>([^<]+)</h3>', html_content)
        if match:
            return match.group(1).strip()
        return "Unknown"

    def _extract_file_path(self, html_content: str) -> str:
        """从 HTML 中提取文件路径"""
        match = re.search(r'File: ([^<\n]+)', html_content)
        if match:
            return match.group(1).strip()
        return ""

    def _extract_line_number(self, html_content: str) -> Optional[int]:
        """从 HTML 中提取行号"""
        match = re.search(r'Line: (\d+)', html_content)
        if match:
            return int(match.group(1))
        return None


# 预定义的测试用例
class StandardTestCases:
    """标准测试用例集合"""

    @staticmethod
    def get_uninitialized_var_tests() -> List[ValidationTestCase]:
        """获取未初始化变量测试用例"""
        return [
            ValidationTestCase(
                name="uninit_true_positive",
                vulnerability_type="uninitialized_variable",
                should_detect=True,
                expected_line=4,
                description="使用未初始化的变量",
                test_code="""
void test_uninit() {
    int x;
    return x;  // 应该检测到
}
"""
            ),
            ValidationTestCase(
                name="uninit_true_negative",
                vulnerability_type="uninitialized_variable",
                should_detect=False,
                description="使用已初始化的变量",
                test_code="""
void test_init() {
    int x = 0;
    return x;  // 不应该检测到
}
"""
            ),
            ValidationTestCase(
                name="uninit_conditional",
                vulnerability_type="uninitialized_variable",
                should_detect=True,
                expected_line=5,
                description="条件路径中的未初始化变量",
                test_code="""
void test_conditional(int flag) {
    int x;
    if (flag > 0) {
        x = 1;
    }
    return x;  // 应该检测到（某些路径未初始化）
}
"""
            ),
        ]

    @staticmethod
    def get_null_deref_tests() -> List[ValidationTestCase]:
        """获取空指针解引用测试用例"""
        return [
            ValidationTestCase(
                name="null_deref_true",
                vulnerability_type="null_pointer_dereference",
                should_detect=True,
                expected_line=5,
                description="可能的空指针解引用",
                test_code="""
#include <stdlib.h>
void test_null() {
    int *p = NULL;
    *p = 1;  // 应该检测到
}
"""
            ),
            ValidationTestCase(
                name="null_deref_false",
                vulnerability_type="null_pointer_dereference",
                should_detect=False,
                description="有检查的指针使用",
                test_code="""
#include <stdlib.h>
void test_safe() {
    int *p = NULL;
    if (p != NULL) {
        *p = 1;  // 不应该检测到
    }
}
"""
            ),
        ]

    @staticmethod
    def get_memory_leak_tests() -> List[ValidationTestCase]:
        """获取内存泄漏测试用例"""
        return [
            ValidationTestCase(
                name="mem_leak_true",
                vulnerability_type="memory_leak",
                should_detect=True,
                expected_line=4,
                description="分配后未释放",
                test_code="""
#include <stdlib.h>
void test_leak() {
    int *p = malloc(sizeof(int));
    *p = 1;
    return;  // 应该检测到（未释放）
}
"""
            ),
            ValidationTestCase(
                name="mem_leak_false",
                vulnerability_type="memory_leak",
                should_detect=False,
                description="正确释放内存",
                test_code="""
#include <stdlib.h>
void test_no_leak() {
    int *p = malloc(sizeof(int));
    *p = 1;
    free(p);  // 不应该检测到
    return;
}
"""
            ),
        ]

    @classmethod
    def get_all_tests(cls) -> List[ValidationTestCase]:
        """获取所有标准测试用例"""
        all_tests = []
        all_tests.extend(cls.get_uninitialized_var_tests())
        all_tests.extend(cls.get_null_deref_tests())
        all_tests.extend(cls.get_memory_leak_tests())
        return all_tests


async def validate_checker_with_standard_tests(
    checker_code: str,
    checker_name: str,
    llvm_dir: Path,
    test_category: Optional[str] = None
) -> CSAValidationResult:
    """
    使用标准测试用例验证检查器

    Args:
        checker_code: 检查器代码
        checker_name: 检查器名称
        llvm_dir: LLVM 目录
        test_category: 测试类别（如 "uninitialized_var", "null_deref"）

    Returns:
        验证结果
    """
    validator = ClangSAValidator(llvm_dir)

    # 获取测试用例
    if test_category == "uninitialized_var":
        test_cases = StandardTestCases.get_uninitialized_var_tests()
    elif test_category == "null_deref":
        test_cases = StandardTestCases.get_null_deref_tests()
    elif test_category == "memory_leak":
        test_cases = StandardTestCases.get_memory_leak_tests()
    else:
        test_cases = StandardTestCases.get_all_tests()

    return await validator.validate_checker(
        checker_code=checker_code,
        checker_name=checker_name,
        test_cases=test_cases
    )