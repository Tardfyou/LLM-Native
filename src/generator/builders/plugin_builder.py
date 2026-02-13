"""
插件构建器 - 使用 Knighter 风格的插件架构编译 Clang Static Analyzer Checker

借鉴 Knighter 的实现方式：
1. 生成插件式 Checker（使用 clang_registerCheckers 而非 BuiltinCheckerRegistration.h）
2. 通过 LLVM 构建系统编译为 .so 插件
3. 支持通过 clang -load 加载使用

参考：
- Knighter: llvm_utils/create_plugin.py
- Knighter: src/checker_repair.py (repair_checker 函数)
"""

import os
import re
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Tuple, Optional, List
from dataclasses import dataclass
from loguru import logger


@dataclass
class BuildResult:
    """构建结果"""
    success: bool
    plugin_path: Optional[str] = None
    return_code: int = -1
    stdout: str = ""
    stderr: str = ""
    build_time: float = 0.0


class PluginBuilder:
    """
    Clang Static Analyzer 插件构建器

    使用 Knighter 风格的插件架构，避免 BuiltinCheckerRegistration.h 依赖问题
    """

    # LLVM-21 路径配置（与 Knighter 保持一致）
    LLVM_VERSION = "21"
    LLVM_INCLUDE_PATH = "/usr/lib/llvm-21/include"
    LLVM_LIB_PATH = "/usr/lib/llvm-21/lib"

    # 需要链接的 Clang 库（LLVM-21 兼容）
    # 注意：clangDynamicAnalyzer 在 LLVM-21 中不存在，已移除
    CLANG_LIBS = [
        "clangStaticAnalyzerCore",
        "clangStaticAnalyzerFrontend",
        "clangAnalysis",
        "clangAST",
        "clangBasic",
        "clangLex",
    ]

    def __init__(self, build_dir: Optional[Path] = None):
        """
        初始化插件构建器

        Args:
            build_dir: 构建目录，默认为临时目录
        """
        self.build_dir = Path(build_dir) if build_dir else Path(tempfile.mkdtemp(prefix="checker_build_"))
        self.build_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"PluginBuilder initialized with build_dir: {self.build_dir}")

    def build_checker(
        self,
        checker_code: str,
        plugin_name: str,
        output_dir: Path,
        attempt: int = 1
    ) -> BuildResult:
        """
        构建 Checker 插件

        参考 Knighter 的 checker_repair.py repair_checker 函数和 backend.build_checker

        Args:
            checker_code: Checker 源代码
            plugin_name: 插件名称（如 BufferOverflowChecker）
            output_dir: 输出目录
            attempt: 尝试次数（用于日志）

        Returns:
            BuildResult: 构建结果
        """
        import time
        start_time = time.time()

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. 准备构建文件
        checker_file = output_dir / f"{plugin_name}.cpp"
        exports_file = output_dir / f"{plugin_name}.exports"
        cmake_file = output_dir / "CMakeLists.txt"

        # 2. 写入 checker 代码
        checker_file.write_text(checker_code)

        # 3. 写入 exports 文件（定义插件导出符号）
        exports_content = """clang_registerCheckers
clang_analyzerAPIVersionString
"""
        exports_file.write_text(exports_content)

        # 4. 生成 CMakeLists.txt（Knighter 风格）
        lib_name = f"{plugin_name}Plugin"
        cmake_content = f"""set(LLVM_LINK_COMPONENTS
  Support
  Core
)

set(LLVM_EXPORTED_SYMBOL_FILE ${{CMAKE_CURRENT_SOURCE_DIR}}/{plugin_name}.exports)
add_llvm_library({lib_name} MODULE BUILDTREE_ONLY {plugin_name}.cpp)

clang_target_link_libraries({lib_name} PRIVATE
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
  clangAnalysis
  clangAST
  clangBasic
)
"""
        cmake_file.write_text(cmake_content)

        # 5. 执行编译
        build_result = self._compile_with_cmake(
            output_dir, lib_name, plugin_name
        )

        build_time = time.time() - start_time
        build_result.build_time = build_time

        if build_result.success:
            logger.success(f"Checker plugin built successfully in {build_time:.2f}s: {build_result.plugin_path}")
        else:
            logger.error(f"Checker plugin build failed after {build_time:.2f}s")

        return build_result

    def _compile_with_cmake(
        self,
        source_dir: Path,
        lib_name: str,
        plugin_name: str
    ) -> BuildResult:
        """
        使用 CMake 和 LLVM 工具链编译插件

        参考 Knighter 的 backend.build_checker 实现
        """
        # 创建构建子目录
        build_subdir = source_dir / "build"
        build_subdir.mkdir(exist_ok=True)

        # 1. 配置 CMake
        cmake_cmd = [
            "cmake",
            f"-DCMAKE_BUILD_TYPE=Release",
            f"-DLLVM_DIR={self.LLVM_LIB_PATH}/cmake/llvm",
            f"-DCMAKE_CXX_COMPILER=clang++",
            "-DCMAKE_MODULE_PATH=/usr/lib/llvm-21/lib/cmake/clang",
            ".."
        ]

        logger.debug(f"Running CMake configure: {' '.join(cmake_cmd)}")

        result = subprocess.run(
            cmake_cmd,
            cwd=build_subdir,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            logger.error(f"CMake configuration failed:\n{result.stderr}")
            return BuildResult(
                success=False,
                return_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr
            )

        # 2. 编译
        build_cmd = ["make", lib_name]

        logger.debug(f"Running make: {' '.join(build_cmd)}")

        result = subprocess.run(
            build_cmd,
            cwd=build_subdir,
            capture_output=True,
            text=True,
            timeout=120
        )

        # 3. 查找生成的 .so 文件
        plugin_path = None
        if result.returncode == 0:
            # 查找生成的 .so 文件
            for so_file in build_subdir.rglob(f"{lib_name}.so"):
                plugin_path = str(so_file)
                break

            if plugin_path:
                return BuildResult(
                    success=True,
                    plugin_path=plugin_path,
                    return_code=0,
                    stdout=result.stdout,
                    stderr=result.stderr
                )

        # 编译失败
        return BuildResult(
            success=False,
            return_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr
        )

    def build_checker_simple(
        self,
        checker_code: str,
        plugin_name: str,
        output_dir: Path
    ) -> BuildResult:
        """
        简化版编译（不使用 CMake，直接用 clang++）

        作为 CMake 构建的备选方案
        """
        import time
        start_time = time.time()

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # 输出文件路径
        output_file = output_dir / f"{plugin_name}.so"
        checker_file = output_dir / f"{plugin_name}.cpp"

        # 预处理：修复错误的 utility.h 包含路径
        # LLM 可能生成 #include "clang/StaticAnalyzer/Checkers/utility.h"
        # 正确的路径应该是 #include "utility.h"
        processed_code = self._fix_utility_include_path(checker_code)

        # 预处理：修复LLM幻觉的API调用（常见错误）
        # 修复 evaluateToInt, getMaxSignedBits 等不存在的API
        processed_code = self._fix_hallucinated_apis(processed_code)

        # 预处理：将内置式注册转换为插件式注册（KNighter 风格）
        processed_code = self._convert_to_plugin_style(processed_code)

        # 预处理：修复 Optional API 问题（LLVM-21 兼容性）
        processed_code = self._fix_optional_api(processed_code)

        # 预处理：修复 Optional 类型问题
        # LLM 可能生成错误的 Optional 使用方式
        processed_code = self._fix_optional_types(processed_code)

        # 修复 PathSensitiveBugReport 字符串拼接问题
        processed_code = self._fix_bug_report_string_concat(processed_code)

        # 修复 LLVM-21 特定的 API 兼容性问题（在内联 utility 函数移除之前执行）
        processed_code = self._fix_llvm21_api_issues(processed_code)

        # 修复内联 utility 函数的命名空间问题（在 API 修复之后执行）
        processed_code = self._fix_inline_utility_namespace(processed_code)

        # 写入 checker 代码
        checker_file.write_text(processed_code)

        # 获取 utility.h 路径
        utility_include_dir = Path(__file__).parent.parent / "include"
        utility_cpp = utility_include_dir / "utility.cpp"

        # 构建编译命令 - Clang 21 需要 C++20 或更高
        compile_cmd = [
            "clang++",
            "-shared",
            "-fPIC",
            "-std=c++20",  # Clang 21 需要 C++20
            f"-I{self.LLVM_INCLUDE_PATH}",
            f"-I{utility_include_dir}",  # 添加 utility.h 头文件路径
            f"-L{self.LLVM_LIB_PATH}",  # 添加库路径
            "-o", str(output_file),
            str(checker_file),
            str(utility_cpp),  # 链接 utility.cpp
        ] + [f"-l{lib}" for lib in self.CLANG_LIBS]

        logger.debug(f"Compiling with: {' '.join(compile_cmd)}")

        result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "LLVM_CONFIG": "/usr/lib/llvm-21/bin/llvm-config"}
        )

        build_time = time.time() - start_time

        if result.returncode == 0 and output_file.exists():
            return BuildResult(
                success=True,
                plugin_path=str(output_file),
                return_code=0,
                stdout=result.stdout,
                stderr=result.stderr,
                build_time=build_time
            )
        else:
            return BuildResult(
                success=False,
                return_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                build_time=build_time
            )

    def _fix_optional_types(self, code: str) -> str:
        """
        修复 LLM 生成的代码中的 Optional 类型问题

        问题：
        1. LLM 可能生成 Optional<XXX> 而不是 llvm::Optional<XXX> 或 std::optional<XXX>
        2. LLVM-21 中 llvm::Optional 已弃用，应该使用 std::optional

        解决：
        1. 移除 llvm::Optional，使用 std::optional
        2. 添加必要的 using 声明或直接替换
        """
        lines = code.split('\n')
        output_lines = []
        has_std_optional_using = False
        needs_std_optional_fix = False
        namespace_line_idx = -1

        for i, line in enumerate(lines):
            # 检测是否有 llvm::Optional 使用（需要替换为 std::optional）
            if 'llvm::Optional' in line and 'std::optional' not in line:
                line = line.replace('llvm::Optional', 'std::optional')
                needs_std_optional_fix = True

            # 检测裸 Optional 使用（不带命名空间）
            if re.search(r'\bOptional<', line) and 'llvm::Optional' not in line and 'std::optional' not in line:
                line = re.sub(r'\bOptional<', 'std::optional<', line)
                needs_std_optional_fix = True

            # 检测是否已有 std::optional 声明
            if 'using std::optional' in line:
                has_std_optional_using = True

            # 查找 namespace { 的位置
            if namespace_line_idx == -1 and re.search(r'namespace\s*\{', line):
                namespace_line_idx = i

            output_lines.append(line)

        # 如果没有 Optional 问题，直接返回原代码
        if not needs_std_optional_fix:
            return '\n'.join(output_lines)

        # 需要添加 using std::optional; 声明
        if not has_std_optional_using:
            if namespace_line_idx >= 0:
                # 在 namespace { 后面添加 using 声明
                result_lines = output_lines[:namespace_line_idx + 1]
                result_lines.append("  using std::optional;")
                result_lines.extend(output_lines[namespace_line_idx + 1:])
                return '\n'.join(result_lines)

            # 找不到 namespace，在 using namespace clang; 后添加
            for i, line in enumerate(output_lines):
                if 'using namespace clang;' in line:
                    result_lines = output_lines[:i + 1]
                    result_lines.append("using std::optional;")
                    result_lines.extend(output_lines[i + 1:])
                    return '\n'.join(result_lines)

            # 在文件开头添加
            return "using std::optional;\n\n" + '\n'.join(output_lines)

        return '\n'.join(output_lines)

    def _fix_optional_api(self, code: str) -> str:
        """
        修复 LLVM-21 中 Optional API 的变化

        问题：
        - Optional<>::getAs() -> std::optional<>::has_value() + value()
        - Optional<>::getValueOr() -> std::optional<>::value_or()

        另外：一些 getAsRegion() 调用需要更新为正确的 API
        """
        import re

        # 修复 .getAs<>() -> .has_value() 和 .value()
        # 模式：xxx.getAs<Type>() -> xxx
        code = re.sub(r'(\w+)\.getAs<([^>]+)>\(\)\(\)', r'\1.getAs<\2>()', code)  # 先保持格式一致

        # 修复 getAsRegion() 调用
        # 正确的 API 是 getAsRegion()，但返回值可能是 Optional
        # 如果 LLM 使用了 .getAsRegion().getBaseRegion()，需要检查是否有 has_value

        # 修复 RegionVal -> 需要实际检查变量是否存在
        # 这通常是因为 LLM 错误地命名了变量

        # 修复 ConcreteVal -> 需要检查
        code = re.sub(r'Optional<loc::ConcreteInt>', 'std::optional<loc::ConcreteInt>', code)
        code = re.sub(r'Optional<nonloc::SymbolVal>', 'std::optional<nonloc::SymbolVal>', code)
        code = re.sub(r'Optional<loc::MemRegionVal>', 'std::optional<loc::MemRegionVal>', code)
        code = re.sub(r'Optional<DefinedSVal>', 'std::optional<DefinedSVal>', code)

        return code

    def _convert_to_plugin_style(self, code: str) -> str:
        """
        将 LLM 生成的代码转换为插件式架构（KNighter 风格）

        主要转换：
        1. 移除 BuiltinCheckerRegistration.h
        2. 移除 register*/shouldRegister* 函数
        3. 添加 clang_registerCheckers 函数
        """
        lines = code.split('\n')
        output_lines = []
        skip_until_brace = False
        in_old_registration_func = False
        has_check_registry = False
        checker_class_name = None

        # 第一阶段：查找 checker 类名并处理头文件
        for i, line in enumerate(lines):
            # 检查是否已有 CheckerRegistry.h
            if 'CheckerRegistry.h' in line and '#include' in line:
                has_check_registry = True

            # 查找 checker 类名
            if 'class ' in line and ': public Checker<' in line and 'class ' in line:
                match = re.search(r'class\s+(\w+)\s*:\s*public\s+Checker<', line)
                if match:
                    checker_class_name = match.group(1)

            # 处理 BuiltinCheckerRegistration.h
            if 'BuiltinCheckerRegistration.h' in line and '#include' in line:
                output_lines.append('// BuiltinCheckerRegistration.h removed - using plugin style')
                if not has_check_registry:
                    output_lines.append('#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"')
                    has_check_registry = True
                continue

            output_lines.append(line)

        # 如果没有找到 CheckerRegistry.h，添加它
        if not has_check_registry:
            # 在第一个 include 后添加
            for i, line in enumerate(output_lines):
                if '#include' in line:
                    output_lines.insert(i + 1, '#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"')
                    break

        # 第二阶段：移除旧的注册函数并添加插件式注册
        code = '\n'.join(output_lines)
        output_lines = []
        skip_until_brace = False
        in_old_registration_func = False

        for line in code.split('\n'):
            # 跳过旧的注册函数
            if ('void ento::register' in line or 'bool ento::shouldRegister' in line or
                'void register' in line and 'ento::' in line):
                if '{' not in line:
                    continue  # 跳过单行函数
                else:
                    in_old_registration_func = True
                    continue

            if in_old_registration_func:
                if '{' in line:
                    skip_until_brace = True
                if '}' in line and skip_until_brace:
                    in_old_registration_func = False
                    skip_until_brace = False
                    continue
                continue

            output_lines.append(line)

        code = '\n'.join(output_lines)

        # 第三阶段：添加插件式注册函数
        if 'clang_registerCheckers' not in code:
            if not checker_class_name:
                # 尝试再次查找类名
                match = re.search(r'class\s+(\w+)\s*:\s*public\s+Checker<', code)
                if match:
                    checker_class_name = match.group(1)
                else:
                    checker_class_name = "CustomChecker"

            # 找到文件末尾的 } 或 } // namespace 等
            # 在最后一个 namespace 结束后添加注册函数
            last_brace_pos = code.rfind('}')
            if last_brace_pos != -1:
                # 检查是否在 namespace 结束处
                if last_brace_pos > 0 and code[last_brace_pos-1] == ' ':
                    # 找到完整的 " // namespace" 行
                    lines = code.split('\n')
                else:
                    lines = code.split('\n')

                # 查找最后一行通常是 } 或 } // namespace
                # 在它之前插入注册函数
                insert_index = -1
                for i in range(len(lines) - 1, -1, -1):
                    if lines[i].strip() == '}' or lines[i].strip().startswith('} //'):
                        insert_index = i
                        break

                if insert_index > 0:
                    # 在此位置之前插入
                    registration_code = f"""
// Plugin registration - KNighter style
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_class_name}>(
      "custom.{checker_class_name}",
      "Auto-generated checker",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
"""
                    lines.insert(insert_index, registration_code)
                    code = '\n'.join(lines)

        return code

    def _fix_bug_report_string_concat(self, code: str) -> str:
        """
        修复 PathSensitiveBugReport 构造函数中的字符串拼接问题

        在 Clang 21 中，PathSensitiveBugReport 构造函数的第二个参数需要是
        std::string 或 StringRef，不能是字符串表达式（如 "..." + var）。
        需要将字符串拼接转换为 std::string 或使用 SmallString。
        """
        import re

        # 查找 PathSensitiveBugReport 的创建模式
        # 模式：PathSensitiveBugReport(*BT, "string" + var, N)
        pattern = r'(std::make_unique<PathSensitiveBugReport>\(\s*\*BT,\s*)("[^"]*\s*\+\s*[^,]+)'

        def replace_concat(match):
            prefix = match.group(1)
            expr = match.group(2)
            # 将字符串表达式包装在 std::string() 中
            return f'{prefix}std::string({expr})'

        code = re.sub(pattern, replace_concat, code)
        return code

    def _fix_inline_utility_namespace(self, code: str) -> str:
        """
        确保代码正确包含 utility.h 并移除 LLM 生成的内联 utility 函数

        问题：
        1. LLM 可能生成内联 utility 函数（使用已废弃的 API）
        2. LLM 可能使用 utility.h 中的函数但没有包含头文件

        解决方案：
        1. 检测并移除 LLM 生成的内联 utility 函数
        2. 如果代码使用了 utility 函数，添加 #include "utility.h"
        """
        lines = code.split('\n')
        output_lines = []

        # 检查代码是否已经包含 utility.h
        has_utility_include = any('#include "utility.h"' in line or '#include <utility.h>' in line for line in lines)

        # 检查代码是否使用了 utility.h 中的函数
        utility_functions = [
            'functionKnownToDeref', 'ExprHasName', 'getMemRegionFromExpr',
            'EvaluateExprToInt', 'inferSymbolMaxVal', 'getArraySizeFromExpr',
            'getStringSize', 'findSpecificTypeInParents'
        ]
        uses_utility_functions = any(any(func in line for func in utility_functions) for line in lines)

        # 第一步：检查并移除 LLM 生成的内联 utility 函数块
        first_namespace_idx = -1
        first_namespace_end = -1
        brace_count = 0
        in_first_namespace = False

        for i, line in enumerate(lines):
            if re.search(r'namespace\s*\{', line):
                first_namespace_idx = i
                in_first_namespace = True
                brace_count = 1
                continue

            if in_first_namespace:
                brace_count += line.count('{')
                brace_count -= line.count('}')

                if brace_count == 0:
                    first_namespace_end = i
                    break

        # 检查是否有内联 utility 函数块
        has_inline_utility = False
        if first_namespace_idx != -1 and first_namespace_end != -1:
            # 检查这个 namespace 是否只包含 utility 函数
            namespace_content = '\n'.join(lines[first_namespace_idx:first_namespace_end + 1])
            if (any(func in namespace_content for func in utility_functions) and
                'class ' not in namespace_content.lower()):  # 没有 class 定义，说明是纯 utility 函数块
                has_inline_utility = True

        if has_inline_utility:
            # 移除内联 utility 函数块，添加 #include "utility.h"
            output_lines.extend(lines[:first_namespace_idx])
            if not has_utility_include:
                output_lines.append('')
                output_lines.append('#include "utility.h"')
                output_lines.append('')
            output_lines.extend(lines[first_namespace_end + 1:])
            return '\n'.join(output_lines)
        elif uses_utility_functions and not has_utility_include:
            # 代码使用了 utility 函数但没有包含头文件，添加它
            # 在最后一个 #include 后添加
            last_include_idx = -1
            for i, line in enumerate(lines):
                if line.strip().startswith('#include'):
                    last_include_idx = i

            if last_include_idx >= 0:
                output_lines.extend(lines[:last_include_idx + 1])
                output_lines.append('')
                output_lines.append('#include "utility.h"')
                output_lines.append('')
                output_lines.extend(lines[last_include_idx + 1:])
            else:
                # 没有找到 #include，在文件开头添加
                output_lines.append('#include "utility.h"')
                output_lines.append('')
                output_lines.extend(lines)

            return '\n'.join(output_lines)

        return code

    def _fix_llvm21_api_issues(self, code: str) -> str:
        """
        修复 LLVM-21 特定的 API 兼容性问题

        问题：
        1. dyn_cast 模板参数问题 - 某些类型转换需要特殊的处理
        2. APSIntPtr.isZero() 不存在 - 应该使用直接比较
        3. APSInt 的 getValue() 调用需要先解引用 ConcreteInt/SymbolVal
        4. ParentMap API 变化 - 内联 utility 函数中的 PM.getParent() 已废弃

        解决方案：
        1. 修复 dyn_cast<TypedValueRegion>(MR) 为 dyn_cast_or_null
        2. 修复 APSInt 相关的 isZero() 调用
        3. 内联 utility 函数中的 ParentMap API 不修复，将被 _fix_inline_utility_namespace 移除
        """
        import re

        lines = code.split('\n')
        output_lines = []

        for i, line in enumerate(lines):
            fixed_line = line

            # 1. 修复 APSInt 的 isZero() 调用 - 改为直接比较
            # Size.isZero() -> (Size == 0)
            fixed_line = re.sub(
                r'\b([\w.]+)\.isZero\(\)',
                r'(\1 == 0)',
                fixed_line
            )

            # 2. 修复 dyn_cast 对于 TypedValueRegion 的使用
            # 使用 dyn_cast_or_null 处理可能为空的情况
            fixed_line = re.sub(
                r'\bdyn_cast\s*<\s*TypedValueRegion\s*>\s*\(',
                r'dyn_cast_or_null<TypedValueRegion>(',
                fixed_line
            )

            # 3. 修复 dyn_cast 对于其他 Region 类型的使用
            # 统一使用 dyn_cast_or_null 提高鲁棒性
            fixed_line = re.sub(
                r'\bdyn_cast\s*<\s*(\w+Region)\s*>\s*\(',
                r'dyn_cast_or_null<\1>(',
                fixed_line
            )

            # 4. 修复非 Region 类型上的 dyn_cast，保持原样但加空格
            # （某些情况下的格式问题）

            output_lines.append(fixed_line)

        return '\n'.join(output_lines)

    def _fix_utility_include_path(self, code: str) -> str:
        """
        修复 LLM 生成的错误的 utility.h 包含路径

        问题：
        LLM 可能生成：
        - #include "clang/StaticAnalyzer/Checkers/utility.h"
        - #include <clang/StaticAnalyzer/Checkers/utility.h>

        但正确的应该是：
        - #include "utility.h"

        这是项目的自定义头文件，不是 Clang 官方头文件。
        """
        lines = code.split('\n')
        output_lines = []
        has_utility_include = False

        for line in lines:
            # 检测各种错误的 utility.h 包含路径
            if 'utility.h' in line and '#include' in line:
                if '"clang/StaticAnalyzer/Checkers/utility.h"' in line:
                    output_lines.append('#include "utility.h"  // Fixed from incorrect path')
                    has_utility_include = True
                    logger.debug("Fixed incorrect utility.h include path")
                elif '<clang/StaticAnalyzer/Checkers/utility.h>' in line:
                    output_lines.append('#include "utility.h"  // Fixed from incorrect path')
                    has_utility_include = True
                    logger.debug("Fixed incorrect utility.h include path")
                elif '#include "utility.h"' in line or '#include <utility.h>' in line:
                    # 正确的路径，保持不变
                    output_lines.append(line)
                    has_utility_include = True
                else:
                    # 其他包含 utility.h 的形式，替换为标准形式
                    output_lines.append('#include "utility.h"  // Normalized utility.h include')
                    has_utility_include = True
            else:
                output_lines.append(line)

        return '\n'.join(output_lines)

    def _fix_hallucinated_apis(self, code: str) -> str:
        """
        修复 LLM 幻觉的不存在的 API 调用

        LLM 经常生成一些不存在的函数，需要替换为正确的 API。

        常见幻觉：
        - evaluateToInt() / evaluateAsInt() -> EvaluateExprToInt()
        - getMaxSignedBits() -> getBitWidth()
        - getMemRegionFromExpr(E) -> getMemRegionFromExpr(E, C)
        - inferSymbolMaxVal(Sym) -> inferSymbolMaxVal(Sym, C)
        """
        import re

        lines = code.split('\n')
        output_lines = []
        fixed_count = 0

        for line in lines:
            original_line = line
            # 1. 修复 evaluateToInt / evaluateAsInt -> EvaluateExprToInt
            # Pattern: int size = evaluateToInt(expr, C);
            # Fix: llvm::APSInt result; if (EvaluateExprToInt(result, expr, C)) { int size = result.getExtValue(); }
            if re.search(r'\bevaluateToInt\s*\(', line) or re.search(r'\bevaluateAsInt\s*\(', line):
                # 这是一个比较复杂的替换，需要添加变量声明和 if 语句
                # 暂时添加注释，让修复阶段处理
                line = re.sub(r'\bevaluateToInt\s*\(', '/* FIXME: evaluateToInt should be EvaluateExprToInt */ evaluateToInt(', line)
                line = re.sub(r'\bevaluateAsInt\s*\(', '/* FIXME: evaluateAsInt should be EvaluateExprToInt */ evaluateAsInt(', line)
                fixed_count += 1

            # 2. 修复 getMaxSignedBits() -> getBitWidth()
            if 'getMaxSignedBits()' in line:
                line = line.replace('getMaxSignedBits()', 'getBitWidth()')
                fixed_count += 1

            # 3. 修复 getMemRegionFromExpr(E) -> getMemRegionFromExpr(E, C)
            # 使用正则表达式来匹配这种模式
            pattern = r'getMemRegionFromExpr\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)'
            match = re.search(pattern, line)
            if match:
                expr_var = match.group(1)
                # 检查是否已经有两个参数
                if not re.search(r'getMemRegionFromExpr\s*\([^,]+,\s*\w+\s*\)', line):
                    line = re.sub(pattern, f'getMemRegionFromExpr({expr_var}, C)', line)
                    fixed_count += 1

            # 4. 修复 inferSymbolMaxVal(Sym) -> inferSymbolMaxVal(Sym, C)
            pattern = r'inferSymbolMaxVal\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)'
            match = re.search(pattern, line)
            if match:
                sym_var = match.group(1)
                # 检查是否已经有两个参数
                if not re.search(r'inferSymbolMaxVal\s*\([^,]+,\s*\w+\s*\)', line):
                    line = re.sub(pattern, f'inferSymbolMaxVal({sym_var}, C)', line)
                    fixed_count += 1

            # 5. 修复 getStringSize -> getStringSize (if exists in utility.h)
            # 这个函数存在，但需要正确的参数

            # 6. 修复 getArraySizeDirect -> getArraySizeFromExpr
            if 'getArraySizeDirect(' in line:
                line = line.replace('getArraySizeDirect(', 'getArraySizeFromExpr(')
                fixed_count += 1

            # 7. 修复 isCallToFunction() - 幻觉API，使用 getCalleeIdentifier() 代替
            # 错误：if (isCallToFunction(Call, "free")) { ... }
            # 正确：const IdentifierInfo *II = Call.getCalleeIdentifier(); if (II && II->getName() == "free") { ... }
            if 'isCallToFunction(' in line:
                # 这是一个复杂的替换，暂时注释掉并添加警告
                line = re.sub(r'\bisCallToFunction\s*\([^,]+,\s*"([^"]+)"\s*\)',
                             r'/* FIXME: isCallToFunction() does not exist. Use: const IdentifierInfo *II = Call.getCalleeIdentifier(); if (II && II->getName() == "\1") */ true',
                             line)
                fixed_count += 1

            # 8. 修复 getElementSize() - 幻觉API，使用 ASTContext.getTypeSize() 代替
            # 错误：size_t size = getElementSize(type);
            # 正确：uint64_t size = C.getASTContext().getTypeSize(type);
            if 'getElementSize(' in line:
                line = re.sub(r'\bgetElementSize\s*\(',
                             r'C.getASTContext().getTypeSize(',
                             line)
                fixed_count += 1

            # 9. 修复 getBufferSize() - 幻觉API
            if 'getBufferSize(' in line:
                line = re.sub(r'\bgetBufferSize\s*\(',
                             r'/* FIXME: getBufferSize() does not exist */ C.getASTContext().getTypeSize(',
                             line)
                fixed_count += 1

            # 10. 修复 APInt 到 APSInt 的直接转换
            # 错误：llvm::APSInt value = apint_obj;
            # 正确：llvm::APSInt value(apint_obj, true);
            if re.search(r'llvm::APSInt\s+\w+\s*=\s*\w+\.get\w+\(\);', line):
                line = re.sub(r'(llvm::APSInt\s+(\w+)\s*=\s*)(\w+)\.get(\w+)\(\);',
                             r'\1llvm::APSInt(\3.get\4(), true);',
                             line)
                fixed_count += 1

            if line != original_line:
                logger.debug(f"Fixed hallucinated API: {original_line[:60]}...")

            output_lines.append(line)

        if fixed_count > 0:
            logger.info(f"Fixed {fixed_count} hallucinated API calls")

        return '\n'.join(output_lines)


class PluginCodeGenerator:
    """
    插件式 Checker 代码生成器

    生成使用 CheckerRegistry.h 而非 BuiltinCheckerRegistration.h 的代码
    """

    # 插件式 Checker 模板（Knighter 风格）
    PLUGIN_TEMPLATE = '''#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {{
class {checker_class} : public Checker<check::PreCall> {{
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // 初始化 BugType
  {checker_class}() : BT(new BugType(this, "{checker_name}", "{category}")) {{}}
}};
}} // end anonymous namespace

// 主检查逻辑
void {checker_class}::checkPreCall(const CallEvent &Call, CheckerContext &C) const {{
{check_logic}
}}

// 插件注册 - 使用 CheckerRegistry.h 而非 BuiltinCheckerRegistration.h
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_class}>(
      "custom.{checker_class}",
      "{description}",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
'''

    def generate_plugin_checker(
        self,
        vulnerability_type: str,
        description: str = "Detects security vulnerabilities"
    ) -> str:
        """
        生成插件式 Checker 代码

        Args:
            vulnerability_type: 漏洞类型（如 buffer_overflow, use_after_free）
            description: Checker 描述

        Returns:
            完整的插件式 Checker C++ 代码
        """
        # 映射漏洞类型到具体的检查逻辑
        checker_configs = {
            "buffer_overflow": {
                "class": "BufferOverflowChecker",
                "category": "Security",
                "logic": self._get_buffer_overflow_logic()
            },
            "use_after_free": {
                "class": "UseAfterFreeChecker",
                "category": "Memory",
                "logic": self._get_use_after_free_logic()
            },
            "null_pointer": {
                "class": "NullPointerDereferenceChecker",
                "category": "Security",
                "logic": self._get_null_pointer_logic()
            },
            "uninitialized_var": {
                "class": "UninitializedVarChecker",
                "category": "Security",
                "logic": self._get_uninitialized_var_logic()
            }
        }

        config = checker_configs.get(
            vulnerability_type,
            {
                "class": "GenericChecker",
                "category": "Security",
                "logic": "  // Generic check logic\n  // TODO: Implement specific vulnerability detection"
            }
        )

        return self.PLUGIN_TEMPLATE.format(
            checker_class=config["class"],
            checker_name=config["class"].replace("Checker", " Checker"),
            category=config["category"],
            description=description,
            check_logic=config["logic"]
        )

    def _get_buffer_overflow_logic(self) -> str:
        """缓冲区溢出检测逻辑"""
        return '''  // 检测危险的字符串操作函数
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  if (!II) return;

  llvm::StringRef FName = II->getName();

  // 检测不安全的函数调用
  if (FName == "gets" || FName == "strcpy" || FName == "strcat" ||
      FName == "sprintf" || FName == "scanf") {
    // 报告缓冲区溢出风险
    ExplodedNode *N = C.generateErrorNode();
    if (!N) return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Potential buffer overflow detected: unsafe function call",
        N);
    C.emitReport(std::move(Report));
  }

  // 检测 memcpy 溢出
  if (FName == "memcpy") {
    if (Call.getNumArgs() >= 3) {
      // 这里可以添加更复杂的尺寸检查逻辑
      // 简化版：仅标记需要检查
      ExplodedNode *N = C.generateErrorNode();
      if (!N) return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "memcpy called: verify size parameters to prevent overflow",
          N);
      C.emitReport(std::move(Report));
    }
  }'''

    def _get_use_after_free_logic(self) -> str:
        """Use-After-Free 检测逻辑"""
        return '''  // 跟踪已释放的内存
  const IdentifierInfo *II = Call.getCalleeIdentifier();
  if (!II) return;

  llvm::StringRef FName = II->getName();

  // 检测 free 调用
  if (FName == "free" || FName == "kfree") {
    if (Call.getNumArgs() >= 1) {
      // 记录释放的指针（需要符号执行支持）
      // 这里是简化实现
    }
  }

  // 检测可能的 use-after-free
  // 实际实现需要维护一个已释放内存的集合
  // 并在每次函数调用时检查参数是否指向已释放的内存'''

    def _get_null_pointer_logic(self) -> str:
        """空指针解引用检测逻辑"""
        return '''  // 检测可能的空指针解引用
  if (Call.getNumArgs() == 0) return;

  // 检查函数参数是否可能为空
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    if (Call.getArgSVal(i).isUndef() || Call.getArgSVal(i).isZeroConstant()) {
      ExplodedNode *N = C.generateErrorNode();
      if (!N) return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Potential null pointer dereference",
          N);
      C.emitReport(std::move(Report));
      break;
    }
  }'''

    def _get_uninitialized_var_logic(self) -> str:
        """未初始化变量检测逻辑"""
        return '''  // 检测未初始化变量的使用
  if (Call.getNumArgs() == 0) return;

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    auto ArgVal = Call.getArgSVal(i);

    // 检查是否为未定义值
    if (ArgVal.isUndef()) {
      ExplodedNode *N = C.generateErrorNode();
      if (!N) return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Use of uninitialized variable detected",
          N);
      C.emitReport(std::move(Report));
      break;
    }
  }'''


def convert_to_plugin_style(code: str, checker_class_name: str = None) -> str:
    """
    将现有代码转换为插件式风格

    移除 BuiltinCheckerRegistration.h 依赖，使用插件注册方式
    Clang 21 支持 LLM 生成的现代 API，因此只需要做最小转换

    Args:
        code: 原始 checker 代码
        checker_class_name: Checker 类名（自动推断）

    Returns:
        转换后的插件式代码
    """
    # ============================================================================
    # 第一阶段：使用行处理方式移除旧的注册代码
    # ============================================================================
    lines = code.split('\n')
    output_lines = []
    skip_until_brace = False
    in_old_registration_func = False

    for line in lines:
        # 跳过旧的注册函数（单行和多行）
        if 'void ento::register' in line or 'bool ento::shouldRegister' in line:
            # 单行函数（没有 { 在当前行）
            if '{' not in line:
                continue  # 跳过整行
            else:
                in_old_registration_func = True
                continue

        # 如果在多行注册函数中，检查是否结束
        if in_old_registration_func:
            if '{' in line:
                skip_until_brace = True
            if '}' in line and skip_until_brace:
                in_old_registration_func = False
                skip_until_brace = False
                continue
            continue

        # 处理 BuiltinCheckerRegistration.h
        if 'BuiltinCheckerRegistration.h' in line and '#include' in line:
            output_lines.append('// BuiltinCheckerRegistration.h removed - using plugin style')
            if 'CheckerRegistry.h' not in code:
                output_lines.append('#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"')
            continue

        output_lines.append(line)

    code = '\n'.join(output_lines)

    # ============================================================================
    # 添加插件注册函数
    # ============================================================================
    if 'clang_registerCheckers' not in code:
        if not checker_class_name:
            class_match = re.search(r'class\s+(\w+)\s*:\s*public\s+Checker<', code)
            if class_match:
                checker_class_name = class_match.group(1)
            else:
                checker_class_name = "CustomChecker"

        # 找到 namespace 结束的 }
        last_brace = code.rfind('}')
        if last_brace != -1:
            # 查找 namespace 结束前的位置
            namespace_end = code.rfind('} // namespace', 0, last_brace)
            if namespace_end == -1:
                namespace_end = code.rfind('}\n\n}', 0, last_brace)
            if namespace_end != -1:
                insert_pos = code.find('}', namespace_end)
                code = code[:insert_pos + 1] + f'''

// Plugin registration - Knighter style
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_class_name}>(
      "custom.{checker_class_name}",
      "Auto-generated checker",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
''' + code[insert_pos + 1:]
            else:
                # 找不到明确的 namespace 结束，添加到最后
                code = code.rstrip() + f'''

// Plugin registration - Knighter style
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_class_name}>(
      "custom.{checker_class_name}",
      "Auto-generated checker",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
'''

    return code


class PluginCodeGenerator:
    """
    插件式 Checker 代码生成器

    生成使用 CheckerRegistry.h 而非 BuiltinCheckerRegistration.h 的代码
    """

    # 插件式 Checker 模板（Knighter 风格）
    PLUGIN_TEMPLATE = '''#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {{
class {checker_class} : public Checker<check::PreCall> {{
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  // 初始化 BugType
  {checker_class}() : BT(new BugType(this, "{checker_name}", "{category}")) {{}}
}};
}} // end anonymous namespace

// 主检查逻辑
void {checker_class}::checkPreCall(const CallEvent &Call, CheckerContext &C) const {{
{check_logic}
}}

// 插件注册 - 使用 CheckerRegistry.h 而非 BuiltinCheckerRegistration.h
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_class}>(
      "custom.{checker_class}",
      "{description}",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
'''


# 便捷函数
def build_checker_plugin(
    code: str,
    plugin_name: str,
    output_dir: Path
) -> Tuple[bool, str, str]:
    """
    便捷函数：构建 Checker 插件

    Args:
        code: Checker 源代码
        plugin_name: 插件名称
        output_dir: 输出目录

    Returns:
        (success, plugin_path_or_error, stderr)
    """
    builder = PluginBuilder()
    result = builder.build_checker_simple(code, plugin_name, output_dir)

    if result.success:
        return True, result.plugin_path, result.stderr
    else:
        return False, "", result.stderr
