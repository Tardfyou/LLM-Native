"""
代码处理工具
Code processing utilities

参考KNighter的tools.py，提供代码提取、错误格式化等实用函数
"""

import re
import logging
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


# ============================================================================
# 新增工具函数 - 参考KNighter
# ============================================================================

def extract_checker_code(response: str) -> str:
    """
    从LLM响应中提取checker代码

    支持多种代码块格式:
    - ```cpp ... ```
    - ```c++ ... ```
    - ```C++ ... ```
    - ```c ... ```
    - 嵌套代码块处理

    Args:
        response: LLM响应文本

    Returns:
        提取出的代码，如果没有找到则返回原始响应
    """
    if not response:
        return ""

    # 首先尝试提取最外层的代码块
    patterns = [
        r'```cpp\s*\n(.*?)```',
        r'```c\+\+\s*\n(.*?)```',
        r'```C\+\+\s*\n(.*?)```',
        r'```c\s*\n(.*?)```',
        r'```\s*\n(.*?)```',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, response, re.DOTALL)
        if matches:
            # 取最后一个匹配（通常是最完整的代码）
            code = matches[-1].strip()
            logger.debug(f"Extracted code using pattern: {pattern[:20]}...")
            return code

    # 如果没有找到代码块，返回原始响应
    logger.warning("No code block found in response, returning original")
    return response.strip()


def grab_error_message(error_content: str) -> List[Dict[str, str]]:
    """
    从编译错误输出中提取结构化的错误信息

    解析格式如:
    error: 'xxx' was not declared in this scope
       12 |     return xxx;
          |            ^~~

    Args:
        error_content: 编译错误输出

    Returns:
        错误信息列表，每个错误包含error_message和error_code_context
    """
    if not error_content:
        return []

    errors = []
    lines = error_content.split('\n')

    current_error = None

    for line in lines:
        # 检测错误开始行
        if 'error:' in line and 'warning:' not in line:
            if current_error:
                errors.append(current_error)

            # 提取错误消息
            error_match = re.search(r'error:\s*(.+)', line)
            if error_match:
                current_error = {
                    'error_message': error_match.group(1).strip(),
                    'error_code_context': []
                }

        # 检测上下文代码行（包含|的行）
        elif current_error and '|' in line:
            # 移除行号和|符号，保留代码
            code_line = re.sub(r'^\s*\d+\s*\|\s*', '', line)
            code_line = re.sub(r'\s*\|$', '', code_line)
            if code_line.strip():
                current_error['error_code_context'].append(code_line)

    # 添加最后一个错误
    if current_error:
        errors.append(current_error)

    logger.debug(f"Extracted {len(errors)} errors from output")
    return errors


def error_formatting(error_list: List[Dict[str, str]]) -> str:
    """
    格式化错误列表为Markdown格式

    Args:
        error_list: 错误列表

    Returns:
        Markdown格式的错误描述
    """
    if not error_list:
        return "No errors found."

    formatted = []

    for i, error in enumerate(error_list, 1):
        formatted.append(f"## Error {i}")
        formatted.append(f"**Message**: `{error['error_message']}`")

        if error['error_code_context']:
            formatted.append("**Code Context**:")
            formatted.append("```cpp")
            for line in error['error_code_context']:
                formatted.append(f"    {line}")
            formatted.append("```")

        formatted.append("")

    return "\n".join(formatted)


def remove_think_tags(text: str) -> str:
    """
    移除DeepSeek推理模型的``标签内容

    Args:
        text: 包含``标签的文本

    Returns:
        移除后的文本
    """
    if not text:
        return text

    # 移除整个``块
    pattern = r'<\|.*?\|>'
    cleaned = re.sub(pattern, '', text, flags=re.DOTALL)

    # 清理多余空行
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)

    return cleaned.strip()


def count_tokens(text: str) -> int:
    """
    简单的token计数估计

    大约4个字符=1个token

    Args:
        text: 输入文本

    Returns:
        估计的token数量
    """
    return len(text) // 4


def validate_cpp_syntax(code: str) -> Tuple[bool, Optional[str]]:
    """
    基本的C++语法验证

    检查:
    - 大括号匹配
    - 圆括号匹配
    - 分号结束

    Args:
        code: C++代码

    Returns:
        (是否有效, 错误消息)
    """
    if not code:
        return False, "Empty code"

    # 检查大括号平衡
    open_braces = code.count('{')
    close_braces = code.count('}')
    if open_braces != close_braces:
        return False, f"Unbalanced braces: {open_braces} open, {close_braces} close"

    # 检查圆括号平衡（排除字符串和注释）
    # 简化版本：只检查整体数量
    open_parens = code.count('(')
    close_parens = code.count(')')
    if open_parens != close_parens:
        return False, f"Unbalanced parentheses: {open_parens} open, {close_parens} close"

    # 检查基本的函数结构
    if 'class ' not in code and 'namespace ' not in code:
        # 如果不是类定义，检查是否有main函数或registerChecker函数
        if 'void registerChecker' not in code and 'int main' not in code:
            return False, "No entry point found (expected 'registerChecker' function)"

    return True, None


def normalize_code(code: str) -> str:
    """
    规范化代码格式

    - 移除多余空行
    - 统一缩进（简单处理）
    - 移除行尾空格

    Args:
        code: 原始代码

    Returns:
        规范化后的代码
    """
    if not code:
        return code

    lines = code.split('\n')

    # 移除行尾空格
    lines = [line.rstrip() for line in lines]

    # 移除多余空行（超过2个连续空行）
    normalized = []
    empty_count = 0
    for line in lines:
        if line.strip():
            normalized.append(line)
            empty_count = 0
        else:
            empty_count += 1
            if empty_count <= 2:
                normalized.append(line)

    return '\n'.join(normalized)


def get_object_id(object_name: str) -> str:
    """
    将对象文件名转换为安全的ID

    将 / 和 . 替换为 -

    Args:
        object_name: 对象文件名

    Returns:
        安全的ID字符串
    """
    return object_name.replace("/", "-").replace(".o", "").strip()


# ============================================================================
# 原有类定义
# ============================================================================

class CodeAnalyzer:
    """代码分析器"""

    @staticmethod
    def extract_functions(code: str) -> List[Dict[str, Any]]:
        """提取代码中的函数定义"""
        functions = []

        # C/C++函数定义正则表达式
        func_pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*{'

        for match in re.finditer(func_pattern, code):
            return_type, func_name = match.groups()
            start_pos = match.start()

            # 找到对应的结束大括号
            brace_count = 0
            end_pos = start_pos

            for i, char in enumerate(code[start_pos:], start_pos):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i
                        break

            functions.append({
                "name": func_name,
                "return_type": return_type,
                "start_pos": start_pos,
                "end_pos": end_pos,
                "signature": match.group(0),
                "body": code[start_pos:end_pos + 1]
            })

        return functions

    @staticmethod
    def extract_includes(code: str) -> List[str]:
        """提取include语句"""
        include_pattern = r'#include\s*[<"]([^>"]+)[>"]'
        return re.findall(include_pattern, code)

    @staticmethod
    def detect_vulnerability_patterns(code: str) -> List[str]:
        """检测常见的漏洞模式"""
        patterns = []

        # 缓冲区溢出模式
        if re.search(r'strcpy\s*\(', code, re.IGNORECASE):
            patterns.append("potential_buffer_overflow_strcpy")

        if re.search(r'sprintf\s*\(', code, re.IGNORECASE):
            patterns.append("potential_buffer_overflow_sprintf")

        # 空指针解引用
        if re.search(r'->\s*[^;]+;', code):
            patterns.append("potential_null_pointer_dereference")

        # 释放后使用
        if re.search(r'free\s*\([^)]+\)', code, re.IGNORECASE):
            patterns.append("use_after_free_risk")

        return patterns

class PatchProcessor:
    """补丁处理器"""

    @staticmethod
    def parse_patch(patch: str) -> List[Dict[str, Any]]:
        """解析补丁内容"""
        hunks = []
        lines = patch.split('\n')

        current_hunk = None
        for line in lines:
            if line.startswith('@@'):
                # 新hunk开始
                if current_hunk:
                    hunks.append(current_hunk)

                # 解析hunk头部
                match = re.match(r'@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@', line)
                if match:
                    old_start, old_count, new_start, new_count = match.groups()
                    current_hunk = {
                        "old_start": int(old_start),
                        "old_count": int(old_count) if old_count else 1,
                        "new_start": int(new_start),
                        "new_count": int(new_count) if new_count else 1,
                        "changes": []
                    }
            elif current_hunk and line.startswith(('+', '-')):
                current_hunk["changes"].append({
                    "type": "addition" if line.startswith('+') else "deletion",
                    "content": line[1:].strip(),
                    "line": line
                })

        if current_hunk:
            hunks.append(current_hunk)

        return hunks

    @staticmethod
    def extract_modified_files(patch: str) -> List[str]:
        """提取修改的文件"""
        files = []
        for line in patch.split('\n'):
            if line.startswith('+++ b/'):
                files.append(line[6:])
        return files

    @staticmethod
    def calculate_patch_complexity(patch: str) -> float:
        """计算补丁复杂度"""
        hunks = PatchProcessor.parse_patch(patch)
        total_changes = sum(len(hunk["changes"]) for hunk in hunks)
        file_count = len(PatchProcessor.extract_modified_files(patch))

        # 复杂度计算：基于变更数量和文件数量
        complexity = min(1.0, (total_changes / 50) + (file_count / 5))
        return complexity

class FileManager:
    """文件管理器"""

    @staticmethod
    def read_file(file_path: Path, encoding: str = 'utf-8') -> str:
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            # 尝试其他编码
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.read()
            except Exception as e:
                raise Exception(f"Failed to read file {file_path}: {e}")

    @staticmethod
    def write_file(file_path: Path, content: str, encoding: str = 'utf-8') -> bool:
        """写入文件内容"""
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"Failed to write file {file_path}: {e}")
            return False

    @staticmethod
    def find_files(directory: Path, pattern: str = "*.cpp") -> List[Path]:
        """查找文件"""
        return list(directory.rglob(pattern))

    @staticmethod
    def create_backup(file_path: Path) -> Path:
        """创建文件备份"""
        backup_path = file_path.with_suffix(file_path.suffix + '.backup')
        import shutil
        shutil.copy2(file_path, backup_path)
        return backup_path
