"""
工具函数模块

提供代码处理、错误解析、进程管理等实用工具。
参考Knighter的tools.py设计，但增强了错误处理和日志功能。
"""

import html
import io
import json
import os
import re
import subprocess
import threading
import time
from bs4 import BeautifulSoup
from pathlib import Path
from queue import Queue
from typing import List, Optional, Tuple, Dict, Any

from loguru import logger


def extract_checker_code(llm_response: str) -> Optional[str]:
    """
    从LLM响应中提取C++代码

    Args:
        llm_response: LLM的响应文本

    Returns:
        提取的C++代码，如果未找到则返回None
    """
    # 尝试提取 ```cpp 代码块
    pattern = r"```cpp\n([\s\S]*?)\n```"
    match = re.search(pattern, llm_response)
    if match:
        return match.group(1).strip()

    # 尝试提取 ``` 代码块
    pattern = r"```\n([\s\S]*?)\n```"
    match = re.search(pattern, llm_response)
    if match:
        code = match.group(1).strip()
        # 检查是否是C++代码
        if "#include" in code or "class " in code or "void " in code:
            return code

    # 尝试找到第一个包含 #include 的代码块
    lines = llm_response.split("\n")
    code_lines = []
    in_code = False
    for line in lines:
        if line.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            code_lines.append(line)
        elif "#include" in line or "namespace" in line:
            # 开始收集代码
            code_lines.append(line)

    if code_lines:
        return "\n".join(code_lines).strip()

    logger.warning("Could not extract checker code from LLM response")
    return None


def grab_error_message(error_content: str) -> List[str]:
    """
    从编译错误输出中提取错误信息

    Args:
        error_content: 编译器的错误输出

    Returns:
        错误信息列表，每个元素包含错误和相关的代码行
    """
    # 匹配格式: error:... 后跟带行号的代码行
    pattern = r"error:.*\n\s*\d+\s*\|\s+.*\n"
    error_list = re.findall(pattern, error_content, re.MULTILINE)

    if not error_list:
        # 尝试另一种格式
        pattern = r"error:.*"
        error_list = re.findall(pattern, error_content, re.MULTILINE)

    return error_list


def error_formatting(error_list: List[str]) -> str:
    """
    将错误列表格式化为Markdown格式

    Args:
        error_list: 错误信息列表

    Returns:
        格式化后的Markdown文本
    """
    error_list_md = ""
    for error in error_list:
        error_list_md += "- Error Line: "
        error_parts = error.split("\n")
        error_list_md += error_parts[1].lstrip() if len(error_parts) > 1 else "unknown"
        error_list_md += "\n\n"
        error_list_md += "\t- Error Messages: "
        error_list_md += error_parts[0].lstrip("error: ") if error_parts else ""
        error_list_md += "\n\n"
    return error_list_md


def force_terminate_process(process, timeout: int = 5) -> bool:
    """
    强制终止进程，首先尝试SIGTERM，然后SIGKILL

    Args:
        process: subprocess.Popen对象
        timeout: 等待优雅终止的超时时间（秒）

    Returns:
        是否成功终止进程
    """
    if process.poll() is not None:
        return True

    process.terminate()
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        logger.warning(
            f"Process didn't terminate after {timeout} seconds, sending SIGKILL"
        )

    process.kill()
    try:
        process.wait(timeout=3)
        return True
    except subprocess.TimeoutExpired:
        logger.error("Process couldn't be killed!")
        return False


def monitor_build_output(
    process,
    warning_limit: int = 100,
    timeout: Optional[int] = None
) -> Tuple[str, str]:
    """
    实时监控构建输出，在警告超限时停止

    Args:
        process: subprocess.Popen对象
        warning_limit: 允许的最大警告数
        timeout: 最大等待时间（秒）

    Returns:
        (输出文本, 完成状态)
    """
    try:
        import psutil
    except ImportError:
        logger.warning("psutil not available, using basic process termination")
        psutil = None

    warning_count = 0
    output_lines = []
    process_completed = True
    stop_monitoring = threading.Event()

    def read_output(stream, queue, stop_event):
        """从输出流读取行并放入队列"""
        try:
            text_stream = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
            while not stop_event.is_set():
                try:
                    line = text_stream.readline()
                    if not line:
                        break
                    queue.put(line)
                except Exception:
                    break
        except Exception:
            pass
        finally:
            queue.put(None)

    stdout_queue = Queue()
    stderr_queue = Queue()

    stdout_thread = threading.Thread(
        target=read_output,
        args=(process.stdout, stdout_queue, stop_monitoring)
    )
    stderr_thread = threading.Thread(
        target=read_output,
        args=(process.stderr, stderr_queue, stop_monitoring)
    )

    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

    start_time = time.time()
    stdout_done = stderr_done = False

    try:
        while not (stdout_done and stderr_done) and process.poll() is None:
            if timeout is not None and time.time() - start_time > timeout:
                logger.warning(f"Timeout of {timeout} seconds exceeded!")
                process_completed = False
                break

            # 处理stdout
            if not stdout_done:
                try:
                    line = stdout_queue.get(timeout=0.1)
                    if line is None:
                        stdout_done = True
                    else:
                        output_lines.append(line)
                        if "warning:" in line.lower():
                            warning_count += 1
                            if warning_count <= 10:
                                logger.warning(f"Warning {warning_count}: {line.strip()}")
                except Exception:
                    pass

            # 处理stderr
            if not stderr_done:
                try:
                    line = stderr_queue.get(timeout=0.1)
                    if line is None:
                        stderr_done = True
                    else:
                        output_lines.append(line)
                        if "warning:" in line.lower():
                            warning_count += 1
                            if warning_count <= 10:
                                logger.warning(f"Warning {warning_count}: {line.strip()}")
                except Exception:
                    pass

            if warning_limit > 0 and warning_count > warning_limit:
                logger.error(f"Warning limit of {warning_limit} exceeded!")
                process_completed = False
                break

    finally:
        stop_monitoring.set()

        if process.poll() is None:
            logger.info("Terminating build process...")
            if psutil:
                force_terminate_process_group(process, psutil)
            else:
                force_terminate_process(process)

        try:
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
        except Exception:
            pass

        for thread, name in [(stdout_thread, "stdout"), (stderr_thread, "stderr")]:
            if thread.is_alive():
                thread.join(timeout=3)
                if thread.is_alive():
                    logger.warning(f"{name} thread did not terminate cleanly")

        _drain_queue(stdout_queue, output_lines)
        _drain_queue(stderr_queue, output_lines)

    if process_completed:
        return "".join(output_lines), "Complete"
    else:
        return "".join(output_lines), "Terminated"


def force_terminate_process_group(process, psutil_module, timeout: int = 10) -> bool:
    """终止进程组"""
    if process.poll() is not None:
        return True

    try:
        parent = psutil_module.Process(process.pid)
        children = parent.children(recursive=True)

        logger.info(
            f"Terminating process group (PID: {process.pid}) "
            f"and {len(children)} children..."
        )

        for child in children:
            try:
                child.terminate()
            except (psutil_module.NoSuchProcess, psutil_module.AccessDenied):
                pass

        parent.terminate()

        try:
            process.wait(timeout=timeout // 2)
            return True
        except subprocess.TimeoutExpired:
            pass

    except (psutil_module.NoSuchProcess, psutil_module.AccessDenied):
        pass

    try:
        if psutil:
            parent = psutil_module.Process(process.pid)
            children = parent.children(recursive=True)

            for child in children:
                try:
                    child.kill()
                except (psutil_module.NoSuchProcess, psutil_module.AccessDenied):
                    pass

            parent.kill()

        process.wait(timeout=timeout // 2)
        return True
    except subprocess.TimeoutExpired:
        logger.error("Failed to kill process group!")
        return False


def _drain_queue(queue, output_lines):
    """排空队列中剩余的项目"""
    try:
        while True:
            item = queue.get_nowait()
            if item is not None:
                output_lines.append(item)
    except Exception:
        pass


def compile_checker(
    checker_code: str,
    checker_name: str,
    llvm_dir: Path,
    output_dir: Path
) -> Tuple[bool, str, str]:
    """
    编译Clang Static Analyzer检查器

    Args:
        checker_code: 检查器C++代码
        checker_name: 检查器名称
        llvm_dir: LLVM安装目录
        output_dir: 输出目录

    Returns:
        (是否成功, 编译输出, 错误信息)
    """
    # 创建临时目录
    temp_dir = output_dir / "temp_build"
    temp_dir.mkdir(parents=True, exist_ok=True)

    checker_file = temp_dir / f"{checker_name}.cpp"
    checker_file.write_text(checker_code)

    # 创建加载器
    loader_file = temp_dir / "checker_loader.cpp"
    loader_content = f"""
#include "{checker_name}.cpp"
// Empty loader - the checker registers itself
"""
    loader_file.write_text(loader_content)

    # 构建命令
    build_dir = temp_dir / "build"
    build_dir.mkdir(exist_ok=True)

    # 使用CMake配置
    cmake_cmd = [
        "cmake",
        f"-DLLVM_DIR={llvm_dir}/lib/cmake/llvm",
        f"-DCLANG_DIR={llvm_dir}/lib/cmake/clang",
        "-G", "Unix", "Makefiles",
        str(temp_dir)
    ]

    try:
        result = subprocess.run(
            cmake_cmd,
            cwd=build_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            return False, result.stdout, result.stderr

        # 编译
        build_cmd = ["make", "-j4"]
        result = subprocess.run(
            build_cmd,
            cwd=build_dir,
            capture_output=True,
            text=True,
            timeout=300,
            env={**os.environ, "CXX": "clang++"}
        )

        if result.returncode != 0:
            return False, result.stdout, result.stderr

        return True, result.stdout, ""

    except subprocess.TimeoutExpired:
        return False, "", "Compilation timed out"
    except Exception as e:
        return False, "", str(e)


def get_source_code_from_html(html_text: str) -> str:
    """
    从HTML报告中提取相关源代码

    Args:
        html_text: HTML格式的报告内容

    Returns:
        提取的源代码文本
    """
    start = html_text.find("relevant_lines = ") + len("relevant_lines = ")
    end = html_text.find(";", start)
    try:
        relevant_lines = json.loads(html_text[start:end])
    except json.JSONDecodeError:
        relevant_lines = {}

    soup = BeautifulSoup(html_text, "html.parser")
    output = []

    for table in soup.find_all("table", class_="code"):
        file_id = table.get("data-fileid")
        if not file_id or file_id not in relevant_lines:
            continue

        relevant_line_numbers = list(relevant_lines[file_id].keys())
        relevant_line_numbers.sort(key=int)

        expanded_line_numbers = set()
        for line_no in relevant_line_numbers:
            expanded_line_numbers.add(line_no)
            for i in range(-50, 31):
                expanded_line_numbers.add(str(int(line_no) + i))

        for line in table.find_all("tr"):
            if line.get("class") == ["codeline"]:
                line_no = line.get("data-linenumber")
                if line_no in expanded_line_numbers:
                    code_td = line.find("td", class_="line")
                    if code_td:
                        for unwanted_span in code_td.find_all("span", class_="macro_popup"):
                            unwanted_span.decompose()

                        cleaned_text = html.unescape(
                            code_td.get_text(separator="", strip=False)
                        )
                        cleaned_text = str(line_no).ljust(6) + "| " + cleaned_text
                        output.append(cleaned_text)
            elif line.find("div", class_="msg msgEvent"):
                cleaned_text = html.unescape(line.get_text(separator="", strip=False))
                cleaned_text = " " * 4 + cleaned_text
                output.append(cleaned_text)
            elif line.find("div", class_="msg msgControl"):
                cleaned_text = html.unescape(line.get_text(separator="", strip=False))
                cleaned_text = " " * 4 + cleaned_text
                output.append(cleaned_text)

    return "\n".join(output)


def remove_html_section(text: str, html_text: str) -> str:
    """
    从报告中移除特定的HTML部分

    Args:
        text: 文本内容
        html_text: HTML内容

    Returns:
        处理后的文本
    """
    start_marker = "### Annotated Source Code"
    end_marker = "Show only relevant lines"

    start_pos = text.find(start_marker)
    if start_pos == -1:
        return text

    removal_start = start_pos + len(start_marker) + 1
    text = text[:removal_start]
    text = text.replace("### Bug Summary", "### Report Summary")

    source_code = get_source_code_from_html(html_text)
    return text + "\n\n" + source_code


def truncate_large_file(content: str, max_lines: int = 500) -> str:
    """
    截断过大的文件内容

    Args:
        content: 文件内容
        max_lines: 最大行数

    Returns:
        截断后的内容
    """
    lines = content.split("\n")
    if len(lines) <= max_lines:
        return content

    keep_each = max_lines // 2
    first_part = lines[:keep_each]
    last_part = lines[-keep_each:]

    truncated_content = "\n".join(first_part)
    truncated_content += (
        f"\n\n// ... [TRUNCATED: {len(lines) - max_lines} lines omitted] ...\n\n"
    )
    truncated_content += "\n".join(last_part)

    return truncated_content


def validate_checker_syntax(checker_code: str) -> Tuple[bool, List[str]]:
    """
    验证检查器代码的语法

    Args:
        checker_code: 检查器代码

    Returns:
        (是否有效, 错误列表)
    """
    errors = []

    # 基本检查
    if not checker_code.strip():
        errors.append("Empty checker code")
        return False, errors

    # 检查必需的头文件
    required_includes = [
        "clang/StaticAnalyzer/Core/Checker.h",
        "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
    ]

    for include in required_includes:
        if include not in checker_code:
            errors.append(f"Missing required include: {include}")

    # 检查必需的元素
    if "class " not in checker_code:
        errors.append("Missing checker class definition")

    if "clang_registerCheckers" not in checker_code:
        errors.append("Missing checker registration function")

    # 检查基本的回调函数
    if "check::" not in checker_code and "check" not in checker_code:
        errors.append("Missing checker callback functions")

    return len(errors) == 0, errors


def format_error_context(code: str, error_line: int, context_lines: int = 3) -> str:
    """
    格式化错误的上下文

    Args:
        code: 源代码
        error_line: 错误行号
        context_lines: 上下文行数

    Returns:
        格式化的上下文文本
    """
    lines = code.split("\n")
    start = max(0, error_line - context_lines - 1)
    end = min(len(lines), error_line + context_lines)

    result = []
    for i in range(start, end):
        prefix = ">>> " if i == error_line - 1 else "    "
        result.append(f"{prefix}{i+1:4d} | {lines[i]}")

    return "\n".join(result)
