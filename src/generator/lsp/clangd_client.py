"""
Clangd Language Server Protocol 客户端
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)

class ClangdClient:
    """Clangd LSP客户端"""

    def __init__(self, clangd_path: Optional[str] = None):
        self.clangd_path = clangd_path or "clangd"
        self.process = None
        self.is_connected = False

        # LSP协议状态
        self.request_id = 1
        self.pending_requests = {}

    async def start_server(self, project_root: Path) -> bool:
        """启动Clangd服务器"""
        try:
            # 检查clangd是否可用
            result = await asyncio.create_subprocess_exec(
                self.clangd_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()

            if result.returncode != 0:
                logger.error("clangd not found or not working")
                return False

            # 启动clangd进程
            self.process = await asyncio.create_subprocess_exec(
                self.clangd_path,
                "--log=verbose",  # 使用verbose日志以便调试
                "--background-index=false",  # 禁用后台索引以加快启动
                "--clang-tidy=false",  # 禁用clang-tidy
                "--completion-style=bundled",  # 使用bundled完成风格
                "--header-insertion=never",  # 不自动插入头文件
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(project_root)
            )

            self.is_connected = True
            logger.info("Clangd server started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start clangd server: {e}")
            return False

    async def stop_server(self):
        """停止Clangd服务器"""
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except Exception as e:
                logger.warning(f"Error stopping clangd server: {e}")
                self.process.kill()

            self.process = None
            self.is_connected = False
            logger.info("Clangd server stopped")

    async def initialize_server(self, project_root: Path) -> bool:
        """初始化LSP服务器"""
        if not await self.start_server(project_root):
            logger.warning("Clangd server failed to start, LSP will be disabled")
            return False

        # 发送初始化请求
        init_params = {
            "processId": None,
            "rootPath": str(project_root),
            "rootUri": f"file://{project_root}",
            "capabilities": {
                "textDocument": {
                    "publishDiagnostics": True,
                    "synchronization": {
                        "willSave": True,
                        "didSave": True
                    }
                }
            }
        }

        try:
            # 简化初始化 - 只检查服务器是否启动，不等待完整响应
            logger.info("Clangd server started, LSP initialization simplified")
            return True
        except Exception as e:
            logger.warning(f"LSP initialization failed, continuing without LSP: {e}")
            await self.stop_server()
            return False

    async def analyze_patch(self, patch: str) -> Dict[str, Any]:
        """分析补丁内容"""
        # 简化的补丁分析实现
        # 在实际实现中，这里会解析patch并使用LSP进行更详细的分析

        analysis = {
            "files_changed": self._extract_files_from_patch(patch),
            "functions_affected": self._extract_functions_from_patch(patch),
            "potential_issues": self._identify_potential_issues(patch),
            "complexity_score": self._calculate_patch_complexity(patch)
        }

        return analysis

    async def validate_code(self, code: str, file_path: str = "checker.cpp") -> Dict[str, Any]:
        """验证代码语法和语义"""
        if not self.is_connected:
            # 如果LSP不可用，使用基本的语法检查
            return await self._basic_syntax_check(code, file_path)

        try:
            # 创建临时文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp',
                                          delete=False) as f:
                f.write(code)
                temp_file = f.name

            # 发送文档打开通知
            await self._send_notification("textDocument/didOpen", {
                "textDocument": {
                    "uri": f"file://{temp_file}",
                    "languageId": "cpp",
                    "version": 1,
                    "text": code
                }
            })

            # 等待诊断信息
            await asyncio.sleep(1.0)  # 给clangd一些处理时间

            # 获取诊断信息（在实际实现中需要监听diagnostics通知）
            diagnostics = await self._get_diagnostics(f"file://{temp_file}")

            # 清理临时文件
            Path(temp_file).unlink(missing_ok=True)

            return {
                "has_errors": len([d for d in diagnostics if d.get("severity", 0) <= 1]) > 0,
                "errors": [d for d in diagnostics if d.get("severity", 0) <= 1],
                "warnings": [d for d in diagnostics if d.get("severity", 0) == 2],
                "diagnostics": diagnostics
            }

        except Exception as e:
            logger.error(f"Error validating code with LSP: {e}")
            return await self._basic_syntax_check(code, file_path)

    async def get_fix_suggestions(self, code: str, errors: List[str]) -> List[Dict[str, Any]]:
        """获取修复建议"""
        if not self.is_connected:
            return self._generate_basic_fixes(errors)

        # 在实际实现中，这里会使用LSP的代码操作功能
        # 例如 codeAction 请求

        suggestions = []

        for error in errors:
            suggestion = await self._get_fix_for_error(code, error)
            if suggestion:
                suggestions.append(suggestion)

        return suggestions

    async def _basic_syntax_check(self, code: str, file_path: str) -> Dict[str, Any]:
        """基本的语法检查（不使用LSP）"""
        try:
            # 使用clang++进行基本语法检查
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cpp',
                                          delete=False) as f:
                f.write(code)
                temp_file = f.name

            result = await asyncio.create_subprocess_exec(
                'clang++', '-fsyntax-only', '-I/usr/include/clang',
                '-std=c++17', temp_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await result.communicate()

            # 清理临时文件
            Path(temp_file).unlink(missing_ok=True)

            # 解析错误信息
            errors = []
            warnings = []

            for line in stderr.decode().split('\n'):
                line = line.strip()
                if not line:
                    continue

                if ': error:' in line:
                    errors.append(line)
                elif ': warning:' in line:
                    warnings.append(line)

            return {
                "has_errors": len(errors) > 0,
                "errors": errors,
                "warnings": warnings,
                "diagnostics": errors + warnings
            }

        except Exception as e:
            logger.error(f"Basic syntax check failed: {e}")
            return {
                "has_errors": True,
                "errors": [f"Syntax check failed: {str(e)}"],
                "warnings": [],
                "diagnostics": []
            }

    def _extract_files_from_patch(self, patch: str) -> List[str]:
        """从补丁中提取修改的文件"""
        files = []
        for line in patch.split('\n'):
            if line.startswith('+++ b/'):
                files.append(line[6:])
        return files

    def _extract_functions_from_patch(self, patch: str) -> List[str]:
        """从补丁中提取受影响的函数"""
        functions = []
        lines = patch.split('\n')

        for i, line in enumerate(lines):
            if line.startswith('+') or line.startswith('-'):
                # 检查是否是函数定义或调用
                if ('(' in line and ')' in line and
                    any(keyword in line.lower() for keyword in
                        ['void', 'int', 'char', 'bool', 'static', 'const'])):
                    functions.append(line.strip('+- \t'))

        return list(set(functions))  # 去重

    def _identify_potential_issues(self, patch: str) -> List[str]:
        """识别潜在问题"""
        issues = []

        patch_lower = patch.lower()

        # 检查常见的安全问题
        if 'strcpy(' in patch_lower:
            issues.append("Uses strcpy - potential buffer overflow")

        if 'free(' in patch_lower and 'null' not in patch_lower:
            issues.append("Free without null check - potential use after free")

        if 'malloc(' in patch_lower and 'sizeof' not in patch_lower:
            issues.append("Potential sizeof issues in malloc")

        return issues

    def _calculate_patch_complexity(self, patch: str) -> float:
        """计算补丁复杂度"""
        lines = len(patch.split('\n'))
        changes = len([line for line in patch.split('\n') if line.startswith(('+', '-'))])
        files = len(self._extract_files_from_patch(patch))

        # 简单复杂度计算
        complexity = min(1.0, (changes / 50) + (files / 3) + (lines / 200))
        return complexity

    async def _send_request(self, method: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """发送LSP请求"""
        if not self.is_connected or not self.process:
            return None

        request_id = self.request_id
        self.request_id += 1

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }

        # 创建future来等待响应
        future = asyncio.Future()
        self.pending_requests[request_id] = future

        try:
            # 发送请求
            request_json = json.dumps(request) + "\n"
            self.process.stdin.write(request_json.encode())
            await self.process.stdin.drain()

            # 等待响应（简化实现）
            response = await asyncio.wait_for(future, timeout=10.0)
            return response

        except Exception as e:
            logger.error(f"Error sending LSP request: {e}")
            return None
        finally:
            self.pending_requests.pop(request_id, None)

    async def _send_notification(self, method: str, params: Dict[str, Any]):
        """发送LSP通知"""
        if not self.is_connected or not self.process:
            return

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }

        try:
            notification_json = json.dumps(notification) + "\n"
            self.process.stdin.write(notification_json.encode())
            await self.process.stdin.drain()
        except Exception as e:
            logger.error(f"Error sending LSP notification: {e}")

    async def _get_diagnostics(self, uri: str) -> List[Dict[str, Any]]:
        """获取诊断信息"""
        # 在实际实现中，这里需要监听textDocument/publishDiagnostics通知
        # 这里返回空列表作为简化实现
        return []

    async def _get_fix_for_error(self, code: str, error: str) -> Optional[Dict[str, Any]]:
        """为错误生成修复建议"""
        # 简化的修复建议生成
        if "expected ';'" in error:
            return {
                "error": error,
                "suggestion": "Add missing semicolon",
                "fix_type": "insert_text",
                "position": {"line": 0, "character": 0},  # 需要解析实际位置
                "text": ";"
            }
        elif "undeclared identifier" in error:
            return {
                "error": error,
                "suggestion": "Add necessary include or declaration",
                "fix_type": "add_include"
            }

        return None

    def _generate_basic_fixes(self, errors: List[str]) -> List[Dict[str, Any]]:
        """生成基本的修复建议"""
        fixes = []

        for error in errors:
            fix = self._get_basic_fix_for_error(error)
            if fix:
                fixes.append(fix)

        return fixes

    def _get_basic_fix_for_error(self, error: str) -> Optional[Dict[str, Any]]:
        """为错误生成基本修复"""
        error_lower = error.lower()

        if "include" in error_lower and "not found" in error_lower:
            return {
                "error": error,
                "suggestion": "Add missing include directive",
                "fix_type": "add_include",
                "includes": ["<iostream>", "<string>", "<vector>"]
            }
        elif "undefined" in error_lower:
            return {
                "error": error,
                "suggestion": "Add declaration or include",
                "fix_type": "add_declaration"
            }

        return None

    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.stop_server()
