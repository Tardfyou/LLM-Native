"""
Clangd LSP客户端 - 实时代码检查

提供:
- 代码诊断
- 补全支持
- 语法检查
"""

import asyncio
import json
import os
import subprocess
import tempfile
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class Diagnostic:
    """诊断信息"""
    file_path: str
    line: int
    column: int
    severity: str  # "error", "warning", "info"
    message: str
    source: str = "clangd"


class ClangdClient:
    """Clangd LSP客户端"""

    def __init__(self, config: Dict[str, Any]):
        """
        初始化Clangd客户端

        Args:
            config: LSP配置
        """
        self.config = config
        self.clangd_path = config.get("clangd_path", "/usr/lib/llvm-18/bin/clangd")
        self.timeout = config.get("timeout_seconds", 30)
        self.temp_dir = config.get("temp_dir")

        self.process = None
        self.request_id = 0
        self._initialized = False

    def set_work_dir(self, work_dir: str):
        """设置工作目录，用于放置临时源码文件。"""
        if work_dir:
            self.temp_dir = os.path.join(work_dir, ".lsp_tmp")
            os.makedirs(self.temp_dir, exist_ok=True)

    def start(self) -> bool:
        """
        启动clangd进程

        Returns:
            是否启动成功
        """
        if self.process is not None:
            return True

        try:
            logger.info(f"启动clangd: {self.clangd_path}")

            self.process = subprocess.Popen(
                [self.clangd_path, "--header-insertion=never", "--background-index"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # 初始化LSP
            self._initialize()
            self._initialized = True

            logger.info("clangd启动成功")
            return True

        except FileNotFoundError:
            logger.error(f"clangd未找到: {self.clangd_path}")
            return False
        except Exception as e:
            logger.error(f"clangd启动失败: {e}")
            return False

    def stop(self):
        """停止clangd进程"""
        if self.process:
            try:
                self._send_request("shutdown", {})
                self._send_notification("exit", {})
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            finally:
                self.process = None
                self._initialized = False
                logger.info("clangd已停止")

    def _send_request(self, method: str, params: Dict) -> Optional[Dict]:
        """发送LSP请求"""
        if not self.process:
            return None

        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }

        return self._send_message(request)

    def _send_notification(self, method: str, params: Dict):
        """发送LSP通知(不需要响应)"""
        if not self.process:
            return

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }

        self._send_message(notification, expect_response=False)

    def _send_message(self, message: Dict, expect_response: bool = True) -> Optional[Dict]:
        """发送消息到clangd"""
        content = json.dumps(message)
        header = f"Content-Length: {len(content)}\r\n\r\n"

        try:
            self.process.stdin.write(header + content)
            self.process.stdin.flush()

            if not expect_response:
                return None

            # 读取响应
            return self._read_response()

        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return None

    def _read_response(self) -> Optional[Dict]:
        """读取LSP响应"""
        try:
            # 读取header
            headers = {}
            while True:
                line = self.process.stdout.readline().strip()
                if not line:
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()

            # 读取content
            content_length = int(headers.get("Content-Length", 0))
            if content_length > 0:
                content = self.process.stdout.read(content_length)
                return json.loads(content)

        except Exception as e:
            logger.error(f"读取响应失败: {e}")

        return None

    def _initialize(self) -> bool:
        """初始化LSP连接"""
        init_params = {
            "processId": os.getpid(),
            "rootUri": None,
            "capabilities": {
                "textDocument": {
                    "publishDiagnostics": {
                        "relatedInformation": True
                    }
                }
            }
        }

        response = self._send_request("initialize", init_params)
        if response and "result" in response:
            self._send_notification("initialized", {})
            return True

        return False

    def check_file(self, file_path: str, content: str = None) -> List[Diagnostic]:
        """
        检查文件

        Args:
            file_path: 文件路径
            content: 文件内容(可选，不提供则读取文件)

        Returns:
            诊断信息列表
        """
        if not self._initialized and not self.start():
            return []

        # 如果未提供内容，读取文件
        if content is None:
            if not os.path.exists(file_path):
                logger.error(f"文件不存在: {file_path}")
                return []
            with open(file_path, 'r') as f:
                content = f.read()

        # 转换为URI
        uri = Path(file_path).absolute().as_uri()

        # 通知文件打开
        self._send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": uri,
                "languageId": "cpp",
                "version": 1,
                "text": content
            }
        })

        # 等待诊断(简单实现)
        import time
        time.sleep(2)

        # 获取诊断 - 通过documentDiagnostic请求
        diagnostics = []

        response = self._send_request("textDocument/diagnostic", {
            "textDocument": {"uri": uri}
        })

        if response and "result" in response:
            result = response["result"]
            if "items" in result:
                for item in result["items"]:
                    diag = Diagnostic(
                        file_path=file_path,
                        line=item.get("range", {}).get("start", {}).get("line", 0) + 1,
                        column=item.get("range", {}).get("start", {}).get("character", 0) + 1,
                        severity=self._map_severity(item.get("severity", 1)),
                        message=item.get("message", ""),
                        source="clangd"
                    )
                    diagnostics.append(diag)

        # 关闭文件
        self._send_notification("textDocument/didClose", {
            "textDocument": {"uri": uri}
        })

        return diagnostics

    def check_code(self, code: str, file_name: str = "temp.cpp") -> List[Diagnostic]:
        """
        检查代码

        Args:
            code: 代码内容
            file_name: 临时文件名

        Returns:
            诊断信息列表
        """
        # 创建临时文件
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.cpp',
            prefix=file_name.replace('.cpp', ''),
            dir=self.temp_dir,
            delete=False
        ) as f:
            f.write(code)
            temp_path = f.name

        try:
            return self.check_file(temp_path, code)
        finally:
            os.unlink(temp_path)

    def _map_severity(self, severity: int) -> str:
        """映射诊断严重程度"""
        mapping = {
            1: "error",
            2: "warning",
            3: "info",
            4: "hint"
        }
        return mapping.get(severity, "info")

    def is_available(self) -> bool:
        """检查clangd是否可用"""
        return self._initialized


# 全局客户端实例
_clangd_client: Optional[ClangdClient] = None


def get_clangd_client(config: Optional[Dict[str, Any]] = None) -> ClangdClient:
    """获取clangd客户端实例"""
    global _clangd_client

    if _clangd_client is None:
        if config is None:
            config = {}
        _clangd_client = ClangdClient(config)

    return _clangd_client
