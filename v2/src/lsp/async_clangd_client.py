"""
异步Clangd LSP客户端 - 完整LSP协议支持

提供:
- 异步通信
- 诊断通知监听
- 事件驱动等待机制
- 增量文档更新
"""

import asyncio
import json
import os
import tempfile
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from loguru import logger

from .clangd_client import ClangdClient as SyncClangdClient


class Severity(Enum):
    """诊断严重程度"""
    ERROR = 1
    WARNING = 2
    INFO = 3
    HINT = 4


@dataclass
class Diagnostic:
    """诊断信息"""
    file_path: str
    line: int
    column: int
    severity: str  # "error", "warning", "info", "hint")
    message: str
    source: str = "clangd"
    code: Optional[str] = None
    related_info: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "severity": self.severity,
            "message": self.message,
            "source": self.source,
            "code": self.code,
            "related_info": self.related_info
        }




@dataclass
class TextEdit:
    """文本编辑"""
    start_line: int
    start_char: int
    end_line: int
    end_char: int
    new_text: str


class AsyncClangdClient:
    """异步Clangd LSP客户端"""

    def __init__(self, config: Dict[str, Any]):
        """
        初始化

        Args:
            config: LSP配置
                - clangd_path: clangd可执行文件路径
                - timeout_seconds: 请求超时时间
                - diagnostic_timeout: 诊断等待超时
                - llvm_dir: LLVM安装目录
                - compile_flags: 额外的编译选项
        """
        self.config = config
        self.clangd_path = config.get("clangd_path", "/usr/lib/llvm-18/bin/clangd")
        self.timeout = config.get("timeout_seconds", 30)
        self.diagnostic_timeout = config.get("diagnostic_timeout", 5.0)
        self.llvm_dir = config.get("llvm_dir", "/usr/lib/llvm-18")
        self.temp_dir = config.get("temp_dir")
        self.compile_db_dir = config.get("compile_db_dir")

        self.compile_flags = config.get("compile_flags", self._get_default_compile_flags())

        # 固定的编译数据库目录
        if self.compile_db_dir:
            self._compile_db_dir = self.compile_db_dir
            os.makedirs(self._compile_db_dir, exist_ok=True)
        else:
            self._compile_db_dir = tempfile.mkdtemp(prefix="clangd_compile_db_", dir=self.temp_dir)
        self._ensure_compile_db()

        # 进程和通信
        self.process: Optional[asyncio.subprocess.Process] = None
        self.request_id = 0
        self.pending_requests: Dict[int, asyncio.Future] = {}

        # 诊断队列
        self.diagnostics_queue: asyncio.Queue = asyncio.Queue()
        self._diagnostic_events: Dict[str, asyncio.Event] = {}

        # 后台任务
        self._reader_task: Optional[asyncio.Task] = None
        self._initialized = False

        # 项目根目录
        self._root_uri: Optional[str] = None

        # 通知回调
        self._on_diagnostics_callback: Optional[Callable[[Dict], None]] = None

        # 同步客户端作为兜底实现
        self._sync_client = SyncClangdClient(config)

    def set_work_dir(self, work_dir: str):
        """设置工作目录，约束 compile_commands 与同步兜底临时文件。"""
        if not work_dir:
            return

        lsp_root = os.path.join(work_dir, ".lsp_tmp")
        os.makedirs(lsp_root, exist_ok=True)
        self.temp_dir = lsp_root
        self._compile_db_dir = os.path.join(lsp_root, "compile_db")
        os.makedirs(self._compile_db_dir, exist_ok=True)
        self._ensure_compile_db()

        if hasattr(self._sync_client, "set_work_dir"):
            self._sync_client.set_work_dir(work_dir)

    def _get_default_compile_flags(self) -> List[str]:
        """获取默认的编译选项，包含Clang头文件路径"""
        flags = [
            "-std=c++20",
            "-O0",
            "-g",
        ]

        # 添加LLVM/Clang头文件路径
        llvm_include = os.path.join(self.llvm_dir, "include")
        if os.path.exists(llvm_include):
            flags.append(f"-I{llvm_include}")

        # 添加常见的Clang头文件位置
        possible_includes = [
            "/usr/lib/llvm-18/include",
            "/usr/include/llvm-18",
            "/usr/local/include/llvm-18",
            "/usr/lib/llvm-18/lib/clang/18/include",
        ]

        for inc_path in possible_includes:
            if os.path.exists(inc_path) and f"-I{inc_path}" not in flags:
                flags.append(f"-I{inc_path}")

        return flags

    def _ensure_compile_db(self):
        """确保编译数据库目录存在并包含 compile_commands.json"""
        os.makedirs(self._compile_db_dir, exist_ok=True)

        # 创建空的 compile_commands.json
        cc_json_path = os.path.join(self._compile_db_dir, "compile_commands.json")
        if not os.path.exists(cc_json_path):
            with open(cc_json_path, 'w', encoding='utf-8') as f:
                json.dump([], f)

    async def start(self, compile_commands_dir: str = None) -> bool:
        """
        启动clangd进程

        Args:
            compile_commands_dir: compile_commands.json 所在目录

        Returns:
            是否启动成功
        """
        if self.process is not None:
            return True

        try:
            logger.info(f"启动clangd: {self.clangd_path}")

            # 确保编译数据库目录存在
            db_dir = compile_commands_dir or self._compile_db_dir
            os.makedirs(db_dir, exist_ok=True)

            # 构建命令行参数
            args = [
                "--header-insertion=never",
                "--background-index",
                "--clang-tidy",
                f"--compile-commands-dir={db_dir}",
            ]

            # 启动进程
            self.process = await asyncio.create_subprocess_exec(
                self.clangd_path,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # 启动后台读取任务
            self._reader_task = asyncio.create_task(self._read_loop())

            logger.info(f"clangd进程已启动, compile-commands-dir={db_dir}")
            return True

        except FileNotFoundError:
            logger.error(f"clangd未找到: {self.clangd_path}")
            return False
        except Exception as e:
            logger.error(f"clangd启动失败: {e}")
            return False

    async def initialize(self) -> bool:
        """初始化客户端（异步）"""
        if self.is_available():
            return True

        try:
            # 使用同步客户端兜底初始化
            started = await asyncio.to_thread(self._sync_client.start)
            self._initialized = bool(started)
            return self._initialized
        except Exception as e:
            logger.error(f"clangd初始化失败: {e}")
            return False

    async def check_code(self, code: str, file_name: str = "checker.cpp") -> List[Diagnostic]:
        """异步检查代码（使用同步客户端兜底）"""
        if not self.is_available():
            await self.initialize()

        try:
            sync_diagnostics = await asyncio.to_thread(self._sync_client.check_code, code, file_name)
        except Exception as e:
            logger.error(f"clangd检查失败: {e}")
            return []

        diagnostics: List[Diagnostic] = []
        for d in sync_diagnostics:
            diagnostics.append(
                Diagnostic(
                    file_path=getattr(d, "file_path", file_name),
                    line=getattr(d, "line", 0),
                    column=getattr(d, "column", 0),
                    severity=getattr(d, "severity", "info"),
                    message=getattr(d, "message", ""),
                    source=getattr(d, "source", "clangd"),
                )
            )

        return diagnostics

    def is_available(self) -> bool:
        """检查clangd是否可用"""
        return self._initialized or self._sync_client.is_available()


# 全局客户端实例
_async_clangd_client: Optional[AsyncClangdClient] = None


def get_async_clangd_client(config: Optional[Dict[str, Any]] = None) -> AsyncClangdClient:
    """获取异步clangd客户端实例"""
    global _async_clangd_client

    if _async_clangd_client is None:
        if config is None:
            config = {}
        _async_clangd_client = AsyncClangdClient(config)

    return _async_clangd_client
