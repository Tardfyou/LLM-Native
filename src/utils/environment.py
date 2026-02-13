"""
Environment Configuration Module
环境配置模块 - 简化版，专注于宿主机运行

功能:
- 自动检测项目根目录
- 配置 ChromaDB 连接
- 设置路径
"""

import os
import socket
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


def get_project_root() -> Path:
    """
    获取项目根目录

    优先级:
    1. 环境变量 LLM_NATIVE_ROOT
    2. 从当前文件向上查找包含 config/config.yaml 的目录

    Returns:
        Path: 项目根目录
    """
    # 检查环境变量
    env_root = os.environ.get("LLM_NATIVE_ROOT")
    if env_root:
        return Path(env_root)

    # 从当前文件位置向上查找项目根
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "config" / "config.yaml").exists():
            return parent
        if (parent / "LLM-Native" / "config" / "config.yaml").exists():
            return parent / "LLM-Native"

    # 回退到默认位置 (src/utils -> LLM-Native)
    return current.parent.parent.parent


def check_chroma_server(host: str = "localhost", port: int = 8001, timeout: float = 2.0) -> bool:
    """
    检查 ChromaDB 服务器是否可访问

    Args:
        host: 主机名
        port: 端口号
        timeout: 超时时间（秒）

    Returns:
        bool: True 如果可以连接
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


class PathConfig:
    """路径配置类"""

    def __init__(self, project_root: Optional[Path] = None):
        if project_root:
            self.project_root = Path(project_root)
        else:
            self.project_root = get_project_root()

        self._setup_paths()
        logger.info(f"PathConfig initialized: root={self.project_root}")

    def _setup_paths(self):
        """设置所有路径"""
        self.src_dir = self.project_root / "src"
        self.data_dir = self.project_root / "data"
        self.config_dir = self.project_root / "config"
        self.results_dir = self.project_root / "results"
        self.logs_dir = self.project_root / "logs"

        self.knowledge_dir = self.data_dir / "knowledge"
        self.benchmarks_dir = self.data_dir / "benchmarks"
        self.vector_cache_dir = self.knowledge_dir / "vector_cache"
        self.pretrained_models_dir = self.project_root / "pretrained_models"
        self.prompt_templates_dir = self.project_root / "prompt_templates"

        # 确保目录存在
        for dir_path in [
            self.data_dir, self.results_dir, self.logs_dir,
            self.knowledge_dir, self.benchmarks_dir, self.vector_cache_dir
        ]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def get_config_dict(self) -> Dict[str, str]:
        """获取路径配置字典"""
        return {
            "root_dir": str(self.project_root),
            "src_dir": str(self.src_dir),
            "data_dir": str(self.data_dir),
            "results_dir": str(self.results_dir),
            "logs_dir": str(self.logs_dir),
            "knowledge_dir": str(self.knowledge_dir),
            "benchmarks_dir": str(self.benchmarks_dir),
            "config_dir": str(self.config_dir),
            "prompt_templates_dir": str(self.prompt_templates_dir),
        }


class ChromaDBConfig:
    """ChromaDB 配置类"""

    DEFAULT_PORT = 8001

    def __init__(self, path_config: PathConfig, config: Optional[Dict[str, Any]] = None):
        self.path_config = path_config
        self.original_config = config or {}

        vector_db_config = self.original_config.get("knowledge_base", {}).get("vector_db", {})
        self.collection_name = vector_db_config.get("collection", "llm_native_knowledge")
        self.persist_directory = str(path_config.vector_cache_dir)

        # 从环境变量或配置读取
        self.host = os.environ.get("CHROMA_HOST") or vector_db_config.get("host", "localhost")
        self.port = int(os.environ.get("CHROMA_PORT") or vector_db_config.get("port", self.DEFAULT_PORT))

        # 检测模式
        self._detect_mode()

        if self.mode == "remote":
            logger.info(f"ChromaDB: remote mode at {self.host}:{self.port}")
        else:
            logger.info(f"ChromaDB: local mode at {self.persist_directory}")

    def _detect_mode(self):
        """检测 ChromaDB 运行模式"""
        # 优先使用环境变量
        if os.environ.get("CHROMA_HOST"):
            if check_chroma_server(self.host, self.port):
                self.mode = "remote"
            else:
                logger.warning(f"ChromaDB server not available at {self.host}:{self.port}, using local mode")
                self.mode = "local"
            return

        # 自动检测
        if check_chroma_server(self.host, self.port):
            self.mode = "remote"
        else:
            self.mode = "local"

    def is_remote(self) -> bool:
        return self.mode == "remote"

    def is_local(self) -> bool:
        return self.mode == "local"

    def get_client_config(self) -> Dict[str, Any]:
        if self.mode == "remote":
            return {
                "mode": "remote",
                "host": self.host,
                "port": self.port,
                "collection": self.collection_name,
            }
        else:
            return {
                "mode": "local",
                "persist_directory": self.persist_directory,
                "collection": self.collection_name,
            }


def get_environment_config(config: Optional[Dict[str, Any]] = None) -> Tuple[PathConfig, ChromaDBConfig]:
    """获取环境配置"""
    path_config = PathConfig()
    chroma_config = ChromaDBConfig(path_config, config)
    return path_config, chroma_config


def update_config_with_environment(config: Dict[str, Any]) -> Dict[str, Any]:
    """使用环境配置更新配置"""
    path_config, chroma_config = get_environment_config(config)

    # 更新路径配置
    if "paths" not in config:
        config["paths"] = {}
    config["paths"].update(path_config.get_config_dict())

    # 更新 knowledge_base 配置
    if "knowledge_base" not in config:
        config["knowledge_base"] = {}
    if "vector_db" not in config["knowledge_base"]:
        config["knowledge_base"]["vector_db"] = {}

    vector_db = config["knowledge_base"]["vector_db"]
    vector_db["persist_directory"] = chroma_config.persist_directory
    vector_db["mode"] = chroma_config.mode

    if chroma_config.is_remote():
        vector_db["host"] = chroma_config.host
        vector_db["port"] = chroma_config.port

    # 更新日志配置
    if "logging" not in config:
        config["logging"] = {}
    config["logging"]["file"] = str(path_config.logs_dir / "llm_native.log")

    return config


def print_environment_info():
    """打印环境信息"""
    print("\n" + "=" * 50)
    print("LLM-Native 环境信息")
    print("=" * 50)

    path_config = PathConfig()
    print(f"项目根目录: {path_config.project_root}")
    print(f"数据目录: {path_config.data_dir}")
    print(f"结果目录: {path_config.results_dir}")
    print(f"日志目录: {path_config.logs_dir}")

    chroma_config = ChromaDBConfig(path_config)
    print(f"\nChromaDB 模式: {chroma_config.mode}")
    if chroma_config.is_remote():
        print(f"ChromaDB 地址: {chroma_config.host}:{chroma_config.port}")
    else:
        print(f"ChromaDB 路径: {chroma_config.persist_directory}")

    print("=" * 50 + "\n")


if __name__ == "__main__":
    print_environment_info()
