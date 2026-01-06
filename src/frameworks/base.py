"""
Base Framework Classes
静态分析框架的抽象基类
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Optional

from loguru import logger


@dataclass
class FrameworkConfig:
    """框架配置类"""
    name: str
    version: str = "latest"
    language: str = "cpp"  # 支持的编程语言
    file_extensions: List[str] = None  # 支持的文件扩展名
    compiler_flags: List[str] = None  # 编译标志
    output_extension: str = ""  # 输出文件扩展名

    def __post_init__(self):
        if self.file_extensions is None:
            self.file_extensions = [".cpp", ".c", ".cc", ".cxx"]
        if self.compiler_flags is None:
            self.compiler_flags = []


@dataclass
class CompilationResult:
    """编译结果"""
    success: bool
    output_file: Optional[Path] = None
    error_message: Optional[str] = None
    warnings: List[str] = None
    compilation_time: float = 0.0

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


@dataclass
class ValidationResult:
    """验证结果"""
    success: bool
    compilation_success: bool = False
    semantic_checks: Dict[str, Any] = None
    performance_metrics: Dict[str, Any] = None
    error_message: Optional[str] = None

    def __post_init__(self):
        if self.semantic_checks is None:
            self.semantic_checks = {}
        if self.performance_metrics is None:
            self.performance_metrics = {}


class Framework(ABC):
    """静态分析框架基类"""

    def __init__(self, config: FrameworkConfig):
        """
        初始化框架

        Args:
            config: 框架配置
        """
        self.config = config
        self.logger = logger.bind(framework=config.name)

    @property
    @abstractmethod
    def name(self) -> str:
        """框架名称"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """框架描述"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        检查框架是否可用

        Returns:
            框架是否可用
        """
        pass

    @abstractmethod
    def compile_detector(self, source_code: str, output_dir: Path) -> CompilationResult:
        """
        编译检测器代码

        Args:
            source_code: 检测器源代码
            output_dir: 输出目录

        Returns:
            编译结果
        """
        pass

    @abstractmethod
    def validate_detector(self, detector_path: Path, test_cases_dir: Optional[Path] = None) -> ValidationResult:
        """
        验证检测器

        Args:
            detector_path: 检测器文件路径
            test_cases_dir: 测试用例目录

        Returns:
            验证结果
        """
        pass

    @abstractmethod
    def get_template_prompts(self) -> Dict[str, str]:
        """
        获取框架特定的提示模板

        Returns:
            提示模板字典
        """
        pass

    def get_supported_vulnerabilities(self) -> List[str]:
        """
        获取支持的漏洞类型

        Returns:
            支持的漏洞类型列表
        """
        return [
            "buffer_overflow",
            "use_after_free",
            "null_pointer_dereference",
            "integer_overflow",
            "format_string",
            "command_injection",
            "sql_injection",
            "xss"
        ]

    def get_file_extension(self) -> str:
        """
        获取输出文件扩展名

        Returns:
            文件扩展名
        """
        return self.config.output_extension

    def supports_language(self, language: str) -> bool:
        """
        检查是否支持指定语言

        Args:
            language: 编程语言

        Returns:
            是否支持
        """
        return language.lower() == self.config.language.lower()

    def get_info(self) -> Dict[str, Any]:
        """
        获取框架信息

        Returns:
            框架信息字典
        """
        return {
            "name": self.name,
            "description": self.description,
            "version": self.config.version,
            "language": self.config.language,
            "file_extensions": self.config.file_extensions,
            "available": self.is_available(),
            "supported_vulnerabilities": self.get_supported_vulnerabilities()
        }
