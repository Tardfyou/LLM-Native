"""
生成引擎数据模型
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

@dataclass
class GenerationInput:
    """生成引擎输入"""

    # 核心输入 (至少需要一个输入源)
    patch: Optional[str] = None                  # 补丁内容 (传统方式)
    vulnerability_description: Optional[str] = None  # 漏洞描述 (0day支持)
    poc_code: Optional[str] = None               # PoC代码 (0day支持)
    vulnerability_type: Optional[str] = None      # 漏洞类型: buffer_overflow, use_after_free等 (可选，0day可为None)
    framework: str = "clang"                      # 目标框架: clang

    # 可选增强输入
    code_context: Optional[str] = None           # 相关代码片段
    cwe_id: Optional[str] = None                 # CWE编号
    language: str = "cpp"                        # 目标语言

    # 配置参数
    enable_rag: bool = True                      # 启用RAG
    enable_multi_agent: bool = True              # 启用多专家
    max_iterations: int = 3                      # 最大修复迭代次数

    # 验证配置
    test_cases: List[Dict] = field(default_factory=list)  # 测试样例

    def __post_init__(self):
        """验证至少提供了一种输入方式"""
        if not any([self.patch, self.vulnerability_description, self.poc_code]):
            raise ValueError("必须提供至少一种输入: patch（补丁）、vulnerability_description（漏洞描述）或poc_code（PoC代码）")

@dataclass
class ValidationResult:
    """验证结果"""

    success: bool = False                        # 是否验证成功
    compilation_success: bool = False           # 编译是否成功
    functional_tests: List[Dict] = field(default_factory=list)  # 功能测试结果
    errors: List[str] = field(default_factory=list)  # 错误信息
    warnings: List[str] = field(default_factory=list)  # 警告信息
    quality_score: float = 0.0                  # 质量评分
    execution_time: float = 0.0                 # 执行时间

@dataclass
class DetectionPlan:
    """检测计划"""

    vulnerability_pattern: str                   # 漏洞模式描述
    detection_strategy: str                      # 检测策略
    required_apis: List[str] = field(default_factory=list)  # 需要的API
    code_structure: Dict[str, Any] = field(default_factory=dict)  # 代码结构
    validation_rules: List[str] = field(default_factory=list)  # 验证规则

@dataclass
class GenerationState:
    """生成状态管理"""

    input_data: GenerationInput                  # 输入数据
    current_stage: str = "initialized"          # 当前阶段
    vulnerability_pattern: Optional[str] = None # 提取的漏洞模式
    detection_plan: Optional[DetectionPlan] = None  # 检测计划
    generated_code: Optional[str] = None        # 生成的代码
    validation_results: List[ValidationResult] = field(default_factory=list)  # 验证结果
    agent_messages: List[Dict] = field(default_factory=list)  # Agent消息历史
    confidence_score: float = 0.0               # 置信度评分
    iteration_count: int = 0                    # 迭代次数
    start_time: datetime = field(default_factory=datetime.now)
    last_update: datetime = field(default_factory=datetime.now)

    def update_stage(self, new_stage: str):
        """更新阶段"""
        self.current_stage = new_stage
        self.last_update = datetime.now()

    def add_validation_result(self, result: ValidationResult):
        """添加验证结果"""
        self.validation_results.append(result)
        self.last_update = datetime.now()

    def get_elapsed_time(self) -> float:
        """获取已用时间"""
        return (datetime.now() - self.start_time).total_seconds()

@dataclass
class GenerationOutput:
    """生成引擎输出"""

    # 核心输出
    checker_code: str                           # 生成的C++ checker代码
    success: bool                               # 是否成功生成

    # 过程追踪
    pattern: str                                # 提取的漏洞模式
    plan: DetectionPlan                         # 生成的检测计划
    intermediate_codes: List[str] = field(default_factory=list)  # 中间版本

    # 验证结果
    final_validation: ValidationResult = field(default_factory=lambda: ValidationResult())

    # 质量指标
    confidence_score: float = 0.0              # 置信度 (0-1)
    quality_metrics: Dict = field(default_factory=dict)  # 详细指标

    # 元数据
    generation_time: float = 0.0               # 生成耗时(秒)
    iterations_used: int = 0                   # 使用的迭代次数
    rag_queries_used: int = 0                  # RAG查询次数
    prompt_versions: List[str] = field(default_factory=list)  # 提示词版本

    # 状态追踪
    generation_trace: List[Dict] = field(default_factory=list)  # 生成过程追踪
