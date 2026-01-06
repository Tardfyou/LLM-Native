"""
LLM Client Base Interface
大语言模型客户端的基础接口和抽象类
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from loguru import logger


@dataclass
class LLMConfig:
    """LLM配置类"""
    api_key: str
    base_url: Optional[str] = None
    model_name: str = "deepseek-chat"
    temperature: float = 0.1
    max_tokens: int = 4096
    top_p: float = 0.9
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    timeout: int = 60
    max_retries: int = 3


@dataclass
class LLMResponse:
    """LLM响应类"""
    success: bool
    content: str
    raw_response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    usage: Optional[Dict[str, int]] = None
    finish_reason: Optional[str] = None


class LLMClient(ABC):
    """大语言模型客户端基类"""

    def __init__(self, config: LLMConfig):
        """
        初始化LLM客户端

        Args:
            config: LLM配置
        """
        self.config = config
        self._validate_config()

    def _validate_config(self):
        """验证配置"""
        if not self.config.api_key:
            raise ValueError("API key is required")

        if self.config.max_tokens <= 0:
            raise ValueError("max_tokens must be positive")

        if not (0 <= self.config.temperature <= 2):
            raise ValueError("temperature must be between 0 and 2")

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        生成文本

        Args:
            prompt: 输入提示
            **kwargs: 额外参数

        Returns:
            LLMResponse: 生成结果
        """
        pass

    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        pass

    def estimate_tokens(self, text: str) -> int:
        """
        估算文本的token数量

        Args:
            text: 输入文本

        Returns:
            估算的token数量
        """
        # 简单的估算：1个中文字符≈1.5个token，1个英文单词≈1.3个token
        chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        english_words = len(text.split()) - chinese_chars  # 粗略估算

        return int(chinese_chars * 1.5 + english_words * 1.3)

    def is_available(self) -> bool:
        """
        检查服务是否可用

        Returns:
            服务是否可用
        """
        try:
            # 发送一个简单的测试请求
            response = self.generate("Hello", max_tokens=10)
            return response.success
        except Exception as e:
            logger.error(f"LLM service availability check failed: {e}")
            return False

    def get_usage_stats(self) -> Dict[str, Any]:
        """
        获取使用统计信息

        Returns:
            使用统计
        """
        return {
            "model_name": self.config.model_name,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "is_available": self.is_available()
        }


class MockLLMClient(LLMClient):
    """Mock LLM客户端，用于测试"""

    def __init__(self, config: Optional[LLMConfig] = None):
        if config is None:
            config = LLMConfig(api_key="mock-key", model_name="mock-model")
        super().__init__(config)

    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """生成模拟响应"""
        logger.info(f"Mock LLM generating response for prompt: {prompt[:50]}...")

        # 模拟不同的响应类型
        if "codeql" in prompt.lower():
            mock_content = self._generate_mock_codeql_response()
        else:
            mock_content = f"Mock response for: {prompt[:100]}..."

        return LLMResponse(
            success=True,
            content=mock_content,
            usage={"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300}
        )

    def _generate_mock_codeql_response(self) -> str:
        """生成模拟的CodeQL查询"""
        return '''
/**
 * @name Mock vulnerability detector
 * @description Detects mock vulnerabilities
 * @kind path-problem
 * @problem.severity error
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

predicate isSource(DataFlow::Node source) {
  // Mock source definition
  exists(FunctionCall fc |
    fc.getTarget().getName() = "mock_source" and
    source.asExpr() = fc
  )
}

predicate isSink(DataFlow::Node sink) {
  // Mock sink definition
  exists(FunctionCall fc |
    fc.getTarget().getName() = "mock_sink" and
    sink.asExpr() = fc.getArgument(0)
  )
}

predicate isSanitizer(DataFlow::Node node) {
  // Mock sanitizer
  exists(FunctionCall fc |
    fc.getTarget().getName() = "mock_sanitize" and
    node.asExpr() = fc.getArgument(0)
  )
}

module MockConfig implements DataFlow::ConfigSig {
  predicate isSource = isSource/1;
  predicate isSink = isSink/1;
  predicate isBarrier = isSanitizer/1;
}

module MockFlow = DataFlow::Global<MockConfig>;

from MockFlow::PathNode source, MockFlow::PathNode sink
where MockFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Mock vulnerability detected"
'''

    def get_model_info(self) -> Dict[str, Any]:
        return {
            "model_name": "mock-model",
            "provider": "mock",
            "context_length": 4096,
            "description": "Mock LLM for testing"
        }
