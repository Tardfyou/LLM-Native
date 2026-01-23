"""
LLM Client Base Classes
大语言模型客户端基础类 - 增强版

参考KNighter的model.py，提供:
- 6次重试机制
- 推理模型特殊处理
- ``标签移除
- 指数退避策略
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import logging
import re
import time

# 使用标准logging而不是loguru，以避免依赖问题
logger = logging.getLogger(__name__)


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


@dataclass
class LLMConfig:
    """LLM配置类 - 增强版，支持推理模型和更强重试机制"""
    model_name: str
    api_key: str
    base_url: str = "https://api.deepseek.com/v1"
    temperature: float = 0.7
    max_tokens: int = 2000
    timeout: int = 30
    max_retries: int = 6  # 增加到6次重试 (参考KNighter)
    top_p: float = 0.9
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    backoff_factor: float = 2.0  # 指数退避因子
    handle_think_tags: bool = True  # 处理``标签

    # 不支持temperature的推理模型列表
    REASONING_MODELS = ["o1", "o3-mini", "o4-mini", "o1-preview", "gpt-5"]

    def supports_temperature(self, model_name: str = None) -> bool:
        """检查模型是否支持temperature参数"""
        check_model = model_name or self.model_name
        return not any(reasoning_model in check_model for reasoning_model in self.REASONING_MODELS)


class LLMClient(ABC):
    """LLM客户端抽象基类"""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """生成文本"""
        pass

    @abstractmethod
    def generate_with_history(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """基于对话历史生成文本"""
        pass

    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """检查模型是否可用"""
        pass

    def _prepare_request_data(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """准备请求数据"""
        data = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "frequency_penalty": kwargs.get("frequency_penalty", self.config.frequency_penalty),
            "presence_penalty": kwargs.get("presence_penalty", self.config.presence_penalty),
        }

        # 添加可选参数
        if "stream" in kwargs:
            data["stream"] = kwargs["stream"]
        if "stop" in kwargs:
            data["stop"] = kwargs["stop"]

        return data

    def _handle_response(self, response_data: Dict[str, Any]) -> str:
        """处理API响应"""
        try:
            if "choices" in response_data and len(response_data["choices"]) > 0:
                choice = response_data["choices"][0]
                if "message" in choice and "content" in choice["message"]:
                    return choice["message"]["content"]
                elif "text" in choice:
                    return choice["text"]

            self.logger.error(f"Unexpected response format: {response_data}")
            return ""

        except Exception as e:
            self.logger.error(f"Error handling response: {e}")
            return ""
