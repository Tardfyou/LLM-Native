"""
LLM Client Base Classes
大语言模型客户端基础类
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import logging

# 使用标准logging而不是loguru，以避免依赖问题
logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """LLM配置类"""
    model_name: str
    api_key: str
    base_url: str = "https://api.deepseek.com/v1"
    temperature: float = 0.7
    max_tokens: int = 2000
    timeout: int = 30
    max_retries: int = 3
    top_p: float = 0.9
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0


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
