"""
DeepSeek LLM Client
支持DeepSeek API的客户端实现
"""

import json
import time
from typing import Dict, Any, Optional

import requests
from loguru import logger

from .llm_client import LLMClient, LLMConfig, LLMResponse


class DeepSeekClient(LLMClient):
    """DeepSeek LLM客户端"""

    # DeepSeek API endpoints
    BASE_URL = "https://api.deepseek.com/v1"

    # 支持的模型列表
    SUPPORTED_MODELS = [
        "deepseek-chat",
        "deepseek-coder",
        "deepseek-chat-67b",
        "deepseek-coder-33b",
        "deepseek-coder-6.7b",
        "deepseek-chat-7b"
    ]

    def __init__(self, config: LLMConfig):
        """
        初始化DeepSeek客户端

        Args:
            config: LLM配置
        """
        super().__init__(config)

        # 验证模型名称
        if config.model_name not in self.SUPPORTED_MODELS:
            logger.warning(f"Model {config.model_name} not in supported list: {self.SUPPORTED_MODELS}")
            logger.info(f"Using default model: deepseek-chat")
            config.model_name = "deepseek-chat"

        # 设置请求头
        self.headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json"
        }

        # 设置基础URL
        self.base_url = config.base_url or self.BASE_URL

        logger.info(f"Initialized DeepSeek client with model: {config.model_name}")

    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        生成文本

        Args:
            prompt: 输入提示
            **kwargs: 额外参数

        Returns:
            LLMResponse: 生成结果
        """
        try:
            # 构建请求数据
            request_data = self._build_request_data(prompt, **kwargs)

            # 发送请求
            response = self._make_request(request_data)

            if response.success:
                # 解析响应
                return self._parse_response(response.data)
            else:
                return LLMResponse(
                    success=False,
                    content="",
                    error=response.error
                )

        except Exception as e:
            logger.error(f"Error in DeepSeek generation: {e}")
            return LLMResponse(
                success=False,
                content="",
                error=f"Generation failed: {str(e)}"
            )

    def _build_request_data(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """构建API请求数据"""
        data = {
            "model": self.config.model_name,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "frequency_penalty": kwargs.get("frequency_penalty", self.config.frequency_penalty),
            "presence_penalty": kwargs.get("presence_penalty", self.config.presence_penalty),
            "stream": False  # 不使用流式响应
        }

        # 处理额外参数
        if "system_message" in kwargs:
            data["messages"].insert(0, {
                "role": "system",
                "content": kwargs["system_message"]
            })

        return data

    def _make_request(self, request_data: Dict[str, Any]) -> 'APIResponse':
        """发送API请求"""
        url = f"{self.base_url}/chat/completions"

        for attempt in range(self.config.max_retries):
            try:
                logger.debug(f"Making DeepSeek API request (attempt {attempt + 1})")

                response = requests.post(
                    url,
                    headers=self.headers,
                    json=request_data,
                    timeout=self.config.timeout
                )

                if response.status_code == 200:
                    return APIResponse(success=True, data=response.json())
                elif response.status_code == 429:
                    # Rate limit exceeded
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.warning(f"Rate limit exceeded, waiting {wait_time}s")
                    time.sleep(wait_time)
                    continue
                else:
                    error_msg = f"API request failed with status {response.status_code}: {response.text}"
                    logger.error(error_msg)
                    return APIResponse(success=False, error=error_msg)

            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout (attempt {attempt + 1})")
                if attempt < self.config.max_retries - 1:
                    time.sleep(1)
                    continue
                return APIResponse(success=False, error="Request timeout")

            except requests.exceptions.RequestException as e:
                error_msg = f"Request error: {str(e)}"
                logger.error(error_msg)
                return APIResponse(success=False, error=error_msg)

        return APIResponse(success=False, error="Max retries exceeded")

    def _parse_response(self, response_data: Dict[str, Any]) -> LLMResponse:
        """解析API响应"""
        try:
            choices = response_data.get("choices", [])
            if not choices:
                return LLMResponse(
                    success=False,
                    content="",
                    error="No choices in response",
                    raw_response=response_data
                )

            choice = choices[0]
            message = choice.get("message", {})
            content = message.get("content", "")

            # 提取使用统计
            usage = response_data.get("usage", {})

            return LLMResponse(
                success=True,
                content=content,
                raw_response=response_data,
                usage={
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0)
                },
                finish_reason=choice.get("finish_reason")
            )

        except Exception as e:
            logger.error(f"Error parsing DeepSeek response: {e}")
            return LLMResponse(
                success=False,
                content="",
                error=f"Response parsing failed: {str(e)}",
                raw_response=response_data
            )

    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        return {
            "model_name": self.config.model_name,
            "provider": "deepseek",
            "base_url": self.base_url,
            "supported_models": self.SUPPORTED_MODELS,
            "context_length": self._get_context_length(),
            "description": f"DeepSeek {self.config.model_name} model"
        }

    def _get_context_length(self) -> int:
        """获取模型的上下文长度"""
        # DeepSeek模型的上下文长度
        context_lengths = {
            "deepseek-chat": 32768,
            "deepseek-coder": 16384,
            "deepseek-chat-67b": 32768,
            "deepseek-coder-33b": 16384,
            "deepseek-coder-6.7b": 8192,
            "deepseek-chat-7b": 4096
        }

        return context_lengths.get(self.config.model_name, 4096)

    def get_available_models(self) -> List[str]:
        """获取可用的模型列表"""
        try:
            url = f"{self.base_url}/models"
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                models = [model["id"] for model in data.get("data", [])]
                return [m for m in models if m in self.SUPPORTED_MODELS]
            else:
                logger.warning(f"Failed to fetch models: {response.status_code}")
                return self.SUPPORTED_MODELS.copy()

        except Exception as e:
            logger.error(f"Error fetching available models: {e}")
            return self.SUPPORTED_MODELS.copy()


class APIResponse:
    """API响应包装类"""
    def __init__(self, success: bool, data: Optional[Dict[str, Any]] = None, error: Optional[str] = None):
        self.success = success
        self.data = data
        self.error = error
