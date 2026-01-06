"""
DeepSeek LLM Client
DeepSeek大语言模型客户端实现
"""

import requests
import json
import time
from typing import Dict, Any, List, Optional
import logging

from .llm_client import LLMClient, LLMConfig

# 使用标准logging而不是loguru，以避免依赖问题
logger = logging.getLogger(__name__)


class DeepSeekClient(LLMClient):
    """DeepSeek LLM客户端"""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json"
        })

    def generate(self, prompt: str, **kwargs) -> str:
        """生成文本"""
        messages = [{"role": "user", "content": prompt}]
        return self.generate_with_history(messages, **kwargs)

    def generate_with_history(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """基于对话历史生成文本"""
        try:
            data = self._prepare_request_data(messages, **kwargs)

            for attempt in range(self.config.max_retries):
                try:
                    response = self.session.post(
                        f"{self.config.base_url}/chat/completions",
                        json=data,
                        timeout=self.config.timeout
                    )

                    if response.status_code == 200:
                        result = response.json()
                        return self._handle_response(result)
                    elif response.status_code == 429:  # Rate limit
                        if attempt < self.config.max_retries - 1:
                            wait_time = 2 ** attempt  # Exponential backoff
                            self.logger.warning(f"Rate limited, waiting {wait_time} seconds...")
                            time.sleep(wait_time)
                            continue
                        else:
                            raise Exception(f"Rate limit exceeded after {self.config.max_retries} attempts")
                    elif response.status_code == 401:
                        raise Exception("Invalid API key")
                    elif response.status_code == 402:
                        raise Exception("Insufficient balance")
                    else:
                        raise Exception(f"API error: {response.status_code} - {response.text}")

                except requests.exceptions.RequestException as e:
                    if attempt < self.config.max_retries - 1:
                        wait_time = 2 ** attempt
                        self.logger.warning(f"Request failed, retrying in {wait_time} seconds: {e}")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise Exception(f"Request failed after {self.config.max_retries} attempts: {e}")

            return ""

        except Exception as e:
            self.logger.error(f"Error generating text: {e}")
            return ""

    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        try:
            response = self.session.get(
                f"{self.config.base_url}/models",
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                models = data.get("data", [])

                # 查找当前配置的模型
                current_model = None
                for model in models:
                    if model.get("id") == self.config.model_name:
                        current_model = model
                        break

                return {
                    "available_models": [m.get("id", "") for m in models],
                    "current_model": self.config.model_name,
                    "model_details": current_model or {},
                    "status": "available"
                }
            else:
                return {
                    "available_models": [],
                    "current_model": self.config.model_name,
                    "model_details": {},
                    "status": "unavailable",
                    "error": f"Failed to fetch models: {response.status_code}"
                }

        except Exception as e:
            self.logger.error(f"Error getting model info: {e}")
            return {
                "available_models": [],
                "current_model": self.config.model_name,
                "model_details": {},
                "status": "error",
                "error": str(e)
            }

    def is_available(self) -> bool:
        """检查模型是否可用"""
        try:
            # 简单的心跳检查
            response = self.session.get(
                f"{self.config.base_url}/models",
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False

    def get_available_models(self) -> List[str]:
        """获取可用模型列表"""
        try:
            response = self.session.get(
                f"{self.config.base_url}/models",
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                data = response.json()
                return [model.get("id", "") for model in data.get("data", [])]
            else:
                return []

        except Exception as e:
            self.logger.error(f"Error getting available models: {e}")
            return []
