"""
Simple and clean LLM model interface supporting multiple providers

支持的提供商:
- OpenAI: gpt-4o, gpt-4, o1, o3-mini, o4-mini
- 智谱AI (GLM): glm-4.7, glm-4, glm-4-air, glm-4-flash
- DeepSeek: deepseek-chat, deepseek-reasoner
- Claude: claude-3-5-sonnet, claude-3-5-haiku
- Google: gemini-2.0-flash-exp
- 通用兼容: Any OpenAI-compatible API
"""

import asyncio
import os
import time
from typing import Any, Dict, Optional

from openai import OpenAI

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    anthropic = None
    ANTHROPIC_AVAILABLE = False

try:
    from google import genai
    GOOGLE_AVAILABLE = True
except ImportError:
    genai = None
    GOOGLE_AVAILABLE = False

from loguru import logger

# Global clients
clients: Dict[str, Any] = {}
model_config = {
    "model": "glm-4.7",
    "temperature": 0.3,
    "max_tokens": 9192,
}


def init_llm(config: Dict[str, Any]) -> None:
    """
    Initialize LLM clients from configuration

    Args:
        config: 配置字典，包含 llm 配置节
    """
    global clients, model_config

    keys = config.get("llm", {}).get("keys", {})

    # Initialize OpenAI client
    if "openai_key" in keys:
        clients["openai"] = OpenAI(api_key=keys["openai_key"])
        logger.info("Initialized OpenAI client")

    # Initialize 智谱AI (GLM) client - 使用 OpenAI SDK
    if "glm_key" in keys:
        clients["glm"] = OpenAI(
            api_key=keys["glm_key"],
            base_url="https://open.bigmodel.cn/api/paas/v4"
        )
        logger.info("Initialized GLM client (OpenAI-compatible)")

    # Initialize DeepSeek client - 使用 OpenAI SDK
    if "deepseek_key" in keys:
        clients["deepseek"] = OpenAI(
            api_key=keys["deepseek_key"],
            base_url="https://api.deepseek.com/v1"
        )
        logger.info("Initialized DeepSeek client (OpenAI-compatible)")

    # Initialize local/custom OpenAI-compatible client
    base_url = config.get("llm", {}).get("base_url")
    if base_url:
        # 通用 API key 或特定提供商的 key
        api_key = keys.get("api_key", keys.get("openai_key", "dummy"))
        clients["local"] = OpenAI(base_url=base_url, api_key=api_key)
        logger.info(f"Initialized local client: {base_url}")

    # Initialize Claude client
    if "claude_key" in keys and ANTHROPIC_AVAILABLE:
        clients["claude"] = anthropic.Anthropic(api_key=keys["claude_key"])
        logger.info("Initialized Claude client")

    # Initialize Google client
    if "google_key" in keys and GOOGLE_AVAILABLE:
        clients["google"] = genai.Client(api_key=keys["google_key"])
        logger.info("Initialized Google client")

    # 从环境变量初始化
    if os.environ.get("OPENAI_API_KEY"):
        if "openai" not in clients:
            clients["openai"] = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
            logger.info("Initialized OpenAI client from env")

    if os.environ.get("GLM_API_KEY") and "glm" not in clients:
        clients["glm"] = OpenAI(
            api_key=os.environ["GLM_API_KEY"],
            base_url="https://open.bigmodel.cn/api/paas/v4"
        )
        logger.info("Initialized GLM client from env")

    if os.environ.get("DEEPSEEK_API_KEY") and "deepseek" not in clients:
        clients["deepseek"] = OpenAI(
            api_key=os.environ["DEEPSEEK_API_KEY"],
            base_url="https://api.deepseek.com/v1"
        )
        logger.info("Initialized DeepSeek client from env")

    # Set model configuration from config.yaml
    llm_config = config.get("llm", {})
    model_config["model"] = llm_config.get("primary_model", "glm-4.7")
    model_config["fast_model"] = llm_config.get("fast_model", "deepseek-reasoner")  # 快速模型

    generation = llm_config.get("generation", {})
    model_config["temperature"] = generation.get("temperature", 0.7)
    model_config["max_tokens"] = generation.get("max_tokens", 10000)

    logger.info(f"LLM initialized with model: {model_config['model']}, fast_model: {model_config['fast_model']}, max_tokens: {model_config['max_tokens']}")

    if not clients:
        raise ValueError("No LLM clients configured. Please provide API keys in config.yaml")


def get_client_and_model(model_name: str) -> tuple:
    """
    Determine which client to use and actual model name

    Returns:
        (client, actual_model_name) 元组
    """
    # Model to client mapping
    model_mapping = {
        # OpenAI models
        "gpt-4o": ("openai", "gpt-4o"),
        "gpt-4o-mini": ("openai", "gpt-4o-mini"),
        "gpt-4-turbo": ("openai", "gpt-4-turbo"),
        "gpt-4": ("openai", "gpt-4"),
        "o1": ("openai", "o1"),
        "o1-preview": ("openai", "o1-preview"),
        "o1-mini": ("openai", "o1-mini"),
        "o3-mini": ("openai", "o3-mini"),
        "o4-mini": ("openai", "o4-mini"),
        "gpt-5": ("openai", "gpt-5"),

        # 智谱AI GLM models
        "glm-4.7": ("glm", "glm-4.7"),
        "glm-4.7-flash": ("glm", "glm-4.7-flash"),  # 快速模型
        "glm-4-plus": ("glm", "glm-4-plus"),
        "glm-4": ("glm", "glm-4"),
        "glm-4-air": ("glm", "glm-4-air"),
        "glm-4-airx": ("glm", "glm-4-airx"),
        "glm-4-flash": ("glm", "glm-4-flash"),
        "glm-3-turbo": ("glm", "glm-3-turbo"),

        # DeepSeek models
        "deepseek-chat": ("deepseek", "deepseek-chat"),
        "deepseek-reasoner": ("deepseek", "deepseek-reasoner"),
        "deepseek-coder": ("deepseek", "deepseek-coder"),

        # Claude models
        "claude": ("claude", "claude-3-5-sonnet-20241022"),
        "claude-3-5-sonnet": ("claude", "claude-3-5-sonnet-20241022"),
        "claude-3-5-haiku": ("claude", "claude-3-5-haiku-20241022"),
        "claude-3-opus": ("claude", "claude-3-opus-20240229"),

        # Google models
        "google": ("google", "gemini-2.0-flash-exp"),
        "gemini": ("google", "gemini-2.0-flash-exp"),
    }

    # Check if it's a known model
    if model_name in model_mapping:
        client_name, actual_model = model_mapping[model_name]
        if client_name in clients:
            return clients[client_name], actual_model
        else:
            logger.warning(f"Client '{client_name}' not configured for model '{model_name}'")

    # Check if it's a local model (format: local:model_name)
    if model_name.startswith("local:") and "local" in clients:
        actual_model = model_name[6:]  # Remove "local:" prefix
        return clients["local"], actual_model

    # Check custom providers (format: provider:model_name)
    if ":" in model_name:
        provider, actual_model = model_name.split(":", 1)
        if provider in clients:
            return clients[provider], actual_model

    # Default: try with available clients
    # Prefer GLM for glm-* models
    if model_name.startswith("glm-") and "glm" in clients:
        return clients["glm"], model_name

    # Prefer DeepSeek for deepseek-* models
    if model_name.startswith("deepseek-") and "deepseek" in clients:
        return clients["deepseek"], model_name

    # Default to local client if available
    if "local" in clients:
        return clients["local"], model_name

    # Fallback to GLM if available
    if "glm" in clients:
        return clients["glm"], model_name

    # Fallback to OpenAI if available
    if "openai" in clients:
        return clients["openai"], model_name

    raise ValueError(f"No client available for model '{model_name}'. Available clients: {list(clients.keys())}")


def invoke_llm(
    prompt: str,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
    max_tokens: Optional[int] = None,
) -> Optional[str]:
    """
    调用 LLM 生成文本

    Args:
        prompt: 输入提示词
        temperature: 温度参数 (可选)
        model: 模型名称 (可选)
        max_tokens: 最大 token 数 (可选)

    Returns:
        生成的文本，失败返回 None
    """
    model = model or model_config["model"]
    temperature = temperature if temperature is not None else model_config["temperature"]
    max_tokens = max_tokens or model_config["max_tokens"]

    logger.info(f"LLM request: model={model}, tokens={max_tokens}")

    # Simple token check
    if len(prompt) > 400000:  # ~100k tokens
        logger.warning("Prompt too long, skipping")
        return None

    # Get client and actual model name
    try:
        client, actual_model = get_client_and_model(model)
    except ValueError as e:
        logger.error(f"Error getting client for model '{model}': {e}")
        return None

    # Retry logic (6次重试)
    for attempt in range(6):
        try:
            # Handle different client types
            if ANTHROPIC_AVAILABLE and isinstance(client, anthropic.Anthropic):
                # Claude API
                response = client.messages.create(
                    model=actual_model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                answer = response.content[0].text

            elif GOOGLE_AVAILABLE and isinstance(client, genai.Client):
                # Google API
                response = client.models.generate_content(
                    model=actual_model,
                    contents=prompt,
                )
                answer = response.text

            else:  # OpenAI or compatible (GLM, DeepSeek, etc.)
                kwargs = {
                    "model": actual_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "timeout": 120.0,  # 设置 120 秒超时
                }

                # Only add temperature for models that support it
                no_temp_models = ["o1", "o3-mini", "o4-mini", "o1-preview", "gpt-5"]
                if not any(m in actual_model for m in no_temp_models):
                    kwargs["temperature"] = temperature

                # 记录开始时间
                import time
                start = time.time()
                logger.info(f"API call started: model={actual_model}, prompt_len={len(prompt)}")

                response = client.chat.completions.create(**kwargs)

                elapsed = time.time() - start
                logger.info(f"API call completed in {elapsed:.1f}s")
                answer = response.choices[0].message.content

            logger.info(f"LLM response received: {len(answer) if answer else 0} chars")
            return answer

        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            logger.error(f"LLM error attempt {attempt + 1}/6: {error_type}: {error_msg[:200]}")
            if attempt >= 5:
                logger.error("LLM failed after 6 attempts")
                return None
            # 指数退避
            wait_time = min(2 ** attempt, 32)
            logger.info(f"Waiting {wait_time}s before retry...")
            time.sleep(wait_time)

    return None


def invoke_llm_with_history(
    messages: list,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
    max_tokens: Optional[int] = None,
) -> Optional[str]:
    """
    使用对话历史调用 LLM

    Args:
        messages: 消息历史列表 [{"role": "user", "content": "..."}, ...]
        temperature: 温度参数 (可选)
        model: 模型名称 (可选)
        max_tokens: 最大 token 数 (可选)

    Returns:
        生成的文本，失败返回 None
    """
    model = model or model_config["model"]
    temperature = temperature if temperature is not None else model_config["temperature"]
    max_tokens = max_tokens or model_config["max_tokens"]

    logger.info(f"LLM request with history: model={model}, messages={len(messages)}")

    # Get client and actual model name
    try:
        client, actual_model = get_client_and_model(model)
    except ValueError as e:
        logger.error(f"Error getting client for model '{model}': {e}")
        return None

    # Retry logic (6次重试)
    for attempt in range(6):
        try:
            # Handle different client types
            if ANTHROPIC_AVAILABLE and isinstance(client, anthropic.Anthropic):
                # Claude API
                response = client.messages.create(
                    model=actual_model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                answer = response.content[0].text

            elif GOOGLE_AVAILABLE and isinstance(client, genai.Client):
                # Google API (需要转换消息格式)
                contents = "\n\n".join([f"{m['role']}: {m['content']}" for m in messages])
                response = client.models.generate_content(
                    model=actual_model,
                    contents=contents,
                )
                answer = response.text

            else:  # OpenAI or compatible (GLM, DeepSeek, etc.)
                kwargs = {
                    "model": actual_model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "timeout": 120.0,  # 设置 120 秒超时
                }

                # Only add temperature for models that support it
                no_temp_models = ["o1", "o3-mini", "o4-mini", "o1-preview", "gpt-5"]
                if not any(m in actual_model for m in no_temp_models):
                    kwargs["temperature"] = temperature

                response = client.chat.completions.create(**kwargs)
                answer = response.choices[0].message.content

            logger.info(f"LLM response received: {len(answer) if answer else 0} chars")
            return answer

        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            logger.error(f"LLM error attempt {attempt + 1}/6: {error_type}: {error_msg[:200]}")
            if attempt >= 5:
                logger.error("LLM failed after 6 attempts")
                return None
            # 指数退避
            wait_time = min(2 ** attempt, 32)
            logger.info(f"Waiting {wait_time}s before retry...")
            time.sleep(wait_time)

    return None


def is_available() -> bool:
    """检查 LLM 是否可用"""
    return bool(clients)


def get_available_models() -> list:
    """获取可用的模型列表"""
    return list(model_mapping.keys()) if 'model_mapping' in globals() else [
        "glm-4.7", "glm-4", "glm-4-air", "glm-4-flash",
        "deepseek-chat", "deepseek-reasoner",
        "gpt-4o", "gpt-4o-mini", "gpt-4",
        "claude-3-5-sonnet", "claude-3-5-haiku",
    ]


def get_current_model() -> str:
    """获取当前使用的模型"""
    return model_config.get("model", "glm-4.7")


def get_fast_model() -> str:
    """获取快速模型（用于 repair 等场景）"""
    return model_config.get("fast_model", "deepseek-reasoner")


# 向后兼容的包装器类
class LLMClientWrapper:
    """
    向后兼容的 LLM 客户端包装器

    包装新的简化接口，提供与旧代码兼容的 generate() 方法
    """

    def __init__(self, config: Dict[str, Any]):
        """初始化包装器"""
        init_llm(config)

    def generate(self, prompt: str, **kwargs) -> str:
        """
        生成文本 (向后兼容接口)

        Args:
            prompt: 输入提示词
            **kwargs: 额外参数 (temperature, max_tokens, model等)

        Returns:
            生成的文本
        """
        return invoke_llm(prompt, **kwargs) or ""

    def generate_with_history(self, messages: list, **kwargs) -> str:
        """
        使用对话历史生成文本 (向后兼容接口)

        Args:
            messages: 消息历史列表
            **kwargs: 额外参数

        Returns:
            生成的文本
        """
        return invoke_llm_with_history(messages, **kwargs) or ""

    @property
    def config(self):
        """返回配置对象 (向后兼容)"""
        return LLMConfigProxy(model_config)


class LLMConfigProxy:
    """配置对象代理 (向后兼容)"""
    def __init__(self, config_dict):
        self._config = config_dict

    @property
    def model_name(self):
        return self._config.get("model", "glm-4.7")

    @property
    def temperature(self):
        return self._config.get("temperature", 0.7)

    @property
    def max_tokens(self):
        return self._config.get("max_tokens", 10000)

    @property
    def fast_model(self):
        return self._config.get("fast_model", "deepseek-reasoner")

    @property
    def timeout(self):
        return self._config.get("timeout", 120)

    @property
    def max_retries(self):
        return self._config.get("max_retries", 6)
