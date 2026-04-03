from __future__ import annotations

import os
from typing import Any, Dict, Optional

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
import httpx


# Provider 配置 (不含密钥，密钥在配置文件中)
PROVIDER_CONFIGS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "env_key": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
    },
    "xty": {
        "base_url": "https://api.xty.app/v1",
        "env_key": "XTY_API_KEY",
        "default_model": "gpt-3.5-turbo",
    },
}


def build_langchain_chat_model(
    config: Optional[Dict[str, Any]] = None,
    override: Any = None,
    *,
    temperature_key: Optional[str] = None,
    default_temperature: float = 0.2,
) -> BaseChatModel:
    if isinstance(override, BaseChatModel):
        return override

    raw_config = config or {}
    llm_config = raw_config.get("llm", {}) if isinstance(raw_config.get("llm", {}), dict) else {}
    generation = llm_config.get("generation", {}) if isinstance(llm_config.get("generation", {}), dict) else {}
    api_keys = llm_config.get("api_keys", {}) if isinstance(llm_config.get("api_keys", {}), dict) else {}
    base_urls = llm_config.get("base_urls", {}) if isinstance(llm_config.get("base_urls", {}), dict) else {}
    agent_config = raw_config.get("agent", {}) if isinstance(raw_config.get("agent", {}), dict) else {}

    # 确定 provider
    provider = str(llm_config.get("provider", "deepseek") or "deepseek").strip().lower()
    if provider not in PROVIDER_CONFIGS:
        provider = "deepseek"

    provider_info = PROVIDER_CONFIGS[provider]

    # 获取 API Key (优先配置文件，然后环境变量)
    api_key = str(api_keys.get(provider, "") or "").strip()
    if not api_key:
        env_key = provider_info.get("env_key", "")
        api_key = os.environ.get(env_key, "").strip()

    if not api_key:
        raise ValueError(f"未配置 {provider.upper()} API Key，请在配置文件或环境变量中设置。")

    # 模型名称
    default_model = provider_info.get("default_model", "")
    model_name = str(llm_config.get("primary_model", default_model) or default_model).strip()

    # Base URL
    default_base_url = provider_info.get("base_url", "")
    base_url = str(base_urls.get(provider, default_base_url) or default_base_url).strip()

    # Temperature
    temperature = None
    if temperature_key:
        temperature = agent_config.get(temperature_key, None)
    if temperature is None:
        temperature = agent_config.get("temperature", generation.get("temperature", default_temperature))

    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        temperature=float(temperature or default_temperature),
        max_tokens=int(generation.get("max_tokens", 8192) or 8192),
        timeout=float(generation.get("timeout", 120) or 120),
        max_retries=int(generation.get("max_retries", 3) or 3),
    )
