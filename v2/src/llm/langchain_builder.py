from __future__ import annotations

import os
from typing import Any, Dict, Optional

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI


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
    agent_config = raw_config.get("agent", {}) if isinstance(raw_config.get("agent", {}), dict) else {}

    api_key = str(api_keys.get("deepseek", "") or os.environ.get("DEEPSEEK_API_KEY", "")).strip()
    if not api_key:
        raise ValueError("未配置 DeepSeek API Key，无法启动 LangChain agent。")

    model_name = str(llm_config.get("primary_model", "deepseek-chat") or "deepseek-chat").strip()
    base_url = str(llm_config.get("base_url", "https://api.deepseek.com/v1") or "https://api.deepseek.com/v1").strip()

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
