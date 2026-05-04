from __future__ import annotations

from typing import Any, Dict


PROVIDER_CONFIGS: Dict[str, Dict[str, Any]] = {
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
    "packyapi": {
        "base_url": "https://www.packyapi.com/v1",
        "env_key": "PACKY_API_KEY",
        "default_model": "gpt-5.4",
        # Packy 对部分 OpenAI 兼容接口的非流式聚合不稳定，强制走流式读取文本更稳。
        "force_stream_text": True,
        "force_stream_tools": True,
        "force_langchain_stream_adapter": True,
    },
}


def resolve_provider_name(raw_provider: Any) -> str:
    provider = str(raw_provider or "deepseek").strip().lower()
    if provider not in PROVIDER_CONFIGS:
        return "deepseek"
    return provider
