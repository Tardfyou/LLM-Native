from __future__ import annotations

from typing import Any, Dict, Optional

from langchain_core.language_models.chat_models import BaseChatModel

from ..llm.langchain_builder import build_langchain_chat_model as _build_langchain_chat_model


def build_langchain_chat_model(
    config: Optional[Dict[str, Any]] = None,
    override: Any = None,
) -> BaseChatModel:
    return _build_langchain_chat_model(
        config=config,
        override=override,
        temperature_key="refine_temperature",
        default_temperature=0.2,
    )
