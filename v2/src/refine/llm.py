from __future__ import annotations

from typing import Any, Dict, Optional

from langchain_core.language_models.chat_models import BaseChatModel

from ..llm.langchain_builder import build_langchain_chat_model as _build_langchain_chat_model


def resolve_refine_temperature(
    config: Optional[Dict[str, Any]],
    temperature_key: Optional[str],
    default_temperature: float,
) -> float:
    raw_config = config or {}
    agent_config = raw_config.get("agent", {}) if isinstance(raw_config.get("agent", {}), dict) else {}

    temperature = agent_config.get(temperature_key) if temperature_key else None
    if temperature is None and temperature_key != "refine_decision_temperature":
        temperature = agent_config.get("refine_decision_temperature")
    if temperature is None:
        temperature = agent_config.get("refine_temperature")
    if temperature is None:
        temperature = agent_config.get("temperature")
    if temperature is None:
        temperature = default_temperature
    return float(temperature)


def build_langchain_chat_model(
    config: Optional[Dict[str, Any]] = None,
    override: Any = None,
    *,
    temperature_override: Optional[float] = None,
    default_temperature: float = 0.1,
) -> BaseChatModel:
    resolved_temperature = temperature_override
    if resolved_temperature is None:
        resolved_temperature = resolve_refine_temperature(config, "refine_decision_temperature", default_temperature)

    return _build_langchain_chat_model(
        config=config,
        override=override,
        temperature_override=resolved_temperature,
        default_temperature=default_temperature,
        generation_config_key="refine",
    )
