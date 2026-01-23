"""
LLM Model Module - Simple multi-LLM interface

支持的模型提供商:
- 智谱AI (GLM): glm-4.7, glm-4, glm-4-air, glm-4-flash
- DeepSeek: deepseek-chat, deepseek-reasoner
- OpenAI: gpt-4o, gpt-4, o1, o3-mini, o4-mini
- Claude: claude-3-5-sonnet, claude-3-5-haiku
- Google: gemini-2.0-flash-exp
- 通用兼容: Any OpenAI-compatible API (Ollama, vLLM, LocalAI, etc.)

使用方式:
    from src.model import init_llm, invoke_llm, LLMClientWrapper

    # 方式1: 简化函数接口
    init_llm(config)
    response = invoke_llm("你的问题")

    # 方式2: 向后兼容的包装器
    llm_client = LLMClientWrapper(config)
    response = llm_client.generate("你的问题")
"""

# 简化的统一接口
from .model import (
    init_llm,
    invoke_llm,
    invoke_llm_with_history,
    is_available,
    get_available_models,
    get_current_model,
    get_fast_model,
    get_client_and_model,
    LLMClientWrapper,  # 向后兼容的包装器
)

# 保留旧的基类以兼容
from .llm_client import LLMClient, LLMConfig

__all__ = [
    # 新的简化接口 (推荐)
    "init_llm",
    "invoke_llm",
    "invoke_llm_with_history",
    "is_available",
    "get_available_models",
    "get_current_model",
    "get_fast_model",
    "get_client_and_model",
    "LLMClientWrapper",  # 向后兼容

    # 旧的基类 (向后兼容)
    "LLMClient",
    "LLMConfig",
]
