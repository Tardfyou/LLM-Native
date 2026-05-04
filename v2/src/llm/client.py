"""
LLM客户端 - 支持多 Provider (DeepSeek / XTY中转站 / PackyAPI)

提供统一的LLM调用接口，支持:
- 文本生成
- 工具调用 (Function Calling)
- 流式输出
- 重试机制
"""

import json
import os
import time
from typing import Optional, List, Dict, Any, Callable

import httpx
from loguru import logger
from openai import OpenAI

from .packy_stream import (
    collect_packy_text_and_tools_response,
    collect_packy_text_response,
)
from .provider_config import PROVIDER_CONFIGS, resolve_provider_name
from .usage import empty_usage, extract_usage_from_response, normalize_usage


class LLMClient:
    """多 Provider LLM客户端"""

    def __init__(self, config: Dict[str, Any]):
        """
        初始化LLM客户端

        Args:
            config: LLM配置字典
        """
        self.config = config
        self.log_calls = bool(config.get("log_calls", True))

        # 确定 provider
        self.provider = resolve_provider_name(config.get("provider", "deepseek"))

        provider_info = PROVIDER_CONFIGS[self.provider]

        # 主模型
        self.primary_model = str(
            config.get("primary_model", provider_info.get("default_model", "")) or
            provider_info.get("default_model", "")
        ).strip()

        # 获取API密钥 (优先配置文件，然后环境变量)
        api_keys = config.get("api_keys", {})
        api_key = str(api_keys.get(self.provider, "") or "").strip()
        if not api_key:
            env_key = provider_info.get("env_key", "")
            api_key = os.environ.get(env_key, "").strip()

        if not api_key:
            raise ValueError(f"未配置 {self.provider.upper()} API密钥")

        # Base URL
        base_urls = config.get("base_urls", {})
        default_base_url = str(provider_info.get("base_url", "") or "").strip()
        base_url = str(base_urls.get(self.provider, default_base_url) or default_base_url).strip()
        self.base_url = base_url
        self.api_key = api_key
        self.force_stream_text = bool(provider_info.get("force_stream_text", False))
        self.force_stream_tools = bool(provider_info.get("force_stream_tools", False))

        # 初始化OpenAI兼容客户端
        client_kwargs = {
            "api_key": api_key,
            "base_url": base_url,
        }

        # XTY 中转站需要特殊配置
        if self.provider == "xty":
            client_kwargs["http_client"] = httpx.Client(
                base_url=base_url,
                follow_redirects=True,
            )

        self.client = OpenAI(**client_kwargs)

        # 生成系统默认参数。优先读取 llm.generate.*，再回退到旧的 llm.generation.*。
        gen_config = config.get("generation", {})
        generate_config = config.get("generate", {})
        if not isinstance(gen_config, dict):
            gen_config = {}
        if not isinstance(generate_config, dict):
            generate_config = {}
        self.temperature = gen_config.get("temperature", 0.7)
        self.max_tokens = generate_config.get("max_tokens", gen_config.get("max_tokens", 16384))
        self.timeout = gen_config.get("timeout", 120)
        self.max_retries = gen_config.get("max_retries", 3)
        self.stream = bool(gen_config.get("stream", True))
        self._last_usage: Dict[str, Any] = empty_usage()

        if self.log_calls:
            logger.info(f"LLM客户端初始化完成: provider={self.provider}, model={self.primary_model}")

    def generate(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Optional[str]:
        """
        生成文本

        Args:
            prompt: 输入提示词
            temperature: 温度参数(可选)
            max_tokens: 最大token数(可选)

        Returns:
            生成的文本，失败返回None
        """
        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens or self.max_tokens

        # 重试机制
        for attempt in range(self.max_retries):
            try:
                if self.log_calls:
                    logger.info(f"LLM调用: model={self.primary_model}, temp={temp}, tokens={tokens}")

                if self.stream or self.force_stream_text:
                    answer = self._stream_generate(
                        prompt=prompt,
                        temperature=temp,
                        max_tokens=tokens,
                    )
                else:
                    response = self.client.chat.completions.create(
                        model=self.primary_model,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=temp,
                        max_tokens=tokens,
                        timeout=self.timeout
                    )
                    self._last_usage = extract_usage_from_response(response, fallback_model=self.primary_model)
                    answer = response.choices[0].message.content or ""
                if self.log_calls:
                    logger.info(f"LLM响应: {len(answer)} 字符")
                return answer

            except Exception as e:
                logger.error(f"LLM调用失败 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"等待 {wait_time}s 后重试...")
                    time.sleep(wait_time)

        logger.error("LLM调用最终失败")
        return None

    def _stream_generate(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """以流式方式生成纯文本响应，减少大响应阻塞。"""
        if self.provider == "packyapi":
            response = collect_packy_text_response(
                base_url=self.base_url,
                api_key=self.api_key,
                model=self.primary_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=float(self.timeout),
            )
            self._last_usage = normalize_usage(response.get("llm_usage", {}), model=self.primary_model)
            return str(response.get("content", "") or "")

        response = self.client.chat.completions.create(
            model=self.primary_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            timeout=self.timeout,
        )

        content_parts: List[str] = []
        last_usage = empty_usage()
        for chunk in response:
            usage = extract_usage_from_response(chunk, fallback_model=self.primary_model)
            if usage["available"]:
                last_usage = usage
            choices = getattr(chunk, "choices", None) or []
            if not choices:
                continue
            delta = getattr(choices[0], "delta", None)
            text = getattr(delta, "content", None) if delta is not None else None
            if text:
                content_parts.append(text)
        self._last_usage = last_usage
        return "".join(content_parts)

    def chat_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        stream: bool = False,
        on_chunk: Callable[[str], None] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        带工具调用的对话

        Args:
            messages: 对话历史 (OpenAI 格式)
            tools: 工具列表 (OpenAI 格式)
            stream: 是否流式输出
            on_chunk: 流式输出回调函数
            temperature: 温度参数
            max_tokens: 最大 token 数

        Returns:
            {"content": "...", "tool_calls": [{"id": "...", "name": "...", "arguments": {...}]}]}
        """
        temp = temperature if temperature is not None else self.temperature
        tokens = max_tokens or self.max_tokens

        for attempt in range(self.max_retries):
            try:
                if self.log_calls:
                    logger.info(f"LLM调用(工具): model={self.primary_model}, tools={len(tools)}, stream={stream}")

                if stream or self.force_stream_tools:
                    return self._stream_chat_with_tools(
                        messages, tools, temp, tokens, on_chunk
                    )
                else:
                    response = self.client.chat.completions.create(
                        model=self.primary_model,
                        messages=messages,
                        tools=tools,
                        tool_choice="auto",
                        temperature=temp,
                        max_tokens=tokens,
                        timeout=self.timeout
                    )

                    return self._parse_tool_response(response)

            except Exception as e:
                logger.error(f"LLM调用失败 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    if self.log_calls:
                        logger.info(f"等待 {wait_time}s 后重试...")
                    time.sleep(wait_time)

        raise RuntimeError("LLM调用最终失败")

    def _stream_chat_with_tools(
        self,
        messages: List[Dict],
        tools: List[Dict],
        temperature: float,
        max_tokens: int,
        on_chunk: Callable[[str], None] = None
    ) -> Dict[str, Any]:
        """流式输出"""
        if self.provider == "packyapi":
            response = collect_packy_text_and_tools_response(
                base_url=self.base_url,
                api_key=self.api_key,
                model=self.primary_model,
                messages=messages,
                tools=tools,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=float(self.timeout),
                on_chunk=on_chunk,
            )
            self._last_usage = normalize_usage(response.get("llm_usage", {}), model=self.primary_model)
            return {
                "content": response.get("content", ""),
                "tool_calls": response.get("tool_calls", []),
            }

        response = self.client.chat.completions.create(
            model=self.primary_model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            timeout=self.timeout
        )

        content = ""
        tool_calls_data: Dict[int, Dict[str, Any]] = {}
        last_usage = empty_usage()

        for chunk in response:
            usage = extract_usage_from_response(chunk, fallback_model=self.primary_model)
            if usage["available"]:
                last_usage = usage
            delta = chunk.choices[0].delta

            # 内容输出
            if delta.content:
                content += delta.content
                if on_chunk:
                    on_chunk(delta.content)

            # 工具调用
            if delta.tool_calls:
                for tc in delta.tool_calls:
                    idx = tc.index
                    if idx not in tool_calls_data:
                        tool_calls_data[idx] = {
                            "id": tc.id or "",
                            "name": "",
                            "arguments": ""
                        }
                    if tc.id:
                        tool_calls_data[idx]["id"] = tc.id
                    if tc.function:
                        if tc.function.name:
                            tool_calls_data[idx]["name"] = tc.function.name
                        if tc.function.arguments:
                            tool_calls_data[idx]["arguments"] += tc.function.arguments

        # 解析工具调用参数
        tool_calls = []
        for idx in sorted(tool_calls_data.keys()):
            tc_data = tool_calls_data[idx]
            try:
                args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
            except json.JSONDecodeError:
                args = {}

            tool_calls.append({
                "id": tc_data["id"],
                "name": tc_data["name"],
                "arguments": args
            })

        self._last_usage = last_usage
        return {
            "content": content,
            "tool_calls": tool_calls
        }

    def _parse_tool_response(self, response) -> Dict[str, Any]:
        """解析工具调用响应"""
        self._last_usage = extract_usage_from_response(response, fallback_model=self.primary_model)
        message = response.choices[0].message

        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    args = {}

                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": args
                })

        return {
            "content": message.content or "",
            "tool_calls": tool_calls
        }

    def get_last_usage(self) -> Dict[str, Any]:
        return normalize_usage(self._last_usage, model=self.primary_model)


# 全局客户端实例
_llm_client: Optional[LLMClient] = None


def create_llm_client(config: Optional[Dict[str, Any]] = None) -> LLMClient:
    """创建独立的 LLM 客户端实例。"""
    if config is None:
        raise ValueError("创建独立客户端时需要提供配置")
    return LLMClient(config)


def get_llm_client(config: Optional[Dict[str, Any]] = None) -> LLMClient:
    """
    获取LLM客户端实例

    Args:
        config: 配置字典(首次调用时需要)

    Returns:
        LLMClient实例
    """
    global _llm_client

    if _llm_client is None:
        if config is None:
            raise ValueError("首次调用需要提供配置")
        _llm_client = LLMClient(config)

    return _llm_client
