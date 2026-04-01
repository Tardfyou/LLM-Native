"""
LLM客户端 - 支持DeepSeek模型

提供统一的LLM调用接口，支持:
- 文本生成
- 工具调用 (Function Calling)
- 流式输出
- 重试机制
"""

import json
import time
from typing import Optional, List, Dict, Any, Callable

from openai import OpenAI
from loguru import logger


class LLMClient:
    """DeepSeek LLM客户端"""

    def __init__(self, config: Dict[str, Any]):
        """
        初始化LLM客户端

        Args:
            config: LLM配置字典
        """
        self.config = config
        self.primary_model = config.get("primary_model", "deepseek-chat")
        self.log_calls = bool(config.get("log_calls", True))

        # 获取API密钥
        api_keys = config.get("api_keys", {})
        deepseek_key = api_keys.get("deepseek")

        if not deepseek_key:
            raise ValueError("未配置DeepSeek API密钥")

        # 初始化OpenAI兼容客户端
        self.client = OpenAI(
            api_key=deepseek_key,
            base_url="https://api.deepseek.com/v1"
        )

        # 生成参数
        gen_config = config.get("generation", {})
        self.temperature = gen_config.get("temperature", 0.7)
        self.max_tokens = gen_config.get("max_tokens", 8192)
        self.timeout = gen_config.get("timeout", 120)
        self.max_retries = gen_config.get("max_retries", 3)

        if self.log_calls:
            logger.info(f"LLM客户端初始化完成: model={self.primary_model}")

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

                response = self.client.chat.completions.create(
                    model=self.primary_model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temp,
                    max_tokens=tokens,
                    timeout=self.timeout
                )

                answer = response.choices[0].message.content
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

                if stream:
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

        for chunk in response:
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

        return {
            "content": content,
            "tool_calls": tool_calls
        }

    def _parse_tool_response(self, response) -> Dict[str, Any]:
        """解析工具调用响应"""
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
