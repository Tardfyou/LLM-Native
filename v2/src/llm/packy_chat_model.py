from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from langchain_core.messages import AIMessage, BaseMessage

from .packy_stream import collect_packy_text_response


@dataclass(frozen=True)
class PackyStreamingChatModel:
    model: str
    api_key: str
    base_url: str
    temperature: float
    max_tokens: int
    timeout: float
    max_retries: int
    extra_body: Optional[Dict[str, Any]] = None

    def bind(self, **kwargs: Any) -> "PackyStreamingChatModel":
        merged = dict(self.extra_body or {})
        merged.update(kwargs)
        return PackyStreamingChatModel(
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            timeout=self.timeout,
            max_retries=self.max_retries,
            extra_body=merged,
        )

    def invoke(self, messages: List[Any]) -> AIMessage:
        normalized_messages = [self._to_openai_message(message) for message in messages]
        last_error: Optional[Exception] = None
        for _ in range(max(self.max_retries, 1)):
            try:
                response = collect_packy_text_response(
                    base_url=self.base_url,
                    api_key=self.api_key,
                    model=self.model,
                    messages=normalized_messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.timeout,
                    extra_body=self.extra_body,
                )
                content = str(response.get("content", "") or "")
                usage = dict(response.get("llm_usage", {}) or {})
                return AIMessage(
                    content=content,
                    response_metadata={
                        "usage": usage,
                        "model_name": self.model,
                    },
                )
            except Exception as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise RuntimeError("PackyStreamingChatModel invoke failed")

    def _to_openai_message(self, message: Any) -> Dict[str, Any]:
        if isinstance(message, dict):
            return {
                "role": str(message.get("role", "user")),
                "content": self._stringify_content(message.get("content", "")),
            }

        if isinstance(message, BaseMessage):
            payload: Dict[str, Any] = {
                "role": self._role_for_message(message),
                "content": self._stringify_content(message.content),
            }
            tool_call_id = getattr(message, "tool_call_id", None)
            if tool_call_id:
                payload["tool_call_id"] = tool_call_id
            return payload

        return {
            "role": "user",
            "content": self._stringify_content(message),
        }

    def _role_for_message(self, message: BaseMessage) -> str:
        message_type = getattr(message, "type", "")
        if message_type == "system":
            return "system"
        if message_type == "ai":
            return "assistant"
        if message_type == "tool":
            return "tool"
        return "user"

    def _stringify_content(self, content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                    continue
                if isinstance(item, dict):
                    text = item.get("text")
                    if text:
                        parts.append(str(text))
            return "\n".join(parts)
        return str(content or "")
