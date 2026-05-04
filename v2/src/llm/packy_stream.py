from __future__ import annotations

import json
from typing import Any, Callable, Dict, Iterable, List, Optional

import httpx

from .usage import normalize_usage


def collect_packy_text(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    temperature: float,
    max_tokens: int,
    timeout: float,
    extra_body: Optional[Dict[str, Any]] = None,
) -> str:
    return collect_packy_text_response(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        extra_body=extra_body,
    )["content"]


def collect_packy_text_response(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    temperature: float,
    max_tokens: int,
    timeout: float,
    extra_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    parts: List[str] = []
    last_usage: Dict[str, Any] = normalize_usage({}, model=model)
    for event in stream_packy_chat_events(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        extra_body=extra_body,
    ):
        usage = _extract_usage_from_event(event, model=model)
        if usage["available"]:
            last_usage = usage
        for choice in event.get("choices", []):
            delta = choice.get("delta", {})
            text = delta.get("content")
            if text:
                parts.append(str(text))
    return {
        "content": "".join(parts),
        "llm_usage": last_usage,
    }


def collect_packy_text_and_tools(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    temperature: float,
    max_tokens: int,
    timeout: float,
    on_chunk: Optional[Callable[[str], None]] = None,
    extra_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    response = collect_packy_text_and_tools_response(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        tools=tools,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        on_chunk=on_chunk,
        extra_body=extra_body,
    )
    return {
        "content": response["content"],
        "tool_calls": response["tool_calls"],
    }


def collect_packy_text_and_tools_response(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    temperature: float,
    max_tokens: int,
    timeout: float,
    on_chunk: Optional[Callable[[str], None]] = None,
    extra_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    content_parts: List[str] = []
    tool_calls_data: Dict[int, Dict[str, Any]] = {}
    last_usage: Dict[str, Any] = normalize_usage({}, model=model)
    request_body = dict(extra_body or {})
    request_body["tools"] = tools
    request_body["tool_choice"] = "auto"

    for event in stream_packy_chat_events(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        extra_body=request_body,
    ):
        usage = _extract_usage_from_event(event, model=model)
        if usage["available"]:
            last_usage = usage
        for choice in event.get("choices", []):
            delta = choice.get("delta", {})
            text = delta.get("content")
            if text:
                text_str = str(text)
                content_parts.append(text_str)
                if on_chunk:
                    on_chunk(text_str)

            for tool_call in delta.get("tool_calls") or []:
                idx = int(tool_call.get("index", 0))
                entry = tool_calls_data.setdefault(
                    idx,
                    {"id": "", "name": "", "arguments": ""},
                )
                if tool_call.get("id"):
                    entry["id"] = str(tool_call["id"])
                function = tool_call.get("function") or {}
                if function.get("name"):
                    entry["name"] = str(function["name"])
                if function.get("arguments"):
                    entry["arguments"] += str(function["arguments"])

    tool_calls: List[Dict[str, Any]] = []
    for idx in sorted(tool_calls_data.keys()):
        entry = tool_calls_data[idx]
        try:
            arguments = json.loads(entry["arguments"]) if entry["arguments"] else {}
        except json.JSONDecodeError:
            arguments = {}
        tool_calls.append(
            {
                "id": entry["id"],
                "name": entry["name"],
                "arguments": arguments,
            }
        )

    return {
        "content": "".join(content_parts),
        "tool_calls": tool_calls,
        "llm_usage": last_usage,
    }


def stream_packy_chat_events(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: List[Dict[str, Any]],
    temperature: float,
    max_tokens: int,
    timeout: float,
    extra_body: Optional[Dict[str, Any]] = None,
) -> Iterable[Dict[str, Any]]:
    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if extra_body:
        payload.update(extra_body)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    url = f"{base_url.rstrip('/')}/chat/completions"

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        with client.stream("POST", url, headers=headers, json=payload) as response:
            if response.status_code >= 400:
                body = response.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"PackyAPI HTTP {response.status_code}: {body}")

            for line in response.iter_lines():
                if not line:
                    continue
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="replace")
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                if data == "[DONE]":
                    break
                try:
                    event = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    yield event


def _extract_usage_from_event(event: Dict[str, Any], *, model: str) -> Dict[str, Any]:
    if not isinstance(event, dict):
        return normalize_usage({}, model=model)
    for key in ("usage", "usage_metadata"):
        usage = normalize_usage(event.get(key), model=model)
        if usage["available"]:
            return usage
    return normalize_usage({}, model=model)
