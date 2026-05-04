from __future__ import annotations

from typing import Any, Dict, Iterable


def empty_usage() -> Dict[str, Any]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "call_count": 0,
        "available": False,
        "model": "",
    }


def normalize_usage(raw: Any, *, model: str = "", call_count: int | None = None) -> Dict[str, Any]:
    payload = _to_mapping(raw)
    prompt_tokens = _coerce_int(
        payload.get("prompt_tokens", payload.get("input_tokens", payload.get("prompt_token_count", 0)))
    )
    completion_tokens = _coerce_int(
        payload.get("completion_tokens", payload.get("output_tokens", payload.get("completion_token_count", 0)))
    )
    total_tokens = _coerce_int(
        payload.get("total_tokens", prompt_tokens + completion_tokens)
    )
    resolved_model = str(
        model
        or payload.get("model_name", payload.get("model", payload.get("model_id", "")))
        or ""
    ).strip()
    available = any(value > 0 for value in (prompt_tokens, completion_tokens, total_tokens))
    count = _coerce_int(call_count if call_count is not None else payload.get("call_count", 0))
    if count <= 0 and available:
        count = 1
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "call_count": count,
        "available": available,
        "model": resolved_model,
    }


def merge_usages(usages: Iterable[Any]) -> Dict[str, Any]:
    merged = empty_usage()
    models = []
    for raw in usages:
        usage = normalize_usage(raw)
        merged["prompt_tokens"] += usage["prompt_tokens"]
        merged["completion_tokens"] += usage["completion_tokens"]
        merged["total_tokens"] += usage["total_tokens"]
        merged["call_count"] += usage["call_count"]
        merged["available"] = merged["available"] or usage["available"]
        model = str(usage.get("model", "") or "").strip()
        if model and model not in models:
            models.append(model)
    merged["model"] = ",".join(models)
    return merged


def extract_usage_from_response(response: Any, *, fallback_model: str = "") -> Dict[str, Any]:
    if response is None:
        return empty_usage()

    if isinstance(response, dict):
        if "usage" in response:
            return normalize_usage(response.get("usage"), model=fallback_model)
        if "usage_metadata" in response:
            return normalize_usage(response.get("usage_metadata"), model=fallback_model)
        raw = response.get("raw")
        if raw is not None:
            return extract_usage_from_response(raw, fallback_model=fallback_model)

    usage_candidates = [
        getattr(response, "usage_metadata", None),
        getattr(response, "usage", None),
    ]

    response_metadata = getattr(response, "response_metadata", None)
    response_metadata_map = _to_mapping(response_metadata)
    if response_metadata_map:
        usage_candidates.extend(
            [
                response_metadata_map.get("token_usage"),
                response_metadata_map.get("usage"),
            ]
        )
        model_name = str(
            response_metadata_map.get("model_name", response_metadata_map.get("model", fallback_model)) or ""
        ).strip()
        if model_name and not fallback_model:
            fallback_model = model_name

    for candidate in usage_candidates:
        usage = normalize_usage(candidate, model=fallback_model)
        if usage["available"]:
            return usage

    return normalize_usage({}, model=fallback_model)


def usage_summary_text(usage: Any) -> str:
    normalized = normalize_usage(usage)
    if not normalized["available"]:
        return "tokens unavailable"
    return (
        f"in={normalized['prompt_tokens']} "
        f"out={normalized['completion_tokens']} "
        f"total={normalized['total_tokens']} "
        f"calls={normalized['call_count']}"
    )


def _to_mapping(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if hasattr(raw, "model_dump"):
        try:
            dumped = raw.model_dump()
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            return {}
    if hasattr(raw, "dict"):
        try:
            dumped = raw.dict()
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            return {}
    if hasattr(raw, "__dict__"):
        try:
            return dict(vars(raw))
        except Exception:
            return {}
    return {}


def _coerce_int(raw: Any) -> int:
    try:
        return max(0, int(raw or 0))
    except Exception:
        return 0
