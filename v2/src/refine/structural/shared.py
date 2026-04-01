from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class _PatchMechanism:
    removed_calls: frozenset[str]
    added_calls: frozenset[str]
    added_lines: tuple[str, ...]
    removed_lines: tuple[str, ...]
    added_guards: tuple[str, ...]
    has_capacity_guard: bool
    has_null_guard: bool
    has_zero_guard: bool
    has_strlen_binding: bool
    has_length_derived_copy: bool
    has_bounded_formatting_guard: bool
    has_status_guard: bool
    has_state_reset: bool
    has_revalidation_lookup: bool
    has_locking_change: bool


_HEADER_LINE_PREFIXES = ("diff --git ", "index ", "---", "+++", "@@")
_NON_CALL_TOKENS = frozenset({"if", "for", "while", "switch", "return", "sizeof"})
_LOOKUP_CALL_HINTS = frozenset({"get", "find", "lookup", "fetch", "acquire", "reopen", "reattach"})
_LIFECYCLE_CALL_HINTS = frozenset({"free", "delete", "release", "destroy", "close", "put", "drop", "reset"})
_SYNC_CALL_HINTS = (
    "mutex",
    "spin_lock",
    "spin_unlock",
    "lock(",
    "unlock(",
    "atomic",
    "__sync_",
    "__atomic_",
)


def _calls_match_hints(calls: frozenset[str], hints: frozenset[str]) -> bool:
    for call in calls:
        lowered = str(call or "").lower()
        for hint in hints:
            if hint in lowered:
                return True
    return False


def _inspect_patch_mechanism(patch_text: str) -> _PatchMechanism:
    added_lines = _collect_patch_lines(patch_text, "+")
    removed_lines = _collect_patch_lines(patch_text, "-")
    added_text = "\n".join(added_lines)
    removed_text = "\n".join(removed_lines)
    added_guards = tuple(
        line.strip()
        for line in added_lines
        if re.search(r"\bif\s*\(", line)
    )
    has_strlen_binding = bool(
        re.search(
            r"\b(?:size_t|ssize_t|ptrdiff_t|int|unsigned|long|auto)\s+\w+\s*=\s*(?:strn?len|strlen)\s*\(",
            added_text,
        )
    )
    has_length_derived_copy = bool(
        re.search(r"\bmem(?:cpy|move)\s*\([^;]*(?:strn?len|strlen)\s*\(", added_text)
        or (
            has_strlen_binding
            and re.search(r"\bmem(?:cpy|move)\s*\([^;]*\b\w+\s*(?:[+\-]\s*\d+)?\s*\)", added_text)
        )
    )
    return _PatchMechanism(
        removed_calls=_extract_call_names(removed_text),
        added_calls=_extract_call_names(added_text),
        added_lines=tuple(str(line) for line in added_lines),
        removed_lines=tuple(str(line) for line in removed_lines),
        added_guards=added_guards,
        has_capacity_guard=_has_capacity_guard(added_text),
        has_null_guard=_has_null_guard(added_text),
        has_zero_guard=_has_zero_guard(added_text),
        has_strlen_binding=has_strlen_binding,
        has_length_derived_copy=has_length_derived_copy,
        has_bounded_formatting_guard=_has_bounded_formatting_guard(added_text),
        has_status_guard=_has_status_guard(added_text),
        has_state_reset=_has_state_reset(added_text),
        has_revalidation_lookup=_has_revalidation_lookup(added_text),
        has_locking_change=_has_locking_change(added_text, removed_text),
    )


def _collect_patch_lines(patch_text: str, marker: str) -> list[str]:
    lines: list[str] = []
    for raw_line in str(patch_text or "").splitlines():
        if not raw_line.startswith(marker):
            continue
        if raw_line.startswith(_HEADER_LINE_PREFIXES):
            continue
        lines.append(raw_line[1:])
    return lines


def _extract_call_names(text: str) -> frozenset[str]:
    names = {
        match.group("name").lower()
        for match in re.finditer(r"\b(?P<name>[A-Za-z_]\w*)\s*\(", text or "")
        if match.group("name").lower() not in _NON_CALL_TOKENS
    }
    return frozenset(names)


def _has_capacity_guard(added_text: str) -> bool:
    guard_patterns = (
        r"\bif\s*\([^)]*\b\w+\s*(?:>=|>|<=|<)\s*sizeof\s*\(",
        r"\bif\s*\([^)]*sizeof\s*\([^)]*\)\s*(?:>=|>|<=|<)\s*\b\w+",
        r"\bif\s*\([^)]*\b\w+\s*(?:>=|>)\s*(?:out_size|capacity|cap|limit|max(?:imum)?_?\w*)\b",
        r"\bif\s*\([^)]*(?:out_size|capacity|cap|limit|max(?:imum)?_?\w*)\s*(?:<=|<)\s*\b\w+",
    )
    return any(re.search(pattern, added_text or "") for pattern in guard_patterns)


def _has_null_guard(added_text: str) -> bool:
    patterns = (
        r"\bif\s*\([^)]*!\s*\w+",
        r"\bif\s*\([^)]*\bnull\b",
        r"\bif\s*\([^)]*\bnullptr\b",
    )
    return any(re.search(pattern, added_text or "", flags=re.IGNORECASE) for pattern in patterns)


def _has_zero_guard(added_text: str) -> bool:
    patterns = (
        r"\bif\s*\([^)]*\b\w+\s*==\s*0",
        r"\bif\s*\([^)]*0\s*==\s*\w+",
        r"\bif\s*\([^)]*!\s*(?:divisor|denom|denominator|rhs|quotient)\b",
        r"\bif\s*\([^)]*(?:divisor|denom|denominator|rhs|quotient)\s*(?:<=|<)\s*0",
        r"\bif\s*\([^)]*0\s*(?:>=|>)\s*(?:divisor|denom|denominator|rhs|quotient)\b",
    )
    return any(re.search(pattern, added_text or "", flags=re.IGNORECASE) for pattern in patterns)


def _has_bounded_formatting_guard(added_text: str) -> bool:
    if "snprintf" not in (added_text or ""):
        return False
    return bool(
        re.search(
            r"\bif\s*\([^)]*\b\w+\s*<\s*0[^)]*(?:>=|>)\s*(?:\([^)]*\)\s*)?\b\w+",
            added_text or "",
        )
    )


def _has_status_guard(added_text: str) -> bool:
    patterns = (
        r"\bif\s*\([^)]*\b(?:status|ret|rc|res|result|written)\b\s*<\s*0",
        r"\bif\s*\([^)]*\b(?:status|ret|rc|res|result|written)\b[^)]*(?:>=|>)\s*(?:\([^)]*\)\s*)?\b(?:size|capacity|cap|limit|out_size)\b",
        r"\bif\s*\([^)]*\b(?:size|capacity|cap|limit|out_size)\b[^)]*(?:<=|<)\s*\b(?:status|ret|rc|res|result|written)\b",
    )
    return any(re.search(pattern, added_text or "", flags=re.IGNORECASE) for pattern in patterns)


def _has_state_reset(added_text: str) -> bool:
    return bool(
        re.search(r"\bmemset\s*\([^;]*,\s*0\s*,", added_text or "")
        or re.search(r"=\s*(?:NULL|nullptr|0|false)\s*;", added_text or "", flags=re.IGNORECASE)
    )


def _has_revalidation_lookup(added_text: str) -> bool:
    lowered = str(added_text or "").lower()
    return any(
        re.search(rf"\b{re.escape(token)}\w*\s*\(", lowered)
        for token in _LOOKUP_CALL_HINTS
    )


def _has_locking_change(added_text: str, removed_text: str) -> bool:
    combined = f"{added_text or ''}\n{removed_text or ''}".lower()
    return any(token in combined for token in _SYNC_CALL_HINTS)


def _normalize_identifier_token(value: str) -> str:
    text = re.sub(r"(?<!^)(?=[A-Z])", "_", str(value or ""))
    text = text.replace(" ", "_").replace("-", "_")
    text = re.sub(r"[^0-9A-Za-z_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_").lower()
    return text


def _camel_or_space_to_token(value: str) -> str:
    text = re.sub(r"(?<!^)(?=[A-Z])", "_", str(value or ""))
    return text.replace(" ", "_").replace("-", "_")
