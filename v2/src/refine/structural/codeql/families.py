from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Callable, Mapping

from ..shared import (
    _LIFECYCLE_CALL_HINTS,
    _PatchMechanism,
    _calls_match_hints,
    _camel_or_space_to_token,
    _inspect_patch_mechanism,
)
from ....utils.vulnerability_taxonomy import normalize_vulnerability_type


_CATEGORY_TEMPLATE_ALIASES = {
    "stack_overflow": "buffer_overflow",
    "heap_overflow": "buffer_overflow",
    "out_of_bounds_write": "buffer_overflow",
}
_COMMAND_EXECUTION_HINTS = frozenset(
    {"system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve"}
)
_SQL_EXECUTION_HINTS = frozenset({"mysql_query", "sqlite3_exec", "pqexec"})
_PATH_OPEN_HINTS = frozenset({"open", "openat", "fopen", "creat"})
_TOCTOU_CHECK_HINTS = frozenset({"access", "stat", "lstat", "faccessat"})
_BUFFER_OVERREAD_HINTS = frozenset({"memcmp", "memchr", "strnlen", "strncmp"})
_ALLOCATION_HINTS = frozenset({"malloc", "calloc", "realloc", "strdup", "strndup"})


@dataclass(frozen=True)
class _CodeQLSemanticProfile:
    name: str
    priority: int
    family: str
    variant: str
    matches: Callable[[str, _PatchMechanism], bool]


@dataclass(frozen=True)
class _CodeQLFamilyBuilder:
    family: str
    default_variant: str
    variants: Mapping[str, Callable[[_PatchMechanism], str]]
    fallback_pattern_ids: tuple[str, ...] = ()


def build_codeql_structural_candidate(artifact_text: str, patch_text: str) -> str:
    artifact = str(artifact_text or "")
    mechanism = _inspect_patch_mechanism(str(patch_text or ""))
    family, variant = _resolve_family_and_variant(artifact, mechanism)
    if not family:
        return ""

    if not _artifact_needs_family_upgrade(artifact, family, variant):
        return ""

    body = _build_family_candidate(family, variant, mechanism)
    if not body:
        return ""

    name = _extract_header_value("name", artifact) or _default_query_name(family)
    description = (
        _extract_header_value("description", artifact)
        or _default_query_description(family)
    )
    query_id = _extract_header_value("id", artifact) or _default_query_id(family)
    candidate = _with_header(
        query_name=name,
        description=description,
        query_id=query_id,
        body=body,
    )
    return candidate if candidate.strip() and candidate != artifact else ""


def infer_codeql_structural_family(
    artifact_text: str,
    patch_text: str,
) -> str:
    mechanism = _inspect_patch_mechanism(str(patch_text or ""))
    family, _variant = _resolve_family_and_variant(str(artifact_text or ""), mechanism)
    return family


def _resolve_family_and_variant(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> tuple[str, str]:
    profiles = _select_semantic_profiles(artifact_text, mechanism)
    if profiles:
        best = profiles[0]
        return best.family, best.variant

    family = _infer_codeql_category(artifact_text, mechanism)
    if not family:
        return "", ""

    builder = _CODEQL_FAMILY_BUILDERS.get(family)
    if builder is None:
        return family, "pattern"
    return family, builder.default_variant


def _select_semantic_profiles(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> tuple[_CodeQLSemanticProfile, ...]:
    selected = [
        profile
        for profile in _CODEQL_SEMANTIC_PROFILES
        if profile.matches(str(artifact_text or ""), mechanism)
    ]
    selected.sort(key=lambda item: (-item.priority, item.name))
    return tuple(selected)


def _artifact_needs_family_upgrade(
    artifact_text: str,
    family: str,
    variant: str,
) -> bool:
  artifact = str(artifact_text or "")
  if family == "buffer_overflow":
    return not (
      "import semmle.code.cpp.controlflow.Guards" in artifact
      and "writesIntoFixedBuffer" in artifact
      and "destinationCapacityCarrier" in artifact
      and "ensuresLt(" in artifact
      and "getLocation().getStartLine()" not in artifact
    )
  if family == "format_string":
    return not (
      "predicate formatArgument" in artifact
      and "StringLiteral" in artifact
      and "call.getArgument(2)" in artifact
    )
  if family == "race_condition":
    return not (
      "pthread_mutex_lock" in artifact
      and "GlobalVariable" in artifact
      and "hasLockingInFunction" in artifact
    )
  if family == "use_after_free" and variant == "stable_handle_relookup":
    return not (
      "stable-handle relookup" in artifact
      and 'pointerField.getName() + "_id"' in artifact
    )
  if family == "use_after_free":
    return not (
      "clearsReleasedField" in artifact
      and "Released pointer field is not cleared" in artifact
    )
  if family == "command_injection":
    return not (
      "predicate commandArgument" in artifact
      and "StringLiteral" in artifact
      and 'target.hasName("system")' in artifact
    )
  if family == "sql_injection":
    return not (
      "predicate queryArgument" in artifact
      and "StringLiteral" in artifact
      and 'target.hasName("mysql_query")' in artifact
    )
  if family == "path_traversal":
    return not (
      "predicate pathArgument" in artifact
      and "StringLiteral" in artifact
      and 'target.hasName("open")' in artifact
    )
  if family == "memory_leak":
    return not (
      "predicate releasedInFunction" in artifact
      and "escapesThroughReturn" in artifact
      and "PointerType" in artifact
    )
  if family == "double_free":
    return not (
      "predicate releasedVariable" in artifact
      and "reinitializedBetween" in artifact
      and "bbDominates" in artifact
    )
  if family == "toctou":
    return not (
      "predicate samePathValue" in artifact
      and "checkPathArgument" in artifact
      and "bbDominates" in artifact
    )
  if family == "uninitialized_variable":
    return not (
      "LocalVariable" in artifact
      and "predicate hasDominatingInitialization" in artifact
      and "bbDominates" in artifact
    )
  return True


def _build_family_candidate(
    family: str,
    variant: str,
    mechanism: _PatchMechanism,
) -> str:
    builder = _CODEQL_FAMILY_BUILDERS.get(family)
    if builder is None:
        return _select_template_for_family(family)

    render = builder.variants.get(variant) or builder.variants.get(builder.default_variant)
    if render is not None:
        body = str(render(mechanism) or "").strip()
        if body:
            return body

    for pattern_id in builder.fallback_pattern_ids:
        body = _select_pattern_by_id(family, pattern_id)
        if body:
            return body
    return _select_template_for_family(family)


def _extract_header_value(tag: str, artifact_text: str) -> str:
    match = re.search(
        rf"^\s*\*\s*@{re.escape(tag)}\s+(?P<value>.+?)\s*$",
        artifact_text or "",
        flags=re.MULTILINE,
    )
    return str(match.group("value") or "").strip() if match else ""


def _default_query_name(category: str) -> str:
    return {
        "buffer_overflow": "BufferOverflowMissingGuard",
        "null_dereference": "NullDereferenceMissingGuard",
        "use_after_free": "UseAfterFreeDetected",
        "double_free": "DoubleFreeDetected",
        "memory_leak": "MemoryLeakDetected",
        "divide_by_zero": "DivideByZeroDetected",
        "race_condition": "SharedStateRaceDetected",
        "format_string": "NonLiteralFormatString",
        "uninitialized_variable": "UninitializedVariableUse",
        "command_injection": "NonLiteralCommandExecution",
        "sql_injection": "NonLiteralSqlExecution",
        "path_traversal": "UncheckedFilesystemPath",
        "toctou": "PathCheckBeforeUse",
        "out_of_bounds_read": "OutOfBoundsReadDetected",
        "buffer_overread": "BufferOverreadDetected",
        "integer_overflow": "IntegerOverflowDetected",
        "integer_underflow": "IntegerUnderflowDetected",
    }.get(category, "PatchGuidedQuery")


def _default_query_description(category: str) -> str:
    return {
        "buffer_overflow": "Patch-guided buffer overflow query refined around destination bounds and dominating guards.",
        "null_dereference": "Patch-guided null dereference query refined around missing non-null proof.",
        "use_after_free": "Patch-guided use-after-free query refined around stale resource lifetimes.",
        "double_free": "Patch-guided double-free query refined around repeated release of the same resource.",
        "memory_leak": "Patch-guided memory leak query refined around missing cleanup or ownership transfer.",
        "divide_by_zero": "Patch-guided divide-by-zero query refined around missing non-zero guards.",
        "race_condition": "Patch-guided race condition query refined around missing synchronization.",
        "format_string": "Patch-guided format string query refined around non-literal format arguments.",
        "uninitialized_variable": "Patch-guided uninitialized-variable query refined around missing dominating initialization.",
        "command_injection": "Patch-guided command injection query refined around non-literal command arguments.",
        "sql_injection": "Patch-guided SQL injection query refined around non-literal query text.",
        "path_traversal": "Patch-guided path traversal query refined around non-literal filesystem paths.",
        "toctou": "Patch-guided TOCTOU query refined around same-path check-before-use flows.",
        "out_of_bounds_read": "Patch-guided out-of-bounds read query refined around missing bounds proof.",
        "buffer_overread": "Patch-guided buffer overread query refined around read cursor and length semantics.",
        "integer_overflow": "Patch-guided integer overflow query refined around risky arithmetic sinks.",
        "integer_underflow": "Patch-guided integer underflow query refined around risky arithmetic offsets.",
    }.get(category, "Patch-guided structural query.")


def _default_query_id(category: str) -> str:
    return f"cpp/custom/{str(category or '').replace('_', '-')}"


def _infer_codeql_category(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> str:
    query_id = _extract_header_value("id", artifact_text)
    if query_id:
        token = normalize_vulnerability_type(query_id.rsplit("/", 1)[-1], "")
        if token:
            return _CATEGORY_TEMPLATE_ALIASES.get(token, token)

    query_name = _extract_header_value("name", artifact_text)
    if query_name:
        token = normalize_vulnerability_type(_camel_or_space_to_token(query_name), "")
        if token:
            return _CATEGORY_TEMPLATE_ALIASES.get(token, token)

    lowered = str(artifact_text or "").lower()
    if any(token in lowered for token in ("use-after-free", "use after free", "stale", "dangling")):
        return "use_after_free"
    if "double free" in lowered:
        return "double_free"
    if "null" in lowered and "deref" in lowered:
        return "null_dereference"
    if any(token in lowered for token in ("buffer overflow", "fixed-size destination", "fixed-size buffer")):
        return "buffer_overflow"
    if any(token in lowered for token in ("strcpy", "strcat", "memcpy", "memmove", "snprintf", "strncpy")):
        return "buffer_overflow"
    if "divide" in lowered and "zero" in lowered:
        return "divide_by_zero"
    if "race" in lowered or "mutex" in lowered:
        return "race_condition"
    if "format string" in lowered:
        return "format_string"
    if "leak" in lowered:
        return "memory_leak"
    if "uninitialized" in lowered:
        return "uninitialized_variable"
    if "command injection" in lowered or "os command" in lowered:
        return "command_injection"
    if "sql injection" in lowered:
        return "sql_injection"
    if any(token in lowered for token in ("path traversal", "directory traversal")):
        return "path_traversal"
    if any(token in lowered for token in ("toctou", "check-before-use", "time-of-check")):
        return "toctou"
    if any(token in lowered for token in ("buffer overread", "overread")):
        return "buffer_overread"
    if "out-of-bounds read" in lowered or "oob read" in lowered:
        return "out_of_bounds_read"
    if "integer overflow" in lowered:
        return "integer_overflow"
    if "integer underflow" in lowered:
        return "integer_underflow"

    call_hints = mechanism.removed_calls | mechanism.added_calls
    if (
        _calls_match_hints(call_hints, _TOCTOU_CHECK_HINTS)
        and _calls_match_hints(call_hints, _PATH_OPEN_HINTS)
    ):
        return "toctou"
    if _calls_match_hints(call_hints, _COMMAND_EXECUTION_HINTS):
        return "command_injection"
    if _calls_match_hints(call_hints, _SQL_EXECUTION_HINTS):
        return "sql_injection"
    if _calls_match_hints(call_hints, _PATH_OPEN_HINTS):
        return "path_traversal"
    if _calls_match_hints(call_hints, _BUFFER_OVERREAD_HINTS):
        return "buffer_overread"
    if _calls_match_hints(call_hints, _ALLOCATION_HINTS) and not _calls_match_hints(
        call_hints,
        _LIFECYCLE_CALL_HINTS,
    ):
        return "memory_leak"

    if mechanism.has_locking_change:
        return "race_condition"
    if _calls_match_hints(mechanism.removed_calls, _LIFECYCLE_CALL_HINTS):
        return "use_after_free" if (mechanism.has_revalidation_lookup or mechanism.has_state_reset) else "double_free"
    if mechanism.has_zero_guard:
        return "divide_by_zero"
    if mechanism.has_null_guard:
        return "null_dereference"
    if mechanism.has_capacity_guard or mechanism.has_status_guard or mechanism.has_bounded_formatting_guard:
        return "buffer_overflow"
    return ""


def _looks_like_buffer_guarded_transfer(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    family = _infer_codeql_category(artifact_text, mechanism)
    if family != "buffer_overflow":
        return False
    return (
        mechanism.has_capacity_guard
        or mechanism.has_bounded_formatting_guard
        or mechanism.has_strlen_binding
        or mechanism.has_length_derived_copy
        or any(api in str(artifact_text or "").lower() for api in ("strcpy", "memcpy", "snprintf"))
    )


def _looks_like_stable_handle_relookup(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    return (
        _infer_codeql_category(artifact_text, mechanism) == "use_after_free"
        and (mechanism.has_revalidation_lookup or mechanism.has_state_reset)
    )


def _looks_like_local_use_after_free(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    return _infer_codeql_category(artifact_text, mechanism) == "use_after_free"


def _looks_like_locking_discipline(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    return (
        _infer_codeql_category(artifact_text, mechanism) == "race_condition"
        or mechanism.has_locking_change
    )


def _looks_like_literal_format_contract(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    return _infer_codeql_category(artifact_text, mechanism) == "format_string"


@lru_cache(maxsize=1)
def _load_pattern_templates() -> dict[str, list[dict[str, str]]]:
    base = Path(__file__).resolve().parents[4]
    raw = json.loads(
        (base / "data/knowledge/codeql/ql_patterns.json").read_text(encoding="utf-8")
    )
    grouped: dict[str, list[dict[str, str]]] = {}
    for item in raw:
        category = str(item.get("category", "") or "").strip()
        if not category:
            continue
        grouped.setdefault(category, []).append(
            {
                "id": str(item.get("id", "") or "").strip(),
                "template": str(item.get("template", "") or "").strip(),
            }
        )
    return grouped


def _select_template_for_family(family: str) -> str:
    templates = _load_pattern_templates().get(family, [])
    if not templates:
        return ""
    return str(templates[0].get("template", "") or "").strip()


def _select_pattern_by_id(category: str, pattern_id: str) -> str:
    for item in _load_pattern_templates().get(category, []):
        if item.get("id") == pattern_id:
            return str(item.get("template", "") or "").strip()
    return ""


def _with_header(
    query_name: str,
    description: str,
    query_id: str,
    body: str,
) -> str:
    normalized_body = str(body or "").strip()
    if not normalized_body:
        return ""
    return f"""/**
 * @name {query_name}
 * @description {description}
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id {query_id}
 * @tags security
 *       correctness
 */

{normalized_body}
"""


def _render_buffer_overflow_template(mechanism: _PatchMechanism) -> str:
    return _BUFFER_OVERFLOW_TEMPLATE


def _render_format_string_template(mechanism: _PatchMechanism) -> str:
    return _FORMAT_STRING_TEMPLATE


def _render_race_condition_template(mechanism: _PatchMechanism) -> str:
    return _RACE_CONDITION_TEMPLATE


def _render_use_after_free_local_template(mechanism: _PatchMechanism) -> str:
    return _USE_AFTER_FREE_LOCAL_TEMPLATE


def _render_use_after_free_relookup_template(mechanism: _PatchMechanism) -> str:
    return _select_pattern_by_id(
        "use_after_free",
        "use-after-free-stable-handle-relookup-pattern",
    )


def _render_command_injection_template(mechanism: _PatchMechanism) -> str:
    return _COMMAND_INJECTION_TEMPLATE


def _render_sql_injection_template(mechanism: _PatchMechanism) -> str:
    return _SQL_INJECTION_TEMPLATE


def _render_path_traversal_template(mechanism: _PatchMechanism) -> str:
    return _PATH_TRAVERSAL_TEMPLATE


def _render_memory_leak_template(mechanism: _PatchMechanism) -> str:
    return _MEMORY_LEAK_TEMPLATE


def _render_double_free_template(mechanism: _PatchMechanism) -> str:
    return _DOUBLE_FREE_TEMPLATE


def _render_toctou_template(mechanism: _PatchMechanism) -> str:
    return _TOCTOU_TEMPLATE


def _render_uninitialized_variable_template(mechanism: _PatchMechanism) -> str:
    return _UNINITIALIZED_VARIABLE_TEMPLATE


_BUFFER_OVERFLOW_TEMPLATE = """import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance

predicate isUnboundedWriteTarget(Function target) {
  target.hasName("strcpy") or
  target.hasName("strcat") or
  target.hasName("gets") or
  target.hasName("sprintf")
}

predicate isLengthBoundWriteTarget(Function target) {
  target.hasName("memcpy") or
  target.hasName("memmove") or
  target.hasName("strncpy") or
  target.hasName("strncat")
}

predicate isFormattingWriteTarget(Function target) {
  target.hasName("snprintf") or
  target.hasName("vsnprintf")
}

predicate destinationExpr(FunctionCall call, Expr dest) {
  dest = call.getArgument(0)
}

predicate exprContainsVariableAccess(Expr root, VariableAccess access) {
  access = root or root.getAChild*() = access
}

predicate exprContainsFieldAccess(Expr root, FieldAccess access) {
  access = root or root.getAChild*() = access
}

predicate sameValueExpr(Expr left, Expr right) {
  left = right
  or
  exists(VariableAccess l, VariableAccess r |
    exprContainsVariableAccess(left, l) and
    exprContainsVariableAccess(right, r) and
    l.getTarget() = r.getTarget()
  )
  or
  exists(FieldAccess l, FieldAccess r |
    exprContainsFieldAccess(left, l) and
    exprContainsFieldAccess(right, r) and
    l.getTarget() = r.getTarget() and
    sameValueExpr(l.getQualifier(), r.getQualifier())
  )
}

predicate writesIntoFixedBuffer(FunctionCall call, Expr dest) {
  destinationExpr(call, dest) and
  (
    exists(VariableAccess dst, Variable v |
      exprContainsVariableAccess(dest, dst) and
      v = dst.getTarget() and
      v.getType() instanceof ArrayType
    )
    or
    exists(FieldAccess dst, Field f |
      exprContainsFieldAccess(dest, dst) and
      f = dst.getTarget() and
      f.getType() instanceof ArrayType
    )
  )
}

predicate sourceExpr(FunctionCall call, Expr src) {
  exists(Function target |
    target = call.getTarget() and
    (
      (
        target.hasName("strcpy") or
        target.hasName("strcat") or
        target.hasName("memcpy") or
        target.hasName("memmove") or
        target.hasName("strncpy") or
        target.hasName("strncat")
      ) and
      src = call.getArgument(1)
    )
  )
}

predicate explicitBoundArg(FunctionCall call, Expr bound) {
  exists(Function target |
    target = call.getTarget() and
    (
      isLengthBoundWriteTarget(target) and
      bound = call.getArgument(2)
      or
      isFormattingWriteTarget(target) and
      bound = call.getArgument(1)
    )
  )
}

predicate isSourceLengthMeasurement(Expr expr, Expr src) {
  exists(FunctionCall lenCall, Function target |
    expr = lenCall and
    target = lenCall.getTarget() and
    (target.hasName("strlen") or target.hasName("strnlen")) and
    sameValueExpr(lenCall.getArgument(0), src)
  )
}

predicate dominatingAssignedValue(VariableAccess access, Expr value, FunctionCall call) {
  access.getEnclosingFunction() = call.getEnclosingFunction() and
  access.getTarget().getAnAssignedValue() = value and
  value.getEnclosingFunction() = call.getEnclosingFunction() and
  bbDominates(value.getBasicBlock(), call.getBasicBlock())
}

predicate trackedLengthExpr(FunctionCall call, Expr measured) {
  explicitBoundArg(call, measured)
  or
  exists(Expr src |
    sourceExpr(call, src) and
    isSourceLengthMeasurement(measured, src)
  )
  or
  exists(VariableAccess access, Expr value, Expr src |
    sourceExpr(call, src) and
    dominatingAssignedValue(access, value, call) and
    isSourceLengthMeasurement(value, src) and
    (
      measured = access
      or
      exists(Expr bound |
        explicitBoundArg(call, bound) and
        bound.getAChild*() = access and
        measured = access
      )
    )
  )
}

predicate isDestinationCapacityExpr(Expr expr, Expr dest) {
  exists(SizeofExprOperator sizeOf |
    expr = sizeOf and
    sameValueExpr(sizeOf.getExprOperand(), dest)
  )
}

predicate destinationCapacityCarrier(FunctionCall call, Expr capacity) {
  exists(Expr dest |
    destinationExpr(call, dest) and
    (
      isDestinationCapacityExpr(capacity, dest)
      or
      exists(VariableAccess access, Expr value |
        dominatingAssignedValue(access, value, call) and
        isDestinationCapacityExpr(value, dest) and
        capacity = access
      )
    )
  )
}

predicate explicitBoundMatchesDestinationCapacity(FunctionCall call) {
  exists(Expr bound, Expr capacity |
    explicitBoundArg(call, bound) and
    destinationCapacityCarrier(call, capacity) and
    sameValueExpr(bound, capacity)
  )
}

predicate hasPatchStyleBoundsGuard(FunctionCall call) {
  exists(Expr measured, Expr capacity, GuardCondition guard |
    trackedLengthExpr(call, measured) and
    destinationCapacityCarrier(call, capacity) and
    (
      guard.ensuresLt(measured, capacity, 0, call.getBasicBlock(), true)
      or
      guard.ensuresLt(measured, capacity, 1, call.getBasicBlock(), true)
    )
  )
}

from FunctionCall call, Function target, Expr dest, string message
where
  target = call.getTarget() and
  writesIntoFixedBuffer(call, dest) and
  (
    target.hasName("gets") and
    message = "Fixed-size destination is passed to gets without any destination-capacity contract."
    or
    isUnboundedWriteTarget(target) and
    not target.hasName("gets") and
    not hasPatchStyleBoundsGuard(call) and
    message = "Unbounded write into a fixed-size destination is not dominated by a destination-capacity guard."
    or
    isLengthBoundWriteTarget(target) and
    not explicitBoundMatchesDestinationCapacity(call) and
    not hasPatchStyleBoundsGuard(call) and
    message = "Length-driven write into a fixed-size destination is not tied to the destination capacity or a dominating bounds guard."
    or
    isFormattingWriteTarget(target) and
    not explicitBoundMatchesDestinationCapacity(call) and
    not hasPatchStyleBoundsGuard(call) and
    message = "Formatting write into a fixed-size destination uses a size argument that is not tied to the destination capacity."
  )
select call, message
"""


_FORMAT_STRING_TEMPLATE = """import cpp

predicate formatArgument(FunctionCall call, Expr fmtArg) {
  exists(Function target |
    target = call.getTarget() and
    (
      (target.hasName("printf") or target.hasName("sprintf") or target.hasName("vprintf")) and
      fmtArg = call.getArgument(0)
      or
      (target.hasName("fprintf")) and
      fmtArg = call.getArgument(1)
      or
      (target.hasName("snprintf") or target.hasName("vsnprintf")) and
      fmtArg = call.getArgument(2)
    )
  )
}

from FunctionCall call, Expr fmtArg
where
  formatArgument(call, fmtArg) and
  not fmtArg instanceof StringLiteral
select call, "Non-literal format string reaches a formatting sink without a literal format contract."
"""


_RACE_CONDITION_TEMPLATE = """import cpp

predicate hasLockingInFunction(Function f) {
  exists(FunctionCall lockCall, Function target |
    lockCall.getEnclosingFunction() = f and
    target = lockCall.getTarget() and
    (
      target.hasName("pthread_mutex_lock") or
      target.hasName("pthread_rwlock_rdlock") or
      target.hasName("pthread_rwlock_wrlock") or
      target.hasName("mtx_lock")
    )
  ) and
  exists(FunctionCall unlockCall, Function target |
    unlockCall.getEnclosingFunction() = f and
    target = unlockCall.getTarget() and
    (
      target.hasName("pthread_mutex_unlock") or
      target.hasName("pthread_rwlock_unlock") or
      target.hasName("mtx_unlock")
    )
  )
}

from AssignExpr assign, VariableAccess access, Variable targetVar, Function f
where
  assign.getEnclosingFunction() = f and
  access = assign.getLValue() and
  targetVar = access.getTarget() and
  targetVar instanceof GlobalVariable and
  not hasLockingInFunction(f)
select assign, "Shared global state is written without an observed synchronization barrier."
"""


_USE_AFTER_FREE_LOCAL_TEMPLATE = """import cpp

predicate isReleasedPointerField(FieldAccess fieldAccess) {
  fieldAccess.getTarget().getType() instanceof PointerType
}

predicate sameBaseVariable(FieldAccess left, FieldAccess right) {
  exists(VariableAccess leftBase, VariableAccess rightBase |
    leftBase = left.getQualifier() and
    rightBase = right.getQualifier() and
    leftBase.getTarget() = rightBase.getTarget()
  )
}

predicate nullLikeExpr(Expr expr) {
  expr.isConstant() and expr.getValue() = "0"
}

predicate clearsReleasedField(FieldAccess releasedField) {
  exists(AssignExpr assign, FieldAccess lhs |
    lhs = assign.getLValue() and
    isReleasedPointerField(lhs) and
    lhs.getEnclosingFunction() = releasedField.getEnclosingFunction() and
    lhs.getTarget() = releasedField.getTarget() and
    sameBaseVariable(lhs, releasedField) and
    nullLikeExpr(assign.getRValue())
  )
}

from Expr node, string message
where
  (
    exists(FunctionCall releaseCall, FieldAccess releasedField, Function target |
      target = releaseCall.getTarget() and
      releaseCall.getNumberOfArguments() >= 1 and
      releasedField = releaseCall.getArgument(0) and
      isReleasedPointerField(releasedField) and
      (
        target.hasName("free") or
        target.hasName("destroy_session") or
        target.hasName("release")
      ) and
      not clearsReleasedField(releasedField) and
      node = releaseCall and
      message = "Released pointer field is not cleared, leaving a stale alias behind."
    )
    or
    exists(FunctionCall releaseCall, FieldAccess freedField, FieldAccess receiver, FieldAccess use, Function target |
      target = releaseCall.getTarget() and
      releaseCall.getNumberOfArguments() >= 1 and
      freedField = releaseCall.getArgument(0) and
      isReleasedPointerField(freedField) and
      (
        target.hasName("free") or
        target.hasName("destroy_session") or
        target.hasName("release")
      ) and
      not clearsReleasedField(freedField) and
      receiver = use.getQualifier() and
      isReleasedPointerField(receiver) and
      receiver.getTarget() = freedField.getTarget() and
      sameBaseVariable(receiver, freedField) and
      node = use and
      message = "Potential use-after-free: cached pointer field may be dereferenced after an uncleared release path."
    )
  )
select node, message
"""


_COMMAND_INJECTION_TEMPLATE = """import cpp

predicate isCommandExecutionTarget(Function target) {
  target.hasName("system") or
  target.hasName("popen") or
  target.hasName("execl") or
  target.hasName("execlp") or
  target.hasName("execle") or
  target.hasName("execv") or
  target.hasName("execvp") or
  target.hasName("execve")
}

predicate commandArgument(FunctionCall call, Expr command) {
  exists(Function target |
    target = call.getTarget() and
    isCommandExecutionTarget(target) and
    command = call.getArgument(0)
  )
}

from FunctionCall call, Expr command
where
  commandArgument(call, command) and
  not command instanceof StringLiteral
select call, "Non-literal command or executable path reaches an OS command execution sink."
"""


_SQL_INJECTION_TEMPLATE = """import cpp

predicate queryArgument(FunctionCall call, Expr queryText) {
  exists(Function target |
    target = call.getTarget() and
    (
      target.hasName("mysql_query") and
      queryText = call.getArgument(1)
      or
      target.hasName("sqlite3_exec") and
      queryText = call.getArgument(1)
      or
      target.hasName("PQexec") and
      queryText = call.getArgument(1)
    )
  )
}

from FunctionCall call, Expr queryText
where
  queryArgument(call, queryText) and
  not queryText instanceof StringLiteral
select call, "Non-literal SQL text reaches an execution API without a parameterization boundary."
"""


_PATH_TRAVERSAL_TEMPLATE = """import cpp

predicate pathArgument(FunctionCall call, Expr pathExpr) {
  exists(Function target |
    target = call.getTarget() and
    (
      (
        target.hasName("open") or
        target.hasName("fopen") or
        target.hasName("creat")
      ) and
      pathExpr = call.getArgument(0)
      or
      target.hasName("openat") and
      pathExpr = call.getArgument(1)
    )
  )
}

from FunctionCall call, Expr pathExpr
where
  pathArgument(call, pathExpr) and
  not pathExpr instanceof StringLiteral
select call, "Non-literal filesystem path reaches an open/create sink without a canonicalization or root-boundary proof."
"""


_MEMORY_LEAK_TEMPLATE = """import cpp

predicate isAllocationTarget(Function target) {
  target.hasName("malloc") or
  target.hasName("calloc") or
  target.hasName("realloc") or
  target.hasName("strdup") or
  target.hasName("strndup")
}

predicate isReleaseTarget(Function target) {
  target.hasName("free") or
  target.hasName("kfree") or
  target.hasName("delete") or
  target.hasName("release")
}

predicate allocatedVariable(FunctionCall allocCall, Variable v) {
  exists(Function target, VariableAccess binding |
    target = allocCall.getTarget() and
    isAllocationTarget(target) and
    binding.getTarget() = v and
    v.getAnAssignedValue() = allocCall and
    binding.getEnclosingFunction() = allocCall.getEnclosingFunction() and
    v.getType() instanceof PointerType
  )
}

predicate releasedInFunction(Variable v, Function f) {
  exists(FunctionCall releaseCall, Function target, VariableAccess released |
    releaseCall.getEnclosingFunction() = f and
    target = releaseCall.getTarget() and
    isReleaseTarget(target) and
    released = releaseCall.getArgument(0) and
    released.getTarget() = v
  )
}

predicate escapesThroughReturn(Variable v, Function f) {
  exists(ReturnStmt ret, VariableAccess returned |
    ret.getEnclosingFunction() = f and
    returned = ret.getExpr() and
    returned.getTarget() = v
  )
}

from FunctionCall allocCall, Variable v, Function f
where
  allocatedVariable(allocCall, v) and
  f = allocCall.getEnclosingFunction() and
  not releasedInFunction(v, f) and
  not escapesThroughReturn(v, f)
select allocCall, "Allocated pointer stored in " + v.getName() + " is not released or returned from this function."
"""


_DOUBLE_FREE_TEMPLATE = """import cpp
import semmle.code.cpp.controlflow.Dominance

predicate isReleaseTarget(Function target) {
  target.hasName("free") or
  target.hasName("kfree") or
  target.hasName("delete") or
  target.hasName("release") or
  target.hasName("destroy")
}

predicate releasedVariable(FunctionCall call, Variable v) {
  exists(Function target, VariableAccess released |
    target = call.getTarget() and
    isReleaseTarget(target) and
    released = call.getArgument(0) and
    released.getTarget() = v
  )
}

predicate reinitializedBetween(Variable v, FunctionCall first, FunctionCall second) {
  exists(Expr value |
    v.getAnAssignedValue() = value and
    value.getEnclosingFunction() = first.getEnclosingFunction() and
    bbDominates(first.getBasicBlock(), value.getBasicBlock()) and
    bbDominates(value.getBasicBlock(), second.getBasicBlock())
  )
}

from FunctionCall first, FunctionCall second, Variable v
where
  releasedVariable(first, v) and
  releasedVariable(second, v) and
  first != second and
  first.getEnclosingFunction() = second.getEnclosingFunction() and
  bbDominates(first.getBasicBlock(), second.getBasicBlock()) and
  not reinitializedBetween(v, first, second)
select second, "Second release of " + v.getName() + " is reachable without an intervening reinitialization."
"""


_TOCTOU_TEMPLATE = """import cpp
import semmle.code.cpp.controlflow.Dominance

predicate exprContainsVariableAccess(Expr root, VariableAccess access) {
  access = root or root.getAChild*() = access
}

predicate exprContainsFieldAccess(Expr root, FieldAccess access) {
  access = root or root.getAChild*() = access
}

predicate samePathValue(Expr left, Expr right) {
  left = right
  or
  exists(VariableAccess l, VariableAccess r |
    exprContainsVariableAccess(left, l) and
    exprContainsVariableAccess(right, r) and
    l.getTarget() = r.getTarget()
  )
  or
  exists(FieldAccess l, FieldAccess r |
    exprContainsFieldAccess(left, l) and
    exprContainsFieldAccess(right, r) and
    l.getTarget() = r.getTarget() and
    samePathValue(l.getQualifier(), r.getQualifier())
  )
}

predicate isPathCheckTarget(Function target) {
  target.hasName("access") or
  target.hasName("stat") or
  target.hasName("lstat") or
  target.hasName("faccessat")
}

predicate isPathUseTarget(Function target) {
  target.hasName("open") or
  target.hasName("openat") or
  target.hasName("fopen") or
  target.hasName("creat")
}

predicate checkPathArgument(FunctionCall call, Expr pathExpr) {
  exists(Function target |
    target = call.getTarget() and
    isPathCheckTarget(target) and
    pathExpr = call.getArgument(0)
  )
}

predicate usePathArgument(FunctionCall call, Expr pathExpr) {
  exists(Function target |
    target = call.getTarget() and
    (
      (
        target.hasName("open") or
        target.hasName("fopen") or
        target.hasName("creat")
      ) and
      pathExpr = call.getArgument(0)
      or
      target.hasName("openat") and
      pathExpr = call.getArgument(1)
    )
  )
}

from FunctionCall checkCall, FunctionCall useCall, Expr checkedPath, Expr usedPath
where
  checkPathArgument(checkCall, checkedPath) and
  usePathArgument(useCall, usedPath) and
  checkCall.getEnclosingFunction() = useCall.getEnclosingFunction() and
  samePathValue(checkedPath, usedPath) and
  bbDominates(checkCall.getBasicBlock(), useCall.getBasicBlock())
select useCall, "Path is checked before use without an atomic open-or-validate contract."
"""


_UNINITIALIZED_VARIABLE_TEMPLATE = """import cpp
import semmle.code.cpp.controlflow.Dominance

predicate candidateLocal(LocalVariable v) {
  not v.hasInitializer() and
  (
    v.getType() instanceof IntegralType or
    v.getType() instanceof PointerType
  )
}

predicate isReadAccess(VariableAccess access) {
  not exists(AssignExpr assign |
    access = assign.getLValue()
  )
}

predicate hasDominatingInitialization(LocalVariable v, VariableAccess use) {
  exists(Expr value |
    v.getAnAssignedValue() = value and
    value.getEnclosingFunction() = use.getEnclosingFunction() and
    bbDominates(value.getBasicBlock(), use.getBasicBlock())
  )
}

from VariableAccess use, LocalVariable v
where
  v = use.getTarget() and
  candidateLocal(v) and
  isReadAccess(use) and
  not hasDominatingInitialization(v, use)
select use, "Local variable " + v.getName() + " is read without a dominating initialization."
"""


_CODEQL_SEMANTIC_PROFILES = (
    _CodeQLSemanticProfile(
        name="buffer_guarded_transfer",
        priority=100,
        family="buffer_overflow",
        variant="guarded_transfer",
        matches=_looks_like_buffer_guarded_transfer,
    ),
    _CodeQLSemanticProfile(
        name="stable_handle_relookup",
        priority=95,
        family="use_after_free",
        variant="stable_handle_relookup",
        matches=_looks_like_stable_handle_relookup,
    ),
    _CodeQLSemanticProfile(
        name="locking_discipline",
        priority=90,
        family="race_condition",
        variant="locking_discipline",
        matches=_looks_like_locking_discipline,
    ),
    _CodeQLSemanticProfile(
        name="literal_format_contract",
        priority=85,
        family="format_string",
        variant="literal_format_contract",
        matches=_looks_like_literal_format_contract,
    ),
    _CodeQLSemanticProfile(
        name="local_use_after_free",
        priority=80,
        family="use_after_free",
        variant="local_release_alias",
        matches=_looks_like_local_use_after_free,
    ),
)


_CODEQL_FAMILY_BUILDERS = {
    "buffer_overflow": _CodeQLFamilyBuilder(
        family="buffer_overflow",
        default_variant="guarded_transfer",
        variants={
            "guarded_transfer": _render_buffer_overflow_template,
        },
        fallback_pattern_ids=("unsafe-buffer-write-pattern",),
    ),
    "format_string": _CodeQLFamilyBuilder(
        family="format_string",
        default_variant="literal_format_contract",
        variants={
            "literal_format_contract": _render_format_string_template,
        },
        fallback_pattern_ids=("nonliteral-format-string-pattern",),
    ),
    "use_after_free": _CodeQLFamilyBuilder(
        family="use_after_free",
        default_variant="local_release_alias",
        variants={
            "stable_handle_relookup": _render_use_after_free_relookup_template,
            "local_release_alias": _render_use_after_free_local_template,
        },
        fallback_pattern_ids=("use-after-free-stable-handle-relookup-pattern",),
    ),
    "race_condition": _CodeQLFamilyBuilder(
        family="race_condition",
        default_variant="locking_discipline",
        variants={
            "locking_discipline": _render_race_condition_template,
        },
        fallback_pattern_ids=("shared-state-write-without-lock-pattern",),
    ),
    "command_injection": _CodeQLFamilyBuilder(
        family="command_injection",
        default_variant="nonliteral_command",
        variants={
            "nonliteral_command": _render_command_injection_template,
        },
        fallback_pattern_ids=("command-injection-sink-pattern",),
    ),
    "sql_injection": _CodeQLFamilyBuilder(
        family="sql_injection",
        default_variant="nonliteral_query",
        variants={
            "nonliteral_query": _render_sql_injection_template,
        },
        fallback_pattern_ids=("sql-injection-execution-pattern",),
    ),
    "path_traversal": _CodeQLFamilyBuilder(
        family="path_traversal",
        default_variant="nonliteral_path",
        variants={
            "nonliteral_path": _render_path_traversal_template,
        },
        fallback_pattern_ids=("path-traversal-sink-pattern",),
    ),
    "memory_leak": _CodeQLFamilyBuilder(
        family="memory_leak",
        default_variant="unreleased_local_allocation",
        variants={
            "unreleased_local_allocation": _render_memory_leak_template,
        },
        fallback_pattern_ids=("memory-leak-allocation-pattern",),
    ),
    "double_free": _CodeQLFamilyBuilder(
        family="double_free",
        default_variant="repeated_release_without_reinit",
        variants={
            "repeated_release_without_reinit": _render_double_free_template,
        },
        fallback_pattern_ids=("double-free-sequence-pattern",),
    ),
    "toctou": _CodeQLFamilyBuilder(
        family="toctou",
        default_variant="same_path_check_then_use",
        variants={
            "same_path_check_then_use": _render_toctou_template,
        },
        fallback_pattern_ids=("toctou-file-pattern",),
    ),
    "uninitialized_variable": _CodeQLFamilyBuilder(
        family="uninitialized_variable",
        default_variant="missing_dominating_init",
        variants={
            "missing_dominating_init": _render_uninitialized_variable_template,
        },
        fallback_pattern_ids=("uninitialized-variable-read-pattern",),
    ),
    "null_dereference": _CodeQLFamilyBuilder(
        family="null_dereference",
        default_variant="pattern",
        variants={},
        fallback_pattern_ids=("null-dereference-proof-gap-pattern",),
    ),
    "divide_by_zero": _CodeQLFamilyBuilder(
        family="divide_by_zero",
        default_variant="pattern",
        variants={},
        fallback_pattern_ids=("divide-by-zero-pattern",),
    ),
    "out_of_bounds_read": _CodeQLFamilyBuilder(
        family="out_of_bounds_read",
        default_variant="pattern",
        variants={},
        fallback_pattern_ids=("out-of-bounds-read-index-pattern",),
    ),
    "buffer_overread": _CodeQLFamilyBuilder(
        family="buffer_overread",
        default_variant="pattern",
        variants={},
        fallback_pattern_ids=("buffer-overread-cursor-pattern",),
    ),
    "integer_overflow": _CodeQLFamilyBuilder(
        family="integer_overflow",
        default_variant="pattern",
        variants={},
        fallback_pattern_ids=("integer-overflow-sink-pattern",),
    ),
    "integer_underflow": _CodeQLFamilyBuilder(
        family="integer_underflow",
        default_variant="pattern",
        variants={},
        fallback_pattern_ids=("integer-underflow-offset-pattern",),
    ),
}
