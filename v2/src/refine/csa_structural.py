from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

from .structural.csa.families import build_csa_family_candidate as _build_csa_family_candidate
from .structural.shared import (
    _LIFECYCLE_CALL_HINTS,
    _PatchMechanism,
    _calls_match_hints,
    _inspect_patch_mechanism,
)


def build_csa_structural_candidate(artifact_text: str, patch_text: str) -> str:
    artifact = str(artifact_text or "")
    mechanism = _inspect_patch_mechanism(str(patch_text or ""))
    profiles = _select_semantic_profiles(artifact, mechanism)

    candidate = artifact
    if profiles:
        primitive_names = _selected_primitive_names(profiles)
        for primitive_name in primitive_names:
            primitive = _REPAIR_PRIMITIVES_BY_NAME[primitive_name]
            if not primitive.matches(candidate, mechanism):
                continue
            updated = primitive.apply(candidate, mechanism)
            if updated:
                candidate = updated

    candidate = _normalize_candidate_formatting(candidate)
    if candidate != artifact:
        if not _candidate_needs_family_completion(candidate, profiles):
            return candidate
        artifact = candidate

    family_candidate = _build_csa_family_candidate(artifact, mechanism)
    if not family_candidate:
        return ""
    return _normalize_candidate_formatting(family_candidate)


def _select_semantic_profile_names(artifact_text: str, patch_text: str) -> tuple[str, ...]:
    artifact = str(artifact_text or "")
    mechanism = _inspect_patch_mechanism(str(patch_text or ""))
    return tuple(profile.name for profile in _select_semantic_profiles(artifact, mechanism))


@dataclass(frozen=True)
class _RepairPrimitive:
    name: str
    matches: Callable[[str, "_PatchMechanism"], bool]
    apply: Callable[[str, "_PatchMechanism"], str]


@dataclass(frozen=True)
class _SemanticProfile:
    name: str
    priority: int
    matches: Callable[[str, "_PatchMechanism"], bool]
    primitive_names: tuple[str, ...] = ()


_UNSAFE_STRING_APIS = frozenset({"strcpy", "strcat"})
_CAPACITY_BOUND_APIS = frozenset({"memcpy", "memmove", "snprintf", "strncpy", "strncat"})
_STATUS_GUARDED_APIS = frozenset({"snprintf", "vsnprintf", "write", "send", "recv", "read", "fwrite"})


def _select_semantic_profiles(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> tuple[_SemanticProfile, ...]:
    artifact = str(artifact_text or "")
    selected = [
        profile
        for profile in _SEMANTIC_PROFILES
        if profile.matches(artifact, mechanism)
    ]
    selected.sort(key=lambda item: (-item.priority, item.name))
    return tuple(selected)


def _selected_primitive_names(profiles: tuple[_SemanticProfile, ...]) -> tuple[str, ...]:
    ordered: list[str] = []
    for profile in profiles:
        for primitive_name in profile.primitive_names:
            if primitive_name not in ordered:
                ordered.append(primitive_name)
    return tuple(ordered)


_CSA_REQUIRED_DEFINITION_PATTERNS = {
    "checkUnsafeStringOperation": re.compile(r"\bvoid\s+checkUnsafeStringOperation\s*\("),
    "checkMemcpyOperation": re.compile(r"\bvoid\s+checkMemcpyOperation\s*\("),
    "checkStatusOperation": re.compile(r"\bvoid\s+checkStatusOperation\s*\("),
    "getStaticDestinationBytes": re.compile(
        r"\bstd::optional\s*<\s*uint64_t\s*>\s+getStaticDestinationBytes\s*\("
    ),
    "hasSameBlockMemcpyBarrier": re.compile(r"\bbool\s+hasSameBlockMemcpyBarrier\s*\("),
    "hasSameBlockStatusBarrier": re.compile(r"\bbool\s+hasSameBlockStatusBarrier\s*\("),
}


def _has_required_helper_definitions(candidate: str, helper_names: tuple[str, ...]) -> bool:
    source = str(candidate or "")
    return all(
        _CSA_REQUIRED_DEFINITION_PATTERNS[helper_name].search(source)
        for helper_name in helper_names
    )


def _candidate_needs_family_completion(
    candidate: str,
    profiles: tuple[_SemanticProfile, ...],
) -> bool:
    profile_names = {profile.name for profile in profiles}
    if "buffer_guarded_write" in profile_names:
        required_helpers = (
            "checkUnsafeStringOperation",
            "checkMemcpyOperation",
            "getStaticDestinationBytes",
            "hasSameBlockMemcpyBarrier",
        )
        if not _has_required_helper_definitions(candidate, required_helpers):
            return True
    if "checked_status_guard" in profile_names:
        required_helpers = (
            "checkStatusOperation",
            "hasSameBlockStatusBarrier",
        )
        if not _has_required_helper_definitions(candidate, required_helpers):
            return True
    return False


def _looks_like_size_guarded_write_pattern(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    artifact = str(artifact_text or "")
    removed_unbounded = mechanism.removed_calls & (_UNSAFE_STRING_APIS | {"sprintf", "memcpy", "memmove"})
    added_bounded = mechanism.added_calls & _CAPACITY_BOUND_APIS
    handles_copy_family = bool(
        mechanism.removed_calls & _UNSAFE_STRING_APIS
        or mechanism.has_length_derived_copy
        or {"memcpy", "memmove"} & mechanism.removed_calls
        or {"memcpy", "memmove"} & mechanism.added_calls
    )
    return (
        bool(removed_unbounded)
        and bool(added_bounded)
        and (mechanism.has_capacity_guard or mechanism.has_bounded_formatting_guard)
        and handles_copy_family
        and "checkPreCall" in artifact
    )


def _looks_like_checked_status_guard_pattern(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    artifact = str(artifact_text or "")
    return (
        mechanism.has_status_guard
        and "checkPreCall" in artifact
        and any(api in mechanism.added_calls for api in _STATUS_GUARDED_APIS)
    )


def _looks_like_lifecycle_revalidation_pattern(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    artifact = str(artifact_text or "")
    return (
        _calls_match_hints(mechanism.removed_calls, _LIFECYCLE_CALL_HINTS)
        and (mechanism.has_revalidation_lookup or mechanism.has_null_guard or mechanism.has_state_reset)
        and "checkPreCall" in artifact
    )


def _looks_like_synchronization_guard_pattern(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> bool:
    artifact = str(artifact_text or "")
    return mechanism.has_locking_change and "checkPreCall" in artifact


def _apply_capacity_support_includes(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    candidate = artifact
    candidate = _ensure_include(
        candidate,
        '#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"\n',
        after='#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"\n',
    )
    candidate = _ensure_include(
        candidate,
        '#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"\n',
        after='#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"\n',
    )
    candidate = _ensure_include(
        candidate,
        '#include "clang/AST/ASTContext.h"\n',
        after='#include "clang/AST/Expr.h"\n',
    )
    candidate = _ensure_include(
        candidate,
        '#include "clang/AST/ParentMapContext.h"\n',
        after='#include "clang/AST/ASTContext.h"\n',
    )
    candidate = _ensure_include(
        candidate,
        '#include "clang/AST/Type.h"\n',
        after='#include "clang/AST/Stmt.h"\n',
    )
    candidate = _ensure_include(
        candidate,
        "#include <vector>\n",
        after="#include <string>\n",
    )
    return candidate


def _apply_semantic_ast_includes(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _apply_capacity_support_includes(artifact, mechanism)


def _apply_buffer_dispatch_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _replace_function(artifact, "checkPreCall", _build_precall_function(mechanism))


def _apply_semantic_dispatch_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _replace_function(artifact, "checkPreCall", _build_precall_function(mechanism))


def _apply_buffer_string_checker_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _replace_function(artifact, "checkUnsafeStringOperation", _CHECK_UNSAFE_STRING)


def _apply_buffer_memcpy_checker_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _replace_function(artifact, "checkMemcpyOperation", _CHECK_MEMCPY)


def _apply_status_checker_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _upsert_function_before_report_bug(
        artifact,
        "checkStatusOperation",
        _CHECK_STATUS_OPERATION,
    )


def _apply_barrier_helper_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _ensure_helper_block(artifact)


def _apply_drop_legacy_string_helpers_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    candidate = _remove_function(artifact, "checkSprintfOperation")
    candidate = _remove_function(candidate, "checkSnprintfOperation")
    return candidate


def _apply_drop_legacy_status_helpers_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _remove_function(artifact, "checkSnprintfOperation")


def _apply_drop_unused_program_state_include_primitive(
    artifact: str,
    mechanism: _PatchMechanism,
) -> str:
    return _drop_unused_program_state_include(artifact)


def _normalize_candidate_formatting(code: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", code or "")


def _replace_function(code: str, name: str, replacement: str) -> str:
    pattern = re.compile(
        rf"  void {re.escape(name)}\s*\([\s\S]*?\)\s*const\s*\{{[\s\S]*?\n  \}}",
        flags=re.MULTILINE,
    )
    updated, count = pattern.subn(replacement.strip("\n"), code, count=1)
    return updated if count else code


def _remove_function(code: str, name: str) -> str:
    pattern = re.compile(
        rf"\n  void {re.escape(name)}\s*\([\s\S]*?\)\s*const\s*\{{[\s\S]*?\n  \}}\n",
        flags=re.MULTILINE,
    )
    updated, count = pattern.subn("\n", code, count=1)
    return updated if count else code


def _upsert_function_before_report_bug(code: str, name: str, replacement: str) -> str:
    if f"  void {name}" in (code or ""):
        return _replace_function(code, name, replacement)
    marker = "  void reportBug("
    if marker not in code:
        return code
    block = replacement.strip("\n")
    return code.replace(marker, block + "\n\n" + marker, 1)


def _build_precall_function(mechanism: _PatchMechanism) -> str:
    string_funcs = sorted(
        name
        for name in (mechanism.removed_calls | mechanism.added_calls)
        if name in _UNSAFE_STRING_APIS
    )
    copy_funcs = sorted(
        name
        for name in (mechanism.removed_calls | mechanism.added_calls)
        if name in {"memcpy", "memmove"}
    )
    status_funcs = sorted(
        name
        for name in (mechanism.removed_calls | mechanism.added_calls)
        if name in _STATUS_GUARDED_APIS
    )
    branches: list[str] = []

    if string_funcs:
        string_condition = " || ".join(f'FuncName == "{name}"' for name in string_funcs)
        branches.append(
            f"""if ({string_condition}) {{
      checkUnsafeStringOperation(Call, C, FuncName);
    }}"""
        )
    if copy_funcs:
        copy_condition = " || ".join(f'FuncName == "{name}"' for name in copy_funcs)
        branches.append(
            f"""if ({copy_condition}) {{
      checkMemcpyOperation(Call, C);
    }}"""
        )
    if status_funcs and mechanism.has_status_guard:
        status_condition = " || ".join(f'FuncName == "{name}"' for name in status_funcs)
        branches.append(
            f"""if ({status_condition}) {{
      const Expr *StatusRelevantArg =
          Call.getNumArgs() > 1 ? Call.getArgExpr(1)
                                : (Call.getNumArgs() > 0 ? Call.getArgExpr(0)
                                                         : nullptr);
      if (!StatusRelevantArg)
        return;
      checkStatusOperation(Call, C, FuncName);
    }}"""
        )

    body_lines = [
        "  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {",
        "    const IdentifierInfo *II = Call.getCalleeIdentifier();",
        "    if (!II)",
        "      return;",
        "",
        "    StringRef FuncName = II->getName();",
        "",
    ]
    if branches:
        for index, branch in enumerate(branches):
            if index == 0:
                body_lines.append(f"    {branch}")
            else:
                body_lines.append(f"    else {branch}")
    body_lines.append("  }")
    return "\n".join(body_lines)


def _drop_unused_program_state_include(code: str) -> str:
    if any(
        token in code
        for token in (
            "ProgramStateRef",
            "REGISTER_MAP_WITH_PROGRAMSTATE",
            "REGISTER_SET_WITH_PROGRAMSTATE",
            "REGISTER_LIST_WITH_PROGRAMSTATE",
            "C.getState(",
            "->get<",
            "->set<",
            "->remove<",
            "addTransition(",
        )
    ):
        return code
    return code.replace(
        '#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"\n',
        "",
    )


def _ensure_include(code: str, include_line: str, after: str) -> str:
    if include_line in code:
        return code
    if after in code:
        return code.replace(after, after + include_line, 1)
    return include_line + code


def _ensure_helper_block(code: str) -> str:
    if "bool hasSameBlockStatusBarrier(" in code and "void collectExprIdentifiers(" in code:
        return code
    helper_start = "  std::optional<uint64_t> getStaticDestinationBytes("
    marker = "  void reportBug("
    if helper_start in code and marker in code:
        prefix, remainder = code.split(helper_start, 1)
        _, suffix = remainder.split(marker, 1)
        return prefix + _BARRIER_HELPERS.strip("\n") + "\n\n" + marker + suffix
    if marker not in code:
        return code
    return code.replace(marker, _BARRIER_HELPERS + "\n\n" + marker, 1)


_CHECK_UNSAFE_STRING = """
  void checkUnsafeStringOperation(const CallEvent &Call, CheckerContext &C,
                                  StringRef FuncName) const {
    const Expr *DestArg = Call.getArgExpr(0);
    const Expr *SrcArg = Call.getNumArgs() > 1 ? Call.getArgExpr(1) : nullptr;
    const Stmt *OriginCall = Call.getOriginExpr();
    if (!DestArg || !SrcArg || !OriginCall)
      return;

    const auto HasCompanionSizeParameter = [&](const ParmVarDecl *DestParam) {
      std::vector<std::string> Names;
      if (!DestParam)
        return Names;

      const auto *CurrentFunction =
          dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (!CurrentFunction)
        return Names;

      for (const ParmVarDecl *Param : CurrentFunction->parameters()) {
        if (!Param || Param == DestParam)
          continue;
        std::string Lowered = Param->getName().lower();
        if (Lowered.find("size") != std::string::npos ||
            Lowered.find("capacity") != std::string::npos ||
            Lowered.find("cap") != std::string::npos ||
            Lowered.find("limit") != std::string::npos ||
            Lowered.find("len") != std::string::npos ||
            Lowered.find("bytes") != std::string::npos) {
          Names.push_back(Param->getName().str());
        }
      }
      return Names;
    };

    const MemRegion *DestRegion = Call.getArgSVal(0).getAsRegion();
    std::optional<uint64_t> DestBytes =
        getStaticDestinationBytes(DestRegion, C.getASTContext());
    bool HasCapacitySignal = DestBytes.has_value();
    std::vector<std::string> CapacityIdentifiers;
    if (DestRegion) {
      const MemRegion *BaseRegion = DestRegion->StripCasts();
      while (const auto *Element = dyn_cast<ElementRegion>(BaseRegion))
        BaseRegion = Element->getSuperRegion();
      if (const auto *Param = dyn_cast<ParamVarRegion>(BaseRegion))
        CapacityIdentifiers = HasCompanionSizeParameter(Param->getDecl());
    }

    if (CapacityIdentifiers.empty()) {
      if (const auto *Ref = dyn_cast<DeclRefExpr>(DestArg->IgnoreParenImpCasts())) {
        if (const auto *Param = dyn_cast<ParmVarDecl>(Ref->getDecl()))
          CapacityIdentifiers = HasCompanionSizeParameter(Param);
      }
    }

    HasCapacitySignal = HasCapacitySignal || !CapacityIdentifiers.empty();
    if (!HasCapacitySignal)
      return;

    if (FuncName == "strcpy") {
      if (auto LiteralBytes = getStaticStringLiteralBytes(SrcArg)) {
        if (DestBytes && *LiteralBytes <= *DestBytes)
          return;
      }
      if (hasSameBlockStringBarrier(Call, C, DestArg, SrcArg, CapacityIdentifiers,
                                    false))
        return;
    } else if (FuncName == "strcat") {
      if (hasSameBlockStringBarrier(Call, C, DestArg, SrcArg, CapacityIdentifiers,
                                    true))
        return;
    }

    std::string Msg = "Unsafe ";
    Msg += FuncName.str();
    Msg += " usage: missing destination buffer size validation";
    reportBug(OriginCall, C, Msg.c_str());
  }
"""


_CHECK_MEMCPY = """
  void checkMemcpyOperation(const CallEvent &Call, CheckerContext &C) const {
    const Expr *DestArg = Call.getArgExpr(0);
    const Expr *SizeArg = Call.getArgExpr(2);
    const Stmt *OriginCall = Call.getOriginExpr();
    if (!DestArg || !SizeArg || !OriginCall)
      return;

    const auto HasCompanionSizeParameter = [&](const ParmVarDecl *DestParam) {
      std::vector<std::string> Names;
      if (!DestParam)
        return Names;

      const auto *CurrentFunction =
          dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      if (!CurrentFunction)
        return Names;

      for (const ParmVarDecl *Param : CurrentFunction->parameters()) {
        if (!Param || Param == DestParam)
          continue;
        std::string Lowered = Param->getName().lower();
        if (Lowered.find("size") != std::string::npos ||
            Lowered.find("capacity") != std::string::npos ||
            Lowered.find("cap") != std::string::npos ||
            Lowered.find("limit") != std::string::npos ||
            Lowered.find("len") != std::string::npos ||
            Lowered.find("bytes") != std::string::npos) {
          Names.push_back(Param->getName().str());
        }
      }
      return Names;
    };

    const auto LooksLikeLengthCarrier = [&](const Expr *E, const auto &Self)
        -> bool {
      if (!E)
        return false;

      const Expr *CoreExpr = E->IgnoreParenImpCasts();
      if (const auto *SizeCall = dyn_cast<clang::CallExpr>(CoreExpr)) {
        if (const FunctionDecl *FD = SizeCall->getDirectCallee()) {
          std::string Lowered = FD->getName().lower();
          return Lowered == "strlen" || Lowered == "strnlen";
        }
        return false;
      }
      if (const auto *Ref = dyn_cast<DeclRefExpr>(CoreExpr)) {
        std::string Lowered = Ref->getDecl()->getName().lower();
        return Lowered.find("len") != std::string::npos ||
               Lowered.find("size") != std::string::npos ||
               Lowered.find("bytes") != std::string::npos;
      }
      if (const auto *Member = dyn_cast<MemberExpr>(CoreExpr)) {
        std::string Lowered = Member->getMemberDecl()->getName().lower();
        return Lowered.find("len") != std::string::npos ||
               Lowered.find("size") != std::string::npos ||
               Lowered.find("bytes") != std::string::npos;
      }
      if (const auto *BinOp = dyn_cast<BinaryOperator>(CoreExpr)) {
        if (BinOp->getOpcode() == BO_Add || BinOp->getOpcode() == BO_Sub)
          return Self(BinOp->getLHS(), Self) || Self(BinOp->getRHS(), Self);
      }
      return false;
    };

    const MemRegion *DestRegion = Call.getArgSVal(0).getAsRegion();
    std::optional<uint64_t> DestBytes =
        getStaticDestinationBytes(DestRegion, C.getASTContext());
    bool HasCompanionSize = false;
    std::vector<std::string> CapacityIdentifiers;
    if (DestRegion) {
      const MemRegion *BaseRegion = DestRegion->StripCasts();
      while (const auto *Element = dyn_cast<ElementRegion>(BaseRegion))
        BaseRegion = Element->getSuperRegion();
      if (const auto *Param = dyn_cast<ParamVarRegion>(BaseRegion)) {
        CapacityIdentifiers = HasCompanionSizeParameter(Param->getDecl());
        HasCompanionSize = !CapacityIdentifiers.empty();
      }
    }

    if (!HasCompanionSize) {
      if (const auto *Ref = dyn_cast<DeclRefExpr>(DestArg->IgnoreParenImpCasts())) {
        if (const auto *Param = dyn_cast<ParmVarDecl>(Ref->getDecl())) {
          CapacityIdentifiers = HasCompanionSizeParameter(Param);
          HasCompanionSize = !CapacityIdentifiers.empty();
        }
      }
    }

    if (!DestBytes && !HasCompanionSize)
      return;

    if (hasSameBlockMemcpyBarrier(Call, C, DestArg, SizeArg, CapacityIdentifiers))
      return;

    if (auto ConcreteSize = Call.getArgSVal(2).getAs<nonloc::ConcreteInt>()) {
      uint64_t RequestedBytes = ConcreteSize->getValue().getLimitedValue();
      if (DestBytes && RequestedBytes <= *DestBytes)
        return;
    } else if (!LooksLikeLengthCarrier(SizeArg, LooksLikeLengthCarrier)) {
      return;
    }

    reportBug(OriginCall, C,
              "memcpy operation: missing destination capacity validation");
  }
"""


_CHECK_STATUS_OPERATION = """
  void checkStatusOperation(const CallEvent &Call, CheckerContext &C,
                            StringRef FuncName) const {
    const Stmt *OriginCall = Call.getOriginExpr();
    if (!OriginCall)
      return;

    std::vector<std::string> CapacityIds;
    if (Call.getNumArgs() > 1) {
      if (const Expr *CapacityArg = Call.getArgExpr(1))
        CapacityIds = exprIdentifiers(CapacityArg);
    }

    if (hasSameBlockStatusBarrier(Call, C, CapacityIds))
      return;

    std::string Msg = "Unchecked status from ";
    Msg += FuncName.str();
    Msg += " may miss error or truncation handling";
    reportBug(OriginCall, C, Msg.c_str());
  }
"""


_BARRIER_HELPERS = """
  std::optional<uint64_t> getStaticDestinationBytes(const MemRegion *Region,
                                                    ASTContext &Ctx) const {
    if (!Region)
      return std::nullopt;

    const MemRegion *BaseRegion = Region->StripCasts();
    while (const auto *Element = dyn_cast<ElementRegion>(BaseRegion))
      BaseRegion = Element->getSuperRegion();

    if (const auto *Field = dyn_cast<FieldRegion>(BaseRegion)) {
      QualType QT = Field->getDecl()->getType();
      if (!QT.isNull() && !QT->isIncompleteType() &&
          (QT->isArrayType() || Ctx.getAsConstantArrayType(QT)))
        return Ctx.getTypeSizeInChars(QT).getQuantity();
    }

    if (const auto *Typed = dyn_cast<TypedValueRegion>(BaseRegion)) {
      QualType QT = Typed->getValueType();
      if (!QT.isNull() && !QT->isIncompleteType() &&
          (QT->isArrayType() || Ctx.getAsConstantArrayType(QT)))
        return Ctx.getTypeSizeInChars(QT).getQuantity();
    }

    return std::nullopt;
  }

  std::optional<uint64_t> getStaticStringLiteralBytes(const Expr *E) const {
    if (!E)
      return std::nullopt;
    const Expr *CoreExpr = E->IgnoreParenImpCasts();
    if (const auto *Literal = dyn_cast<StringLiteral>(CoreExpr))
      return static_cast<uint64_t>(Literal->getByteLength()) + 1;
    return std::nullopt;
  }

  void collectExprIdentifiers(const Expr *E,
                              std::vector<std::string> &Out) const {
    if (!E)
      return;

    const Expr *CoreExpr = E->IgnoreParenImpCasts();
    if (const auto *Ref = dyn_cast<DeclRefExpr>(CoreExpr)) {
      Out.push_back(Ref->getDecl()->getName().str());
    } else if (const auto *Member = dyn_cast<MemberExpr>(CoreExpr)) {
      Out.push_back(Member->getMemberDecl()->getName().str());
      collectExprIdentifiers(Member->getBase(), Out);
    } else if (const auto *SizeofExpr = dyn_cast<UnaryExprOrTypeTraitExpr>(CoreExpr)) {
      if (SizeofExpr->getKind() == UETT_SizeOf)
        Out.push_back("sizeof");
      if (!SizeofExpr->isArgumentType())
        collectExprIdentifiers(SizeofExpr->getArgumentExpr(), Out);
    }

    for (const Stmt *Child : CoreExpr->children()) {
      if (const auto *ChildExpr = dyn_cast_or_null<Expr>(Child))
        collectExprIdentifiers(ChildExpr, Out);
    }
  }

  std::vector<std::string> dedupeIdentifiers(
      const std::vector<std::string> &Tokens) const {
    std::vector<std::string> Result;
    for (const std::string &Token : Tokens) {
      if (Token.empty())
        continue;
      bool Seen = false;
      for (const std::string &Existing : Result) {
        if (Existing == Token) {
          Seen = true;
          break;
        }
      }
      if (!Seen)
        Result.push_back(Token);
    }
    return Result;
  }

  std::vector<std::string> exprIdentifiers(const Expr *E) const {
    std::vector<std::string> Tokens;
    collectExprIdentifiers(E, Tokens);
    return dedupeIdentifiers(Tokens);
  }

  bool sharesIdentifier(const std::vector<std::string> &Haystack,
                        const std::vector<std::string> &Needles) const {
    for (const std::string &Left : Haystack) {
      for (const std::string &Right : Needles) {
        if (!Left.empty() && Left == Right)
          return true;
      }
    }
    return false;
  }

  bool stmtTerminates(const Stmt *S) const {
    if (!S)
      return false;
    if (isa<ReturnStmt>(S) || isa<BreakStmt>(S) || isa<ContinueStmt>(S) ||
        isa<GotoStmt>(S))
      return true;
    for (const Stmt *Child : S->children()) {
      if (Child && stmtTerminates(Child))
        return true;
    }
    return false;
  }

  bool stmtContainsTarget(const Stmt *Root, const Stmt *Target) const {
    if (!Root || !Target)
      return false;
    if (Root == Target)
      return true;
    for (const Stmt *Child : Root->children()) {
      if (Child && stmtContainsTarget(Child, Target))
        return true;
    }
    return false;
  }

  bool locateSiblingWindow(const CallEvent &Call,
                           CheckerContext &C,
                           std::vector<const Stmt *> &Siblings,
                           int &CurrentIndex) const {
    CurrentIndex = -1;
    const Stmt *CurrentStmt = Call.getOriginExpr();
    const CompoundStmt *Body = nullptr;
    const Stmt *BodyChild = nullptr;
    while (CurrentStmt) {
      auto Parents = C.getASTContext().getParents(*CurrentStmt);
      if (Parents.empty())
        break;
      const Stmt *NextStmt = nullptr;
      for (const auto &ParentNode : Parents) {
        if (const auto *Compound = ParentNode.get<CompoundStmt>()) {
          Body = Compound;
          BodyChild = CurrentStmt;
          break;
        }
        if (!NextStmt) {
          if (const auto *ParentStmt = ParentNode.get<Stmt>())
            NextStmt = ParentStmt;
        }
      }
      if (Body)
        break;
      CurrentStmt = NextStmt;
    }

    if (!Body || !BodyChild)
      return false;

    for (const Stmt *Child : Body->body()) {
      if (Child)
        Siblings.push_back(Child);
    }

    for (size_t I = 0; I < Siblings.size(); ++I) {
      if (Siblings[I] == BodyChild) {
        CurrentIndex = static_cast<int>(I);
        break;
      }
    }
    return CurrentIndex >= 0;
  }

  bool isStringLengthCallFor(const Expr *E,
                             const std::vector<std::string> &SeedIds) const {
    if (!E)
      return false;

    const Expr *CoreExpr = E->IgnoreParenImpCasts();
    if (const auto *CallExpr = dyn_cast<clang::CallExpr>(CoreExpr)) {
      if (const FunctionDecl *FD = CallExpr->getDirectCallee()) {
        std::string Lowered = FD->getName().lower();
        if (Lowered == "strlen" || Lowered == "strnlen") {
          if (CallExpr->getNumArgs() == 0 || SeedIds.empty())
            return true;
          std::vector<std::string> ArgIds = exprIdentifiers(CallExpr->getArg(0));
          return sharesIdentifier(ArgIds, SeedIds);
        }
      }
    }

    for (const Stmt *Child : CoreExpr->children()) {
      if (const auto *ChildExpr = dyn_cast_or_null<Expr>(Child)) {
        if (isStringLengthCallFor(ChildExpr, SeedIds))
          return true;
      }
    }
    return false;
  }

  bool looksLikeLengthExpression(
      const Expr *E,
      const std::vector<std::string> &RootIds,
      const std::vector<std::string> &KnownLengthIds) const {
    if (!E)
      return false;

    const Expr *CoreExpr = E->IgnoreParenImpCasts();
    if (isStringLengthCallFor(CoreExpr, RootIds))
      return true;
    if (const auto *Ref = dyn_cast<DeclRefExpr>(CoreExpr)) {
      std::vector<std::string> RefIds = {Ref->getDecl()->getName().str()};
      if (sharesIdentifier(RefIds, KnownLengthIds))
        return true;
    }
    if (const auto *Member = dyn_cast<MemberExpr>(CoreExpr)) {
      std::vector<std::string> MemberIds = exprIdentifiers(Member);
      if (sharesIdentifier(MemberIds, KnownLengthIds))
        return true;
    }
    if (const auto *BinOp = dyn_cast<BinaryOperator>(CoreExpr)) {
      if (BinOp->getOpcode() == BO_Add || BinOp->getOpcode() == BO_Sub)
        return looksLikeLengthExpression(BinOp->getLHS(), RootIds,
                                         KnownLengthIds) ||
               looksLikeLengthExpression(BinOp->getRHS(), RootIds,
                                         KnownLengthIds);
    }
    return false;
  }

  bool exprIsZeroLiteral(const Expr *E) const {
    if (!E)
      return false;
    const Expr *CoreExpr = E->IgnoreParenImpCasts();
    if (const auto *Literal = dyn_cast<IntegerLiteral>(CoreExpr))
      return Literal->getValue() == 0;
    return false;
  }

  void collectDerivedLengthIdentifiersFromStmt(
      const Stmt *S,
      const std::vector<std::string> &RootIds,
      const std::vector<std::string> &KnownLengthIds,
      std::vector<std::string> &Out) const {
    if (!S)
      return;

    if (const auto *Decl = dyn_cast<DeclStmt>(S)) {
      for (const clang::Decl *Item : Decl->decls()) {
        const auto *Var = dyn_cast<VarDecl>(Item);
        if (!Var || !Var->hasInit())
          continue;
        if (looksLikeLengthExpression(Var->getInit(), RootIds, KnownLengthIds))
          Out.push_back(Var->getName().str());
      }
      return;
    }

    if (const auto *BinOp = dyn_cast<BinaryOperator>(S)) {
      if (!BinOp->isAssignmentOp())
        return;
      const auto *Ref =
          dyn_cast<DeclRefExpr>(BinOp->getLHS()->IgnoreParenImpCasts());
      if (!Ref)
        return;
      if (looksLikeLengthExpression(BinOp->getRHS(), RootIds, KnownLengthIds))
        Out.push_back(Ref->getDecl()->getName().str());
    }
  }

  std::vector<std::string> buildBarrierSizeIdentifiers(
      const std::vector<const Stmt *> &Siblings,
      int CurrentIndex,
      const std::vector<std::string> &SeedIds) const {
    std::vector<std::string> DerivedIds;
    for (int I = 0; I < CurrentIndex; ++I) {
      collectDerivedLengthIdentifiersFromStmt(
          Siblings[static_cast<size_t>(I)], SeedIds, DerivedIds, DerivedIds);
      DerivedIds = dedupeIdentifiers(DerivedIds);
    }
    std::vector<std::string> Result = SeedIds;
    Result.insert(Result.end(), DerivedIds.begin(), DerivedIds.end());
    Result = dedupeIdentifiers(Result);
    return Result;
  }

  bool conditionMatchesBoundBarrier(
      const Expr *Cond,
      const std::vector<std::string> &DestIds,
      const std::vector<std::string> &SizeIds,
      const std::vector<std::string> &CapacityIds) const {
    if (!Cond)
      return false;

    const Expr *CoreCond = Cond->IgnoreParenImpCasts();
    if (const auto *BinOp = dyn_cast<BinaryOperator>(CoreCond)) {
      if (BinOp->getOpcode() == BO_LOr || BinOp->getOpcode() == BO_LAnd)
        return conditionMatchesBoundBarrier(BinOp->getLHS(), DestIds, SizeIds,
                                            CapacityIds) ||
               conditionMatchesBoundBarrier(BinOp->getRHS(), DestIds, SizeIds,
                                            CapacityIds);
      if (!BinOp->isComparisonOp())
        return false;
      std::vector<std::string> CondIds = exprIdentifiers(CoreCond);
      if (!sharesIdentifier(CondIds, SizeIds))
        return false;
      if (sharesIdentifier(CondIds, DestIds) ||
          sharesIdentifier(CondIds, CapacityIds))
        return true;
      for (const std::string &Token : CondIds) {
        if (Token == "sizeof")
          return true;
      }
    }
    return false;
  }

  bool hasSameBlockStringBarrier(
      const CallEvent &Call,
      CheckerContext &C,
      const Expr *DestArg,
      const Expr *SrcArg,
      const std::vector<std::string> &CapacityIds,
      bool IncludeDestLength) const {
    std::vector<const Stmt *> Siblings;
    int CurrentIndex = -1;
    if (!locateSiblingWindow(Call, C, Siblings, CurrentIndex) ||
        CurrentIndex <= 0)
      return false;

    std::vector<std::string> DestIds = exprIdentifiers(DestArg);
    std::vector<std::string> SeedIds = exprIdentifiers(SrcArg);
    if (IncludeDestLength)
      SeedIds.insert(SeedIds.end(), DestIds.begin(), DestIds.end());
    SeedIds = dedupeIdentifiers(SeedIds);
    if (SeedIds.empty())
      return false;

    std::vector<std::string> SizeIds =
        buildBarrierSizeIdentifiers(Siblings, CurrentIndex, SeedIds);
    for (int I = CurrentIndex - 1, LookBack = 0;
         I >= 0 && LookBack < 6;
         --I, ++LookBack) {
      const auto *If = dyn_cast<IfStmt>(Siblings[static_cast<size_t>(I)]);
      if (!If)
        continue;
      if (!stmtTerminates(If->getThen()))
        continue;
      if (conditionMatchesBoundBarrier(If->getCond(), DestIds, SizeIds,
                                       CapacityIds))
        return true;
    }
    return false;
  }

  bool hasSameBlockMemcpyBarrier(
      const CallEvent &Call,
      CheckerContext &C,
      const Expr *DestArg,
      const Expr *SizeArg,
      const std::vector<std::string> &CapacityIds) const {
    std::vector<const Stmt *> Siblings;
    int CurrentIndex = -1;
    if (!locateSiblingWindow(Call, C, Siblings, CurrentIndex) ||
        CurrentIndex <= 0)
      return false;

    std::vector<std::string> DestIds = exprIdentifiers(DestArg);
    std::vector<std::string> SizeIds = exprIdentifiers(SizeArg);
    if (SizeIds.empty())
      return false;

    for (int I = CurrentIndex - 1, LookBack = 0;
         I >= 0 && LookBack < 6;
         --I, ++LookBack) {
      const auto *If = dyn_cast<IfStmt>(Siblings[static_cast<size_t>(I)]);
      if (!If)
        continue;
      if (!stmtTerminates(If->getThen()))
        continue;
      if (conditionMatchesBoundBarrier(If->getCond(), DestIds, SizeIds,
                                       CapacityIds))
        return true;
    }
    return false;
  }

  void collectAssignedValueIdentifiersFromStmt(
      const Stmt *S,
      const Stmt *Target,
      std::vector<std::string> &Out) const {
    if (!S || !Target)
      return;

    if (const auto *Decl = dyn_cast<DeclStmt>(S)) {
      for (const clang::Decl *Item : Decl->decls()) {
        const auto *Var = dyn_cast<VarDecl>(Item);
        if (!Var || !Var->hasInit())
          continue;
        if (stmtContainsTarget(Var->getInit(), Target))
          Out.push_back(Var->getName().str());
      }
      return;
    }

    if (const auto *BinOp = dyn_cast<BinaryOperator>(S)) {
      if (!BinOp->isAssignmentOp())
        return;
      if (!stmtContainsTarget(BinOp->getRHS(), Target))
        return;
      std::vector<std::string> AssignedIds = exprIdentifiers(BinOp->getLHS());
      Out.insert(Out.end(), AssignedIds.begin(), AssignedIds.end());
    }
  }

  bool conditionMatchesStatusBarrier(
      const Expr *Cond,
      const std::vector<std::string> &StatusIds,
      const std::vector<std::string> &CapacityIds) const {
    if (!Cond)
      return false;

    const Expr *CoreCond = Cond->IgnoreParenImpCasts();
    if (const auto *BinOp = dyn_cast<BinaryOperator>(CoreCond)) {
      if (BinOp->getOpcode() == BO_LOr || BinOp->getOpcode() == BO_LAnd)
        return conditionMatchesStatusBarrier(BinOp->getLHS(), StatusIds,
                                             CapacityIds) ||
               conditionMatchesStatusBarrier(BinOp->getRHS(), StatusIds,
                                             CapacityIds);
      if (!BinOp->isComparisonOp())
        return false;

      std::vector<std::string> LeftIds = exprIdentifiers(BinOp->getLHS());
      std::vector<std::string> RightIds = exprIdentifiers(BinOp->getRHS());
      bool LeftHasStatus = sharesIdentifier(LeftIds, StatusIds);
      bool RightHasStatus = sharesIdentifier(RightIds, StatusIds);
      if (!LeftHasStatus && !RightHasStatus)
        return false;

      if ((LeftHasStatus && exprIsZeroLiteral(BinOp->getRHS()) &&
           BinOp->getOpcode() == BO_LT) ||
          (RightHasStatus && exprIsZeroLiteral(BinOp->getLHS()) &&
           BinOp->getOpcode() == BO_GT))
        return true;

      std::vector<std::string> CondIds = exprIdentifiers(CoreCond);
      return sharesIdentifier(CondIds, CapacityIds);
    }
    return false;
  }

  bool hasSameBlockStatusBarrier(
      const CallEvent &Call,
      CheckerContext &C,
      const std::vector<std::string> &CapacityIds) const {
    std::vector<const Stmt *> Siblings;
    int CurrentIndex = -1;
    if (!locateSiblingWindow(Call, C, Siblings, CurrentIndex) ||
        CurrentIndex < 0)
      return false;

    const Stmt *CurrentStmt = Siblings[static_cast<size_t>(CurrentIndex)];
    const Stmt *OriginCall = Call.getOriginExpr();
    if (!CurrentStmt || !OriginCall)
      return false;

    std::vector<std::string> StatusIds;
    collectAssignedValueIdentifiersFromStmt(CurrentStmt, OriginCall, StatusIds);
    StatusIds = dedupeIdentifiers(StatusIds);

    for (int I = CurrentIndex + 1, LookAhead = 0;
         I < static_cast<int>(Siblings.size()) && LookAhead < 6;
         ++I, ++LookAhead) {
      const Stmt *Sibling = Siblings[static_cast<size_t>(I)];
      if (!Sibling)
        continue;

      if (const auto *If = dyn_cast<IfStmt>(Sibling)) {
        if (!stmtTerminates(If->getThen()))
          continue;
        if (!StatusIds.empty() &&
            conditionMatchesStatusBarrier(If->getCond(), StatusIds,
                                          CapacityIds))
          return true;
        continue;
      }

      if (const auto *Ret = dyn_cast<ReturnStmt>(Sibling)) {
        if (!StatusIds.empty() && Ret->getRetValue()) {
          std::vector<std::string> ReturnIds = exprIdentifiers(Ret->getRetValue());
          if (sharesIdentifier(ReturnIds, StatusIds))
            return true;
        }
      }
    }
    return false;
  }
"""


_REPAIR_PRIMITIVES = (
    _RepairPrimitive(
        name="semantic_ast_includes",
        matches=lambda artifact, mechanism: "checkPreCall" in (artifact or ""),
        apply=_apply_semantic_ast_includes,
    ),
    _RepairPrimitive(
        name="semantic_dispatch",
        matches=lambda artifact, mechanism: "checkPreCall" in (artifact or ""),
        apply=_apply_semantic_dispatch_primitive,
    ),
    _RepairPrimitive(
        name="capacity_support_includes",
        matches=lambda artifact, mechanism: _looks_like_size_guarded_write_pattern(artifact, mechanism),
        apply=_apply_capacity_support_includes,
    ),
    _RepairPrimitive(
        name="buffer_dispatch",
        matches=lambda artifact, mechanism: "checkPreCall" in (artifact or ""),
        apply=_apply_buffer_dispatch_primitive,
    ),
    _RepairPrimitive(
        name="buffer_string_checker",
        matches=lambda artifact, mechanism: "checkUnsafeStringOperation" in (artifact or ""),
        apply=_apply_buffer_string_checker_primitive,
    ),
    _RepairPrimitive(
        name="buffer_memcpy_checker",
        matches=lambda artifact, mechanism: "checkMemcpyOperation" in (artifact or ""),
        apply=_apply_buffer_memcpy_checker_primitive,
    ),
    _RepairPrimitive(
        name="status_checker",
        matches=lambda artifact, mechanism: "checkPreCall" in (artifact or ""),
        apply=_apply_status_checker_primitive,
    ),
    _RepairPrimitive(
        name="barrier_helpers",
        matches=lambda artifact, mechanism: "reportBug(" in (artifact or ""),
        apply=_apply_barrier_helper_primitive,
    ),
    _RepairPrimitive(
        name="drop_legacy_string_helpers",
        matches=lambda artifact, mechanism: any(
            token in (artifact or "")
            for token in ("checkSprintfOperation", "checkSnprintfOperation")
        ),
        apply=_apply_drop_legacy_string_helpers_primitive,
    ),
    _RepairPrimitive(
        name="drop_legacy_status_helpers",
        matches=lambda artifact, mechanism: "checkSnprintfOperation" in (artifact or ""),
        apply=_apply_drop_legacy_status_helpers_primitive,
    ),
    _RepairPrimitive(
        name="drop_unused_program_state_include",
        matches=lambda artifact, mechanism: "ProgramState.h" in (artifact or ""),
        apply=_apply_drop_unused_program_state_include_primitive,
    ),
)

_REPAIR_PRIMITIVES_BY_NAME = {primitive.name: primitive for primitive in _REPAIR_PRIMITIVES}


_SEMANTIC_PROFILES = (
    _SemanticProfile(
        name="buffer_guarded_write",
        priority=100,
        matches=_looks_like_size_guarded_write_pattern,
        primitive_names=(
            "semantic_ast_includes",
            "semantic_dispatch",
            "buffer_string_checker",
            "buffer_memcpy_checker",
            "barrier_helpers",
            "drop_legacy_string_helpers",
            "drop_unused_program_state_include",
        ),
    ),
    _SemanticProfile(
        name="checked_status_guard",
        priority=70,
        matches=_looks_like_checked_status_guard_pattern,
        primitive_names=(
            "semantic_ast_includes",
            "semantic_dispatch",
            "status_checker",
            "barrier_helpers",
            "drop_legacy_status_helpers",
            "drop_unused_program_state_include",
        ),
    ),
    _SemanticProfile(
        name="lifecycle_revalidation",
        priority=60,
        matches=_looks_like_lifecycle_revalidation_pattern,
        primitive_names=(),
    ),
    _SemanticProfile(
        name="synchronization_guard",
        priority=55,
        matches=_looks_like_synchronization_guard_pattern,
        primitive_names=(),
    ),
)
