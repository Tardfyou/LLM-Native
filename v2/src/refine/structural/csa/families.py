from __future__ import annotations

import re
from typing import Callable

from ..shared import (
    _LIFECYCLE_CALL_HINTS,
    _PatchMechanism,
    _calls_match_hints,
    _inspect_patch_mechanism,
    _normalize_identifier_token,
)
from ....utils.vulnerability_taxonomy import normalize_vulnerability_type


_BUFFER_WRITE_CALL_HINTS = frozenset(
    {"strcpy", "strcat", "sprintf", "snprintf", "memcpy", "memmove", "strncpy", "strncat"}
)
_STABLE_HANDLE_HINTS = (
    "id",
    "handle",
    "token",
    "key",
    "slot",
    "index",
    "idx",
)
_CACHED_POINTER_HINTS = (
    "cache",
    "cached",
    "stale",
    "current",
    "active",
    "session",
    "entry",
    "node",
    "item",
    "ptr",
    "ref",
)
_CSA_FAMILY_ALIASES = {
    "stack_overflow": "buffer_overflow",
    "heap_overflow": "buffer_overflow",
    "out_of_bounds_write": "buffer_overflow",
}
_CSA_BUFFER_REQUIRED_DEFINITION_PATTERNS = (
    re.compile(r"\bvoid\s+checkUnsafeStringOperation\s*\("),
    re.compile(r"\bvoid\s+checkMemcpyOperation\s*\("),
    re.compile(r"\bstd::optional\s*<\s*uint64_t\s*>\s+getStaticDestinationBytes\s*\("),
    re.compile(r"\bbool\s+hasSameBlockMemcpyBarrier\s*\("),
    re.compile(r"\bvoid\s+checkStatusOperation\s*\("),
    re.compile(r"\bbool\s+hasSameBlockStatusBarrier\s*\("),
)


def build_csa_family_candidate(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> str:
    family = _infer_csa_checker_family(artifact_text, mechanism)
    if not family or not _artifact_needs_family_fallback(artifact_text, family, mechanism):
        return ""

    builder = _CSA_FAMILY_BUILDERS.get(family)
    if builder is None:
        return ""

    class_name = _extract_csa_class_name(artifact_text) or _default_csa_checker_name(family)
    return builder(class_name, mechanism)


def infer_csa_structural_family(
    artifact_text: str,
    patch_text: str,
) -> str:
    mechanism = _inspect_patch_mechanism(str(patch_text or ""))
    return _infer_csa_checker_family(str(artifact_text or ""), mechanism)


def _infer_csa_checker_family(
    artifact_text: str,
    mechanism: _PatchMechanism,
) -> str:
    candidates = [
        _extract_csa_class_name(artifact_text),
        _extract_bug_type_name(artifact_text),
        _extract_first_comment_line(artifact_text),
    ]
    for candidate in candidates:
        family = _infer_family_from_token(candidate)
        if family:
            return family

    lowered = str(artifact_text or "").lower()
    if "null pointer" in lowered and "deref" in lowered:
        return "null_dereference"
    if ("divide" in lowered or "division" in lowered or "divzero" in lowered) and "zero" in lowered:
        return "divide_by_zero"
    if "double free" in lowered:
        return "double_free"
    if any(token in lowered for token in ("use-after-free", "use after free", "dangling", "stale")):
        return "use_after_free"
    if "memory leak" in lowered or "leak" in lowered:
        return "memory_leak"
    if "uninitialized" in lowered or "uninit" in lowered:
        return "uninitialized_variable"
    if any(token in lowered for token in ("buffer overflow", "stack overflow", "heap overflow", "oob write")):
        return "buffer_overflow"

    call_hints = mechanism.removed_calls | mechanism.added_calls
    if _calls_match_hints(call_hints, _LIFECYCLE_CALL_HINTS):
        if mechanism.has_revalidation_lookup or mechanism.has_state_reset:
            return "use_after_free"
        return "double_free"
    if mechanism.has_zero_guard:
        return "divide_by_zero"
    if mechanism.has_null_guard:
        return "null_dereference"
    if (
        mechanism.has_capacity_guard
        or mechanism.has_bounded_formatting_guard
        or mechanism.has_status_guard
        or mechanism.has_length_derived_copy
        or bool(call_hints & _BUFFER_WRITE_CALL_HINTS)
    ):
        return "buffer_overflow"
    return ""


def _infer_family_from_token(value: str) -> str:
    token = _normalize_identifier_token(value)
    if not token:
        return ""

    canonical = normalize_vulnerability_type(token.removesuffix("_checker"), "")
    if canonical in _CSA_FAMILY_ALIASES:
        return _CSA_FAMILY_ALIASES[canonical]
    if canonical in _CSA_FAMILY_BUILDERS:
        return canonical

    if "null" in token and ("deref" in token or "pointer" in token):
        return "null_dereference"
    if token in {"divzero", "div_zero"} or ("div" in token and "zero" in token):
        return "divide_by_zero"
    if "double" in token and "free" in token:
        return "double_free"
    if token in {"uaf", "useafterfree"} or ("use" in token and "free" in token):
        return "use_after_free"
    if "leak" in token:
        return "memory_leak"
    if "uninit" in token or ("uninitialized" in token and "variable" in token):
        return "uninitialized_variable"
    if "overflow" in token or ("oob" in token and "write" in token):
        return "buffer_overflow"
    return ""


def _artifact_needs_family_fallback(
    artifact_text: str,
    family: str,
    mechanism: _PatchMechanism,
) -> bool:
    artifact = str(artifact_text or "")
    if family == "null_dereference":
        return not (
            "checkLocation(" in artifact
            and "isZeroConstant" in artifact
            and "PathSensitiveBugReport" in artifact
        )
    if family == "divide_by_zero":
        return not (
            "BO_Div" in artifact
            and ("assumeDual(" in artifact or "assume(" in artifact)
            and "PathSensitiveBugReport" in artifact
        )
    if family == "double_free":
        return not (
            "checkPostCall(" in artifact
            and "REGISTER_SET_WITH_PROGRAMSTATE" in artifact
            and "contains<" in artifact
            and "add<" in artifact
        )
    if family == "use_after_free":
        if _prefer_relookup_stale_cache_variant(mechanism):
            return not (
                "checkPreStmt(" in artifact
                and "MemberExpr" in artifact
                and "hasAuthoritativeHandlePeer(" in artifact
                and "bypasses authoritative relookup" in artifact
            )
        return not (
            "checkPostCall(" in artifact
            and "checkLocation(" in artifact
            and "REGISTER_SET_WITH_PROGRAMSTATE" in artifact
            and "contains<" in artifact
        )
    if family == "buffer_overflow":
        return not all(
            pattern.search(artifact)
            for pattern in _CSA_BUFFER_REQUIRED_DEFINITION_PATTERNS
        )
    if family == "memory_leak":
        return not (
            "checkDeadSymbols(" in artifact
            and "REGISTER_SET_WITH_PROGRAMSTATE(AllocatedSymbols, SymbolRef)" in artifact
            and "remove<AllocatedSymbols>" in artifact
        )
    if family == "uninitialized_variable":
        return not (
            "checkBind(" in artifact
            and "checkLocation(" in artifact
            and "InitializedRegions" in artifact
            and "contains<InitializedRegions>" in artifact
        )
    return False


def _extract_csa_class_name(artifact_text: str) -> str:
    match = re.search(
        r"class\s+(?P<name>[A-Za-z_]\w*)\s*:\s*public\s+Checker<",
        artifact_text or "",
    )
    return str(match.group("name") or "").strip() if match else ""


def _extract_bug_type_name(artifact_text: str) -> str:
    match = re.search(r'BugType\s*\([^)]*"(?P<name>[^"]+)"', artifact_text or "")
    return str(match.group("name") or "").strip() if match else ""


def _extract_first_comment_line(artifact_text: str) -> str:
    match = re.search(r"//\s*(?P<comment>[^\n]+)", artifact_text or "")
    return str(match.group("comment") or "").strip() if match else ""


def _default_csa_checker_name(family: str) -> str:
    return {
        "null_dereference": "NullDereferenceChecker",
        "divide_by_zero": "DivideByZeroChecker",
        "double_free": "DoubleFreeChecker",
        "use_after_free": "UseAfterFreeChecker",
        "buffer_overflow": "BufferOverflowChecker",
        "memory_leak": "MemoryLeakChecker",
        "uninitialized_variable": "UninitializedVariableChecker",
    }.get(family, "PatchGuidedChecker")


def _render_csa_family_template(template: str, class_name: str) -> str:
    return template.replace("__CHECKER_NAME__", class_name)


def _build_null_dereference_family_candidate(class_name: str, mechanism: _PatchMechanism) -> str:
    return _render_csa_family_template(_NULL_DEREFERENCE_TEMPLATE, class_name)


def _build_divide_by_zero_family_candidate(class_name: str, mechanism: _PatchMechanism) -> str:
    return _render_csa_family_template(_DIVIDE_BY_ZERO_TEMPLATE, class_name)


def _build_double_free_family_candidate(class_name: str, mechanism: _PatchMechanism) -> str:
    return _render_csa_family_template(_DOUBLE_FREE_TEMPLATE, class_name)


def _build_use_after_free_family_candidate(class_name: str, mechanism: _PatchMechanism) -> str:
    if _prefer_relookup_stale_cache_variant(mechanism):
        candidate = _render_csa_family_template(_USE_AFTER_FREE_RELOOKUP_TEMPLATE, class_name)
        stable_hints = ", ".join(f'"{token}"' for token in _STABLE_HANDLE_HINTS)
        cached_hints = ", ".join(f'"{token}"' for token in _CACHED_POINTER_HINTS)
        return (
            candidate
            .replace("__STABLE_HANDLE_HINTS__", stable_hints)
            .replace("__CACHED_POINTER_HINTS__", cached_hints)
        )
    return _render_csa_family_template(_USE_AFTER_FREE_TEMPLATE, class_name)


def _prefer_relookup_stale_cache_variant(mechanism: _PatchMechanism) -> bool:
    return bool(mechanism.has_revalidation_lookup or mechanism.has_state_reset)


def _build_buffer_overflow_family_candidate(class_name: str, mechanism: _PatchMechanism) -> str:
    from ... import csa_structural as legacy

    parts = [
        f"""/**
 * Patch-guided structural fallback for buffer overflow refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/Basic/Version.h"
#include "llvm/ADT/StringRef.h"
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

namespace {{

class {class_name} : public Checker<check::PreCall> {{
  mutable std::unique_ptr<BugType> BT;

public:
  {class_name}()
      : BT(std::make_unique<BugType>(this, "Unsafe buffer write",
                                     "Memory error")) {{}}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {{
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II)
      return;

    StringRef FuncName = II->getName();
    if (FuncName == "strcpy" || FuncName == "strcat") {{
      checkUnsafeStringOperation(Call, C, FuncName);
    }} else if (FuncName == "memcpy" || FuncName == "memmove") {{
      checkMemcpyOperation(Call, C);
    }} else if (FuncName == "snprintf" || FuncName == "vsnprintf" ||
               FuncName == "write" || FuncName == "send" ||
               FuncName == "recv" || FuncName == "read" ||
               FuncName == "fwrite") {{
      const Expr *StatusRelevantArg =
          Call.getNumArgs() > 1 ? Call.getArgExpr(1)
                                : (Call.getNumArgs() > 0 ? Call.getArgExpr(0)
                                                         : nullptr);
      if (!StatusRelevantArg)
        return;
      checkStatusOperation(Call, C, FuncName);
    }}
  }}
""",
        legacy._CHECK_UNSAFE_STRING.strip("\n"),
        "",
        legacy._CHECK_MEMCPY.strip("\n"),
        "",
        legacy._CHECK_STATUS_OPERATION.strip("\n"),
        "",
        legacy._BARRIER_HELPERS.strip("\n"),
        """

  void reportBug(const Stmt *S, CheckerContext &C, const char *Msg) const {
    if (!S)
      return;
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
      auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
      R->addRange(S->getSourceRange());
      C.emitReport(std::move(R));
    }
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<""",
        class_name,
        """>(
      "custom.""",
        class_name,
        """",
      "Patch-guided buffer overflow checker",
      "");
}
""",
    ]
    return "".join(parts)


def _build_memory_leak_family_candidate(class_name: str, mechanism: _PatchMechanism) -> str:
    return _render_csa_family_template(_MEMORY_LEAK_TEMPLATE, class_name)


def _build_uninitialized_variable_family_candidate(class_name: str, mechanism: _PatchMechanism) -> str:
    return _render_csa_family_template(_UNINITIALIZED_VARIABLE_TEMPLATE, class_name)


_NULL_DEREFERENCE_TEMPLATE = """
/**
 * Patch-guided structural fallback for null dereference refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/Version.h"
#include <memory>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

namespace {

class __CHECKER_NAME__ : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  __CHECKER_NAME__()
      : BT(std::make_unique<BugType>(this, "Null pointer dereference",
                                     "Memory error")) {}

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const {
    if (!S)
      return;
    if (!Loc.isZeroConstant())
      return;

    if (ExplodedNode *N = C.generateErrorNode()) {
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT,
          IsLoad ? "Dereference of null pointer"
                 : "Store through null pointer",
          N);
      R->addRange(S->getSourceRange());
      C.emitReport(std::move(R));
    }
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<__CHECKER_NAME__>(
      "custom.__CHECKER_NAME__",
      "Patch-guided null dereference checker",
      "");
}
"""


_DIVIDE_BY_ZERO_TEMPLATE = """
/**
 * Patch-guided structural fallback for divide-by-zero refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/Version.h"
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

namespace {

class __CHECKER_NAME__ : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  __CHECKER_NAME__()
      : BT(std::make_unique<BugType>(this, "Division by zero",
                                     "Arithmetic error")) {}

  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const {
    if (!B)
      return;

    BinaryOperator::Opcode Op = B->getOpcode();
    if (Op != BO_Div && Op != BO_Rem &&
        Op != BO_DivAssign && Op != BO_RemAssign)
      return;
    if (!B->getRHS() || !B->getRHS()->getType()->isScalarType())
      return;

    SVal Divisor = C.getSVal(B->getRHS());
    std::optional<DefinedSVal> Defined = Divisor.getAs<DefinedSVal>();
    if (!Defined)
      return;

    ConstraintManager &CM = C.getConstraintManager();
    ProgramStateRef NonZeroState;
    ProgramStateRef ZeroState;
    std::tie(NonZeroState, ZeroState) = CM.assumeDual(C.getState(), *Defined);

    if (!NonZeroState && ZeroState) {
      if (ExplodedNode *N = C.generateErrorNode(ZeroState)) {
        auto R = std::make_unique<PathSensitiveBugReport>(
            *BT, "Division by a value constrained to zero", N);
        R->addRange(B->getSourceRange());
        C.emitReport(std::move(R));
      }
      return;
    }

    if (NonZeroState)
      C.addTransition(NonZeroState);
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<__CHECKER_NAME__>(
      "custom.__CHECKER_NAME__",
      "Patch-guided divide-by-zero checker",
      "");
}
"""


_DOUBLE_FREE_TEMPLATE = """
/**
 * Patch-guided structural fallback for double-free refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/Version.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

REGISTER_SET_WITH_PROGRAMSTATE(FreedSymbols, SymbolRef)

namespace {

class __CHECKER_NAME__ : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

  static bool isReleaseLike(StringRef FuncName) {
    return FuncName == "free" ||
           FuncName == "kfree" ||
           FuncName == "delete" ||
           FuncName == "release" ||
           FuncName.ends_with("_free") ||
           FuncName.ends_with("_release") ||
           FuncName.contains("destroy");
  }

  static SymbolRef getTrackedSymbol(SVal Value) {
    if (SymbolRef Sym = Value.getAsLocSymbol(true))
      return Sym;
    return Value.getAsSymbol(true);
  }

  void reportDoubleFree(const Stmt *S, CheckerContext &C,
                        ProgramStateRef State) const {
    if (!S)
      return;
    if (ExplodedNode *N = C.generateErrorNode(State)) {
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "Second release of a previously freed symbol", N);
      R->addRange(S->getSourceRange());
      C.emitReport(std::move(R));
    }
  }

public:
  __CHECKER_NAME__()
      : BT(std::make_unique<BugType>(this, "Double free", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II || Call.getNumArgs() == 0)
      return;

    StringRef FuncName = II->getName();
    if (!isReleaseLike(FuncName))
      return;

    SymbolRef Released = getTrackedSymbol(Call.getArgSVal(0));
    if (!Released)
      return;

    ProgramStateRef State = C.getState();
    if (State->contains<FreedSymbols>(Released)) {
      reportDoubleFree(Call.getOriginExpr(), C, State);
      return;
    }

    State = State->add<FreedSymbols>(Released);
    C.addTransition(State);
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<__CHECKER_NAME__>(
      "custom.__CHECKER_NAME__",
      "Patch-guided double-free checker",
      "");
}
"""


_USE_AFTER_FREE_RELOOKUP_TEMPLATE = """
/**
 * Patch-guided structural fallback for stale-cache / authoritative-relookup
 * use-after-free refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/Version.h"
#include "llvm/ADT/StringRef.h"
#include <memory>
#include <string>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

namespace {

class __CHECKER_NAME__ : public Checker<check::PreStmt<MemberExpr>> {
  mutable std::unique_ptr<BugType> BT;

  static bool containsAnyHint(StringRef Name,
                              const char *const *Hints,
                              unsigned HintCount) {
    std::string Lowered = Name.lower();
    for (unsigned I = 0; I < HintCount; ++I) {
      if (!Hints[I])
        continue;
      if (Lowered.find(Hints[I]) != std::string::npos)
        return true;
    }
    return false;
  }

  static bool looksLikeStableHandleField(const FieldDecl *FD) {
    if (!FD)
      return false;
    StringRef Name = FD->getName();
    if (Name.empty())
      return false;

    static const char *const StableHints[] = {__STABLE_HANDLE_HINTS__};
    bool NameSuggestsHandle =
        Name.endswith("_id") ||
        Name.endswith("Id") ||
        containsAnyHint(Name, StableHints,
                        static_cast<unsigned>(sizeof(StableHints) / sizeof(StableHints[0])));
    if (!NameSuggestsHandle)
      return false;

    QualType QT = FD->getType();
    return QT->isIntegerType() ||
           QT->isEnumeralType() ||
           QT->isBooleanType() ||
           QT->isAnyCharacterType() ||
           QT->isPointerType();
  }

  static bool looksLikeCachedPointerField(const FieldDecl *FD) {
    if (!FD || !FD->getType()->isPointerType())
      return false;
    StringRef Name = FD->getName();
    if (Name.empty())
      return false;

    static const char *const CachedHints[] = {__CACHED_POINTER_HINTS__};
    return Name.endswith("_ptr") ||
           Name.endswith("Ptr") ||
           containsAnyHint(Name, CachedHints,
                           static_cast<unsigned>(sizeof(CachedHints) / sizeof(CachedHints[0])));
  }

  static bool hasAuthoritativeHandlePeer(const FieldDecl *PointerField) {
    if (!PointerField)
      return false;
    const auto *Owner = dyn_cast<RecordDecl>(PointerField->getDeclContext());
    if (!Owner)
      return false;

    for (const FieldDecl *FD : Owner->fields()) {
      if (!FD || FD == PointerField)
        continue;
      if (looksLikeStableHandleField(FD))
        return true;
    }
    return false;
  }

public:
  __CHECKER_NAME__()
      : BT(std::make_unique<BugType>(this, "Stale cached pointer use",
                                     "Memory error")) {}

  void checkPreStmt(const MemberExpr *ME, CheckerContext &C) const {
    if (!ME)
      return;

    const Expr *Base = ME->getBase();
    if (!Base)
      return;

    const auto *Inner = dyn_cast<MemberExpr>(Base->IgnoreParenImpCasts());
    if (!Inner)
      return;

    const auto *PointerField = dyn_cast_or_null<FieldDecl>(Inner->getMemberDecl());
    if (!PointerField || !looksLikeCachedPointerField(PointerField))
      return;
    if (!hasAuthoritativeHandlePeer(PointerField))
      return;

    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Direct use of a cached pointer field bypasses authoritative relookup from a stable handle",
          N);
      R->addRange(ME->getSourceRange());
      C.emitReport(std::move(R));
    }
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<__CHECKER_NAME__>(
      "custom.__CHECKER_NAME__",
      "Patch-guided stale-cache use-after-free checker",
      "");
}
"""


_USE_AFTER_FREE_TEMPLATE = """
/**
 * Patch-guided structural fallback for use-after-free refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/Version.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

REGISTER_SET_WITH_PROGRAMSTATE(FreedSymbols, SymbolRef)

namespace {

class __CHECKER_NAME__ : public Checker<check::PostCall, check::Location> {
  mutable std::unique_ptr<BugType> BT;

  static bool isReleaseLike(StringRef FuncName) {
    return FuncName == "free" ||
           FuncName == "kfree" ||
           FuncName == "delete" ||
           FuncName == "release" ||
           FuncName.ends_with("_free") ||
           FuncName.ends_with("_release") ||
           FuncName.contains("destroy");
  }

  static bool isAllocationLike(StringRef FuncName) {
    return FuncName == "malloc" ||
           FuncName == "calloc" ||
           FuncName == "realloc" ||
           FuncName == "strdup" ||
           FuncName == "strndup";
  }

  static SymbolRef getTrackedSymbol(SVal Value) {
    if (SymbolRef Sym = Value.getAsLocSymbol(true))
      return Sym;
    return Value.getAsSymbol(true);
  }

  void reportUseAfterFree(const Stmt *S, bool IsLoad, CheckerContext &C,
                          ProgramStateRef State) const {
    if (!S)
      return;
    if (ExplodedNode *N = C.generateErrorNode(State)) {
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT,
          IsLoad ? "Dereference of a previously released symbol"
                 : "Write through a previously released symbol",
          N);
      R->addRange(S->getSourceRange());
      C.emitReport(std::move(R));
    }
  }

public:
  __CHECKER_NAME__()
      : BT(std::make_unique<BugType>(this, "Use after free",
                                     "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II)
      return;

    StringRef FuncName = II->getName();
    ProgramStateRef State = C.getState();

    if (isReleaseLike(FuncName) && Call.getNumArgs() > 0) {
      SymbolRef Released = getTrackedSymbol(Call.getArgSVal(0));
      if (!Released)
        return;
      State = State->add<FreedSymbols>(Released);
      C.addTransition(State);
      return;
    }

    if (!isAllocationLike(FuncName))
      return;

    SymbolRef Fresh = getTrackedSymbol(Call.getReturnValue());
    if (!Fresh || !State->contains<FreedSymbols>(Fresh))
      return;

    State = State->remove<FreedSymbols>(Fresh);
    C.addTransition(State);
  }

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const {
    SymbolRef Accessed = getTrackedSymbol(Loc);
    if (!Accessed)
      return;

    ProgramStateRef State = C.getState();
    if (!State->contains<FreedSymbols>(Accessed))
      return;

    reportUseAfterFree(S, IsLoad, C, State);
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<__CHECKER_NAME__>(
      "custom.__CHECKER_NAME__",
      "Patch-guided use-after-free checker",
      "");
}
"""


_MEMORY_LEAK_TEMPLATE = """
/**
 * Patch-guided structural fallback for memory leak refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/Basic/Version.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

REGISTER_SET_WITH_PROGRAMSTATE(AllocatedSymbols, SymbolRef)

namespace {

class __CHECKER_NAME__ : public Checker<check::PostCall, check::DeadSymbols> {
  mutable std::unique_ptr<BugType> BT;

  static bool isAllocationLike(StringRef FuncName) {
    return FuncName == "malloc" ||
           FuncName == "calloc" ||
           FuncName == "realloc" ||
           FuncName == "strdup" ||
           FuncName == "strndup";
  }

  static bool isReleaseLike(StringRef FuncName) {
    return FuncName == "free" ||
           FuncName == "kfree" ||
           FuncName == "delete" ||
           FuncName == "release";
  }

  static SymbolRef getTrackedSymbol(SVal Value) {
    if (SymbolRef Sym = Value.getAsLocSymbol(true))
      return Sym;
    return Value.getAsSymbol(true);
  }

public:
  __CHECKER_NAME__()
      : BT(std::make_unique<BugType>(this, "Memory leak", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II)
      return;

    StringRef FuncName = II->getName();
    ProgramStateRef State = C.getState();

    if (isAllocationLike(FuncName)) {
      SymbolRef Fresh = getTrackedSymbol(Call.getReturnValue());
      if (!Fresh)
        return;
      State = State->add<AllocatedSymbols>(Fresh);
      C.addTransition(State);
      return;
    }

    if (!isReleaseLike(FuncName) || Call.getNumArgs() == 0)
      return;

    SymbolRef Released = getTrackedSymbol(Call.getArgSVal(0));
    if (!Released || !State->contains<AllocatedSymbols>(Released))
      return;

    State = State->remove<AllocatedSymbols>(Released);
    C.addTransition(State);
  }

  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    ProgramStateRef NextState = State;
    bool Reported = false;

    for (SymbolRef Sym : State->get<AllocatedSymbols>()) {
      if (!SR.isDead(Sym))
        continue;
      if (!Reported) {
        if (ExplodedNode *N = C.generateErrorNode(State)) {
          auto R = std::make_unique<PathSensitiveBugReport>(
              *BT, "Allocated memory becomes unreachable without a matching release", N);
          C.emitReport(std::move(R));
          Reported = true;
        }
      }
      NextState = NextState->remove<AllocatedSymbols>(Sym);
    }

    if (NextState != State)
      C.addTransition(NextState);
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<__CHECKER_NAME__>(
      "custom.__CHECKER_NAME__",
      "Patch-guided memory leak checker",
      "");
}
"""


_UNINITIALIZED_VARIABLE_TEMPLATE = """
/**
 * Patch-guided structural fallback for uninitialized-variable refinement.
 */

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/Version.h"
#include <memory>

using namespace clang;
using namespace ento;

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;

REGISTER_SET_WITH_PROGRAMSTATE(InitializedRegions, const MemRegion *)

namespace {

class __CHECKER_NAME__ : public Checker<check::Bind, check::Location> {
  mutable std::unique_ptr<BugType> BT;

  static const MemRegion *canonicalRegion(const MemRegion *Region) {
    if (!Region)
      return nullptr;
    Region = Region->StripCasts();
    while (const auto *Element = dyn_cast<ElementRegion>(Region))
      Region = Element->getSuperRegion();
    return Region;
  }

public:
  __CHECKER_NAME__()
      : BT(std::make_unique<BugType>(this, "Uninitialized variable",
                                     "Memory error")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const {
    (void)Val;
    (void)StoreE;
    const MemRegion *Region = canonicalRegion(Loc.getAsRegion());
    if (!Region)
      return;

    ProgramStateRef State = C.getState();
    State = State->add<InitializedRegions>(Region);
    C.addTransition(State);
  }

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const {
    if (!IsLoad || !S)
      return;

    const MemRegion *Region = canonicalRegion(Loc.getAsRegion());
    if (!Region || isa<ParmVarRegion>(Region))
      return;
    if (!isa<VarRegion>(Region) && !isa<FieldRegion>(Region))
      return;

    ProgramStateRef State = C.getState();
    if (State->contains<InitializedRegions>(Region))
      return;

    if (ExplodedNode *N = C.generateErrorNode(State)) {
      auto R = std::make_unique<PathSensitiveBugReport>(
          *BT, "Read of a variable region without a prior path-sensitive initialization", N);
      R->addRange(S->getSourceRange());
      C.emitReport(std::move(R));
    }
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<__CHECKER_NAME__>(
      "custom.__CHECKER_NAME__",
      "Patch-guided uninitialized-variable checker",
      "");
}
"""


_CSA_FAMILY_BUILDERS: dict[str, Callable[[str, _PatchMechanism], str]] = {
    "null_dereference": _build_null_dereference_family_candidate,
    "divide_by_zero": _build_divide_by_zero_family_candidate,
    "double_free": _build_double_free_family_candidate,
    "use_after_free": _build_use_after_free_family_candidate,
    "buffer_overflow": _build_buffer_overflow_family_candidate,
    "memory_leak": _build_memory_leak_family_candidate,
    "uninitialized_variable": _build_uninitialized_variable_family_candidate,
}
