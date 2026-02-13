//===----------------------------------------------------------------------===//
// UninitMemoryCopyChecker - Detect copying uninitialized memory to user space
//===----------------------------------------------------------------------===//
//
// This checker detects potential kernel information leaks where memory
// allocated with kmalloc() (which returns uninitialized memory) is copied
// to user space using copy_to_user() without proper initialization.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"

#include "utility.h"

using namespace clang;
using namespace ento;

//===----------------------------------------------------------------------===//
// Program State Definitions
//===----------------------------------------------------------------------===//

// Track initialization status of memory regions
// true = initialized (safe), false = uninitialized (potentially unsafe)
REGISTER_MAP_WITH_PROGRAMSTATE(UninitMemoryMap, const MemRegion*, bool)

//===----------------------------------------------------------------------===//
// Bug Type Registration
//===----------------------------------------------------------------------===//

namespace {
class UninitMemoryCopyChecker : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  UninitMemoryCopyChecker() {
    BT.reset(new BugType(this, "Kernel Information Leak", "Security"));
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  // Get the memory region from an expression
  const MemRegion *getRegion(const Expr *E, CheckerContext &C) const {
    if (!E) return nullptr;
    ProgramStateRef State = C.getState();
    SVal Val = State->getSVal(E, C.getLocationContext());
    if (Optional<loc::MemRegionVal> RegionVal = Val.getAs<loc::MemRegionVal>()) {
      const MemRegion *MR = RegionVal->getRegion();
      return MR ? MR->getBaseRegion() : nullptr;
    }
    return nullptr;
  }

  // Report bug with appropriate message
  void explainBug(const char *Message, ExplodedNode *ErrorNode,
                  CheckerContext &C) const {
    if (!ErrorNode) {
      ErrorNode = C.generateNonFatalErrorNode(C.getState());
    }

    if (ErrorNode) {
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, Message, ErrorNode);
      C.emitReport(std::move(Report));
    }
  }
};

//===----------------------------------------------------------------------===//
// Callback Implementations
//===----------------------------------------------------------------------===//

void UninitMemoryCopyChecker::checkPostCall(const CallEvent &Call,
                                            CheckerContext &C) const {
  // Check if this is kmalloc or kzalloc
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr) return;

  if (!ExprHasName(OriginExpr, "kmalloc", C) &&
      !ExprHasName(OriginExpr, "kzalloc", C)) {
    return;
  }

  // Get the return value region
  SVal RetVal = Call.getReturnValue();
  const MemRegion *MR = RetVal.getAsRegion();
  if (!MR) return;
  MR = MR->getBaseRegion();

  // Determine if this allocation is initialized
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  bool isInitialized = Callee && Callee->getName().contains("kzalloc");

  // Update state
  ProgramStateRef State = C.getState();
  State = State->set<UninitMemoryMap>(MR, isInitialized);
  C.addTransition(State);
}

void UninitMemoryCopyChecker::checkPreCall(const CallEvent &Call,
                                           CheckerContext &C) const {
  // Check if this is copy_to_user
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "copy_to_user", C)) {
    return;
  }

  // copy_to_user(to, from, n)
  // Second argument (index 1) is the source in kernel space
  if (Call.getNumArgs() < 2) return;

  const Expr *SrcExpr = Call.getArgExpr(1);
  const MemRegion *SrcMR = getRegion(SrcExpr, C);
  if (!SrcMR) return;

  ProgramStateRef State = C.getState();

  // Check if this region is tracked
  const bool *Tracked = State->get<UninitMemoryMap>(SrcMR);
  if (!Tracked) return;  // Not tracked, can't determine

  // If tracked as uninitialized, report bug
  if (!*Tracked) {
    ExplodedNode *ErrorNode = C.generateNonFatalErrorNode(State);
    explainBug("Potential kernel information leak: copying uninitialized memory to user space",
               ErrorNode, C);
  }
}

void UninitMemoryCopyChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                        CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) return;
  MR = MR->getBaseRegion();

  ProgramStateRef State = C.getState();

  // If this region is tracked, update its status
  if (State->contains<UninitMemoryMap>(MR)) {
    const bool *Status = State->get<UninitMemoryMap>(MR);
    // If currently uninitialized and we're binding a value, mark as initialized
    if (Status && !*Status) {
      State = State->set<UninitMemoryMap>(MR, true);
      C.addTransition(State);
    }
  }
}

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<UninitMemoryCopyChecker>(
      "security.uninitmemorycopy",
      "Detects copying of uninitialized kernel memory to user space",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
