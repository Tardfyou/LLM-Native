# Clang Static Analyzer Checker Template

This template provides the basic structure for a Clang Static Analyzer checker.
Replace all `{{...}}` placeholders with appropriate values for your specific checker.

## Basic Checker Structure

```cpp
//===----------------------------------------------------------------------===//
// {{CheckerName}} Checker
//===----------------------------------------------------------------------===//
//
// {{Description}}
//
//===----------------------------------------------------------------------===//

// Standard includes for all Clang Static Analyzer checkers
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"

// Include LLM-Native utility functions (from KNighter)
#include "utility.h"

{{CustomIncludes}}

using namespace clang;
using namespace ento;
using namespace taint;

//===----------------------------------------------------------------------===//
// Program State Definitions
//===----------------------------------------------------------------------===//

{{ProgramStateDefinitions}}

//===----------------------------------------------------------------------===//
// Bug Type Registration
//===----------------------------------------------------------------------===//

namespace {
class {{CheckerClassName}} : public Checker<{{CallbackTypes}}> {
  mutable std::unique_ptr<BugType> BT;

public:
  {{CheckerClassName}}() {
    // Initialize bug type with category and description
    BT.reset(new BugType(this, "{{BugCategory}}", "{{BugTypeName}}"));
  }

  {{CallbackDeclarations}}

private:
  {{HelperFunctionDeclarations}}

  // Explain the bug with a short, clear message
  void explainBug(const char *Message, ExplodedNode *ErrorNode,
                  CheckerContext &C) const {
    // Create a non-fatal error node to allow finding multiple bugs
    if (!ErrorNode) {
      ErrorNode = C.generateNonFatalErrorNode(C.getState());
    }

    if (ErrorNode) {
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, Message, ErrorNode);
      C.emitReport(std::move(Report));
    }
  }

  // Check if an expression evaluates to a known constant
  bool evalAsInt(const Expr *E, llvm::APSInt &Result,
                 CheckerContext &C) const {
    return E->EvaluateAsInt(Result, C.getASTContext());
  }

  // Get the memory region from an expression
  const MemRegion *getRegion(const Expr *E, CheckerContext &C) const {
    SVal Val = C.getSVal(E);
    if (auto RegionVal = Val.getAs<loc::MemRegionVal>()) {
      return RegionVal->getRegion()->getBaseRegion();
    }
    return nullptr;
  }

  // Check if a value is null
  bool isNull(SVal Val) const {
    if (auto ConcreteVal = Val.getAs<loc::ConcreteInt>()) {
      // getValue() returns APSIntPtr, need to dereference
      if (auto IntPtr = ConcreteVal->getValue()) {
        return *IntPtr == 0;
      }
    }
    return false;
  }

  {{AdditionalHelperFunctions}}
};

//===----------------------------------------------------------------------===//
// Callback Implementations
//===----------------------------------------------------------------------===//

{{CallbackImplementations}}

//===----------------------------------------------------------------------===//
// Helper Function Implementations
//===----------------------------------------------------------------------===//

{{HelperFunctionImplementations}}

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<{{CheckerClassName}}>(
      "{{CheckerIdentifier}}",  // e.g., "security.MyChecker"
      "{{CheckerDescription}}",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```

## Program State Macros

### Simple Trait (Single Value)
```cpp
// For tracking a single boolean/enum value
REGISTER_TRAIT_WITH_PROGRAMSTATE({{TraitName}}, {{Type}})
// Example: REGISTER_TRAIT_WITH_PROGRAMSTATE(AllocatedWithKmalloc, bool)
```

### Map Trait (Key-Value Pairs)
```cpp
// For tracking associations between keys and values
REGISTER_MAP_WITH_PROGRAMSTATE({{MapName}}, {{KeyType}}, {{ValueType}})
// Example: REGISTER_MAP_WITH_PROGRAMSTATE(RegionState, const MemRegion*, AllocationState)
```

### Set Trait (Multiple Values)
```cpp
// For tracking a collection of values
REGISTER_SET_WITH_PROGRAMSTATE({{SetName}}, {{ElementType}})
// Example: REGISTER_SET_WITH_PROGRAMSTATE(FreedRegions, const MemRegion*)
```

## Common Callback Types

### For Statement Analysis
```cpp
// Check statements before they are evaluated
checkPreStmt<{{StmtType}}>

// Check statements after they are evaluated
checkPostStmt<{{StmtType}}>

// Examples:
checkPreStmt<ReturnStmt>      // Before return
checkPostStmt<CallExpr>       // After function call
checkPreStmt<UnaryOperator>   // Before unary operation
```

### For Call Analysis
```cpp
// Check before a function call
checkPreCall

// Check after a function call
checkPostCall

// Completely evaluate a call yourself
evalCall

// Examples:
checkPreCall                 // All function calls
checkPreCall<CXXConstructor>  // C++ constructors only
```

### For Branch Analysis
```cpp
// Check branch conditions (if, while, for, etc.)
checkBranchCondition

// Example: Analyze if statement conditions
void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
```

### For Memory Operations
```cpp
// Check memory reads/writes
checkLocation

// Check value bindings (assignments)
checkBind

// Example: Track assignments to variables
void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
```

### For Function Lifecycle
```cpp
// Called when entering a function
checkBeginFunction

// Called when exiting a function
checkEndFunction

// Example: Initialize state at function entry
void checkBeginFunction(CheckerContext &C) const;
```

### For Region Changes
```cpp
// Called when memory regions are invalidated
checkRegionChanges

// Example: React to memory being modified
ProgramStateRef checkRegionChanges(ProgramStateRef State,
                                  const InvalidatedSymbols *Invalidated,
                                  ArrayRef<const MemRegion *> ExplicitRegions,
                                  ArrayRef<const MemRegion *> Regions,
                                  const LocationContext *LCtx,
                                  const CallEvent *Call) const;
```

## Callback Parameter Reference

### CheckerContext
The `CheckerContext` provides access to:
- `C.getState()` - Current program state
- `C.getLocationContext()` - Current location in the program
- `C.getASTContext()` - AST context for type information
- `C.getSourceManager()` - Source code location information
- `C.getSVal(const Expr *)` - Get symbolic value of expression
- `C.generateNonFatalErrorNode(State)` - Create error node
- `C.addTransition(State)` - Add new state transition

### ProgramState
The `ProgramStateRef` represents an abstract state:
- `State->get<{{MapName}}>(Key)` - Retrieve value from map
- `State->set<{{MapName}}>(Key, Value)` - Set value in map
- `State->remove<{{MapName}}>(Key)` - Remove key from map
- `State->contains<{{Set}}>(Value)` - Check if value in set
- `State->add<{{Set}}>(Value)` - Add value to set
- `State->getConstraintManager()` - Access constraint solver
- `State->getSVal(Expr, LocationContext)` - Get symbolic value

### SVal (Symbolic Value)
Represents abstract values:
- `Val.getAsRegion()` - Get memory region if present
- `Val.isUndef()` - Check if undefined
- `Val.isUnknown()` - Check if unknown
- `Val.getAs<loc::ConcreteInt>()` - Get concrete integer value
- `Val.getAs<nonloc::SymbolVal>()` - Get symbolic value

## Example: Simple Checker

Here's a complete example of a simple checker:

```cpp
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "utility.h"

using namespace clang;
using namespace ento;

namespace {
class SimpleExampleChecker : public Checker<check::PreStmt<CallExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SimpleExampleChecker() {
    BT.reset(new BugType(this, "Example", "Example Category"));
  }

  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const {
    // Get the function declaration
    const FunctionDecl *FD = C.getCalleeDecl(CE);
    if (!FD) return;

    // Check if this is a specific function
    if (!ExprHasName(CE, "target_function", C)) return;

    // Get the argument value
    if (CE->getNumArgs() == 0) return;
    SVal ArgVal = C.getSVal(CE->getArg(0));

    // Check if argument is null
    if (isNull(ArgVal)) {
      // Report bug
      ExplodedNode *ErrorNode = C.generateNonFatalErrorNode(C.getState());
      if (ErrorNode) {
        auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT, "Passing null to target_function", ErrorNode);
        C.emitReport(std::move(Report));
      }
    }
  }

private:
  bool isNull(SVal Val) const {
    if (Optional<loc::ConcreteInt> ConcreteVal = Val.getAs<loc::ConcreteInt>()) {
      return ConcreteVal->getValue().isZero();
    }
    return false;
  }
};
} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SimpleExampleChecker>(
      "example.SimpleExample",
      "Example checker demonstrating basic structure",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```

## Template Placeholders Guide

| Placeholder | Description | Example |
|------------|-------------|---------|
| `{{CheckerName}}` | Human-readable checker name | `UseAfterFreeChecker` |
| `{{CheckerClassName}}` | C++ class name | `UseAfterFreeChecker` |
| `{{CheckerIdentifier}}` | Checker identifier for registration | `security.useafterfree` |
| `{{CheckerDescription}}` | Short description for help text | `Detects use-after-free vulnerabilities` |
| `{{BugCategory}}` | Bug category name | `Memory Error` |
| `{{BugTypeName}}` | Specific bug type name | `Use after free` |
| `{{Description}}` | Detailed description comment | See above |
| `{{CallbackTypes}}` | List of callbacks to use | `check::PreStmt<CallExpr>, check::PostCall` |
| `{{CustomIncludes}}` | Additional includes needed | `#include "clang/AST/Attr.h"` |
| `{{ProgramStateDefinitions}}` | State trait macros | See "Program State Macros" |
| `{{CallbackDeclarations}}` | Callback function declarations | `void checkPreStmt(...)` |
| `{{CallbackImplementations}}` | Callback implementations | Actual code |
| `{{HelperFunctionDeclarations}}` | Helper function declarations | `bool isNull(SVal)` |
| `{{HelperFunctionImplementations}}` | Helper implementations | Actual code |
| `{{AdditionalHelperFunctions}}` | Extra helper methods | Any additional methods |

---
*Use this template as a starting point for your Clang Static Analyzer checker. Customize it according to your specific detection requirements.*
