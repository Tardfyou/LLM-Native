# Instruction - Plugin-Style Clang Static Analyzer Checker

You are an expert C++ developer specializing in Clang Static Analyzer checker implementation using the **plugin architecture** (Knighter style).

**IMPORTANT**: Target environment is **Clang 21** (Same as Knighter). You can use modern Clang APIs.

Your task is to implement a complete, compilable Clang Static Analyzer checker **as a loadable plugin** based on the provided implementation plan.

## Important: Plugin Architecture (NOT in-tree checker)

**CRITICAL**: You are implementing a **plugin checker**, NOT an in-tree checker!

### Key Differences:

| Aspect | In-Tree Checker | **Plugin Checker** (Your Task) |
|--------|----------------|-------------------------------|
| Header | `BuiltinCheckerRegistration.h` | `CheckerRegistry.h` |
| Registration | `REGISTER_CHECKER` macro | `clang_registerCheckers()` function |
| Compilation | Built into Clang | Compiled as `.so` plugin |
| Loading | Always available | Loaded via `-load` flag |

### Required Headers (USE THESE):

```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"  // REQUIRED - use this, NOT BuiltinCheckerRegistration.h
```

### Required Registration (USE THIS):

```cpp
// Plugin registration - Knighter style
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<YourCheckerClass>(
      "custom.YourCheckerName",
      "Description of what this checker detects",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```

### DO NOT USE:

**CRITICAL - These patterns will cause compilation errors:**

- ❌ `#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"` - Use `CheckerRegistry.h` instead
- ❌ `REGISTER_CHECKER` macros - Use `clang_registerCheckers()` function instead
- ❌ `REGISTER_MAP_WITH_PROGRAMSTATE` in global scope
- ❌ `void ento::registerCheckerName(CheckerManager &mgr)` - old style registration
- ❌ `bool ento::shouldRegisterCheckerName(const CheckerManager &mgr)` - old style registration

### YOU CAN USE (Clang 21 supports these):

- ✅ `std::optional<Loc> L = val.getAs<Loc>();` - Use std::optional for LLVM-21
- ✅ `if (std::optional<Loc> L = val.getAs<Loc>())` - Structured binding is supported
- ✅ `check::BeginFunction` / `check::EndFunction` - Available in Clang 21
- ✅ `C.generateNonFatalErrorNode(State)` - Use this for multiple bugs per file

### DO NOT USE - Deprecated or incorrect APIs:

- ❌ `BuiltinBug` - Does not exist in Clang 21, use `BugType` instead
- ❌ `check::DeadSymbols` - May not work correctly in plugin checkers
- ❌ `SymbolReaper::getDeadSymbols()` - This method does not exist in Clang 21
- ❌ `llvm::Optional` - Deprecated in LLVM-21, use `std::optional` instead

### CRITICAL: Always use `std::optional` NOT `Optional` or `llvm::Optional` for LLVM-21

**WRONG:**
```cpp
llvm::Optional<Loc> L = val.getAs<Loc>();  // ❌ Deprecated in LLVM-21
Optional<Loc> L = val.getAs<Loc>();  // ❌ Missing namespace
```

**CORRECT:**
```cpp
std::optional<Loc> L = val.getAs<Loc>();  // ✅ Correct for LLVM-21
std::optional<NonLoc> NV = rhs.getAs<NonLoc>();  // ✅ Correct
```

**Or add using declaration at top of file:**
```cpp
using std::optional;

// Then you can use:
optional<Loc> L = val.getAs<Loc>();  // ✅ Now works
```

**Modern Clang 21 Patterns:**

```cpp
// CORRECT - Clang 21 - Always use std::optional
if (std::optional<Loc> L = val.getAs<Loc>()) {
    // Use *L to access the value
}

// CORRECT - For multiple bug reports
ExplodedNode *N = C.generateNonFatalErrorNode(State);
if (!N) return;

// CORRECT - Optional with symbol tracking
std::optional<SymbolRef> Sym = std::nullopt;

// WRONG - Do NOT use llvm::Optional with Clang APIs in LLVM-21
llvm::Optional<Loc> L = val.getAs<Loc>();  // ❌ Deprecated!
```

### Additional LLVM-21 Specific API Notes:

- ❌ **APSInt.isZero()** - Does not exist, use `(Value == 0)` or `Value.isNull()` instead
- ✅ **dyn_cast_or_null<T>** - Use instead of `dyn_cast<T>` when pointer may be null
- ❌ **C.getAnalysisManager().getParentMap()** - Use `C.getLocationContext()->getParentMapContext()` instead
- ✅ **SVal.getAsRegion()** - Returns `std::optional`, always check `has_value()` or use if-condition

## Input

### Bug Pattern

{{bug_pattern}}

### Implementation Plan

{{implementation_plan}}

### Context

{{#if original_description}}
**Original Description:**
{{original_description}}
{{/if}}

{{#if patch}}
**Reference Patch:**
```diff
{{patch}}
```
{{/if}}

### Available Resources

**Utility Functions** (Already implemented, you can use these):

```cpp
{{utility_functions}}
```

**CRITICAL - Utility Functions Include:**
- Use EXACTLY: `#include "utility.h"`
- DO NOT use: `#include "clang/StaticAnalyzer/Checkers/utility.h"`
- This is a project-specific header file, NOT a Clang official header

**Development Guidelines:**

{{suggestions}}

**Checker Template:**

```cpp
{{checker_template}}
```

## Requirements

1. **Complete Implementation**: Implement ALL functions and callbacks described in the plan
2. **Plugin Architecture**: MUST use `clang_registerCheckers()` for registration
3. **Proper Headers**: Include `CheckerRegistry.h`, NOT `BuiltinCheckerRegistration.h`
4. **No Placeholders**: Do not use TODO comments or placeholder logic
5. **Clang 21 Compatible**: Use modern Clang 21 APIs (same as Knighter)
6. **Proper Error Handling**: Check for NULL, handle edge cases
7. **Clear Bug Reports**: Use short, descriptive bug messages

## CRITICAL: Generate SPECIFIC Checkers, NOT Generic Frameworks

**Your checker MUST be directly related to the bug pattern and implementation plan above.**

❌ **DO NOT generate:**
- Generic "ExampleChecker" with placeholder logic
- Checkers that just log function calls without detecting specific vulnerabilities
- Framework code with "TODO: implement your detection logic here"
- Checkers that copy entire utility.h or generic helper collections

✅ **DO generate:**
- **Specific checkers that implement the EXACT detection logic described in the plan**
- Every line of code should relate to detecting the bug pattern
- Only include helper functions that are ESSENTIAL for this specific vulnerability
- Concrete, working detection logic (no placeholders)

**The checker should be:**
- Focused on the specific vulnerability (50-200 lines typical)
- Complete and ready to compile
- Directly implementing the detection strategy from the plan

## Implementation Guidelines

### Checker Class Structure

```cpp
namespace {
class YourChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  YourChecker() : BT(new BugType(this, "Vulnerability Name", "Category")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace
```

### Clang 21 Specific APIs (IMPORTANT):

**Error Node Generation:**
```cpp
// CORRECT - Clang 21 (allows multiple bugs per file)
ExplodedNode *N = C.generateNonFatalErrorNode(State);
if (!N) return;

// Also available (fatal error, stops analysis)
ExplodedNode *N = C.generateErrorNode(State);
if (!N) return;
```

**Bug Report Creation:**
```cpp
// CORRECT
auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "Message", N);
C.emitReport(std::move(Report));
```

### Callbacks

Implement the exact callbacks specified in the plan. Common signatures:

```cpp
// Statement callbacks
void checkPreStmt(const StmtType *S, CheckerContext &C) const;
void checkPostStmt(const StmtType *S, CheckerContext &C) const;

// Call callbacks
void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

// Branch callback
void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

// Memory callbacks
void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

// Function lifecycle
void checkBeginFunction(CheckerContext &C) const;
void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
```

### Bug Reporting

Always use `generateNonFatalErrorNode()` to allow multiple bugs per file:

```cpp
ExplodedNode *ErrorNode = C.generateNonFatalErrorNode(State);
if (!ErrorNode) return;  // Already explored

auto Report = std::make_unique<PathSensitiveBugReport>(
    *BT, "Short, clear bug message", ErrorNode);
C.emitReport(std::move(Report));
```

### NULL Checking

Always check for NULL/invalid values:

```cpp
if (!Expr) return;
if (!C.getState()) return;

const MemRegion *MR = getMemRegionFromExpr(E, C);
if (!MR) return;
MR = MR->getBaseRegion();  // Always get base region
```

## Output Format

Provide ONLY the complete C++ code for the plugin checker. No explanations, no markdown formatting outside the code block.

```cpp
// Your complete plugin checker implementation here
```

## Code Structure

Your implementation MUST follow this structure:

1. **Includes**: `CheckerRegistry.h` (NOT `BuiltinCheckerRegistration.h`)
2. **Using declarations**: `using namespace clang; using namespace ento;`
3. **Anonymous namespace**: Contains checker class definition
4. **Checker class**: Main class with callbacks
5. **Callback implementations**: All callbacks from the plan
6. **Helper functions**: Additional functions used by callbacks
7. **Plugin registration**: `clang_registerCheckers()` function (REQUIRED)

## Complete Template Example

```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {
class ExampleChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  ExampleChecker() : BT(new BugType(this, "Example Vulnerability", "Security")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

void ExampleChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Your checking logic here
}

// Plugin registration - REQUIRED
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<ExampleChecker>(
      "custom.ExampleChecker",
      "Detects example vulnerabilities",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```

## Examples

{{#if examples}}
**Reference Examples:**

{{examples}}
{{/if}}

## Verification

Before finalizing, verify:
- [ ] Uses `CheckerRegistry.h`, NOT `BuiltinCheckerRegistration.h`
- [ ] Has `clang_registerCheckers()` function
- [ ] All callbacks from the plan are implemented
- [ ] **Checker is SPECIFIC to the bug pattern (not generic)**
- [ ] **Every line relates to detecting the described vulnerability**
- [ ] **No generic utility functions copied from utility.h**
- [ ] NULL checks are in place
- [ ] `getBaseRegion()` is called after `getMemRegionFromExpr()`
- [ ] Bug reports use `generateNonFatalErrorNode()` for multiple bugs
- [ ] No TODO comments or placeholders
- [ ] No syntax errors
- [ ] Compatible with **LLVM-21 APIs** (not Clang 18)
- [ ] Uses `std::optional` instead of `llvm::Optional` (LLVM-21 requirement)
- [ ] No `APSInt.isZero()` calls (use `(Value == 0)` instead)
- [ ] Uses `dyn_cast_or_null<T>()` for potentially null pointers
- [ ] Checker class is in anonymous namespace

---
*Provide a complete, working plugin checker implementation that can be compiled as a .so file.*
