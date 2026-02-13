# Instruction - Plugin-Style Clang Static Analyzer Checker

You are an expert C++ developer specializing in Clang Static Analyzer checker implementation using the **plugin architecture** (Knighter style).

**IMPORTANT**: Target environment is **Clang 21** (Same as Knighter). You can use modern Clang APIs.

## ⚠️ CRITICAL: KEEP IT SIMPLE AND FOCUSED ⚠️

**Your checker MUST be:**
- **100-200 lines total** - No more!
- **Single callback** - Only implement what the patch specifically fixes
- **No complex state tracking** - Don't add features not in the patch
- **No helper functions** unless absolutely essential
- **Direct and simple** - Implement the exact vulnerability detection logic

**The patch shows exactly what vulnerability to detect. Implement ONLY that detection.**

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

### ⚠️ CRITICAL: Hallucinated APIs That DO NOT EXIST

**The following APIs are NOT part of Clang - NEVER use them:**

| ❌ Hallucinated API | ✅ Correct Alternative |
|-------------------|----------------------|
| `isCallToFunction(Call, "name")` | `Call.getCalleeIdentifier()->getName() == "name"` |
| `Call.isCalled(CFunction())` | `Call.getCalleeIdentifier()->getName() == "func"` |
| `getElementSize(type)` | `C.getASTContext().getTypeSize(type)` |
| `getBufferSize(expr)` | `C.getASTContext().getTypeSize(expr->getType())` |
| `getArraySize(array)` | `C.getASTContext().getTypeSize(array->getType())` |
| `evaluateToInt(expr, C)` | `EvaluateExprToInt(result, expr, C)` from utility.h |
| `getMaxSignedBits()` | `getBitWidth()` |
| `APSInt.isZero()` | `*APSInt == 0` or `APSInt->getExtValue() == 0` |
| `State->isNull(SVal)` | `State->assume(SVal.castAs<DefinedOrUnknownSVal>()).first` |
| `PathDiagnosticLocation::createBegin(S, SM, LC)` | `PathDiagnosticLocation(S, SM)` |

**Examples:**

```cpp
// ❌ WRONG - isCallToFunction does NOT exist
if (isCallToFunction(Call, "strcpy")) { }

// ✅ CORRECT - use getCalleeIdentifier()
const IdentifierInfo *II = Call.getCalleeIdentifier();
if (II && II->getName() == "strcpy") { }

// ❌ WRONG - getElementSize does NOT exist
size_t size = getElementSize(type);

// ✅ CORRECT - use ASTContext
uint64_t size = C.getASTContext().getTypeSize(type);

// ❌ WRONG - APInt cannot be directly assigned to APSInt
llvm::APSInt sizeValue = sizeAPInt;

// ✅ CORRECT - use APSInt constructor
llvm::APSInt sizeValue(sizeAPInt, true);

// ❌ WRONG - createBegin takes different parameters in LLVM-21
Report->addNote(Msg, PathDiagnosticLocation::createBegin(S, C.getSourceManager(), C.getLocationContext()));

// ✅ CORRECT - use PathDiagnosticLocation constructor
Report->addNote(Msg, PathDiagnosticLocation(S, C.getSourceManager()));
```

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
- ⚠️ **State->get<MapType>(Key)** - Returns `const Value*const *` (double pointer), must dereference twice: `**Ptr`
- ❌ **REGISTER_MAP_WITH_PROGRAMSTATE** - Do NOT use in plugin checkers unless you fully understand the double pointer API
- ❌ **TypedValueRegion::getDecl()** - Does not exist, use `VarRegion::getDecl()` or `FieldRegion::getDecl()` instead

## CRITICAL: LLVM-21 Type System Rules (MUST FOLLOW)

### ⚠️ CRITICAL: Common API Mistakes That Cause Compilation Errors

The following are the most common errors that appear in generated code. **AVOID THESE PATTERNS:**

#### 1. APSIntPtr Type Error

**WRONG:**
```cpp
if (APSIntPtrVal.isZero()) { ... }        // ❌ isZero() doesn't exist
if (APSIntPtrVal == 0) { ... }         // ❌ APSIntPtr is a POINTER!
```

**CORRECT:**
```cpp
if (APSIntPtrVal && *APSIntPtrVal == 0) { ... }  // ✅ Dereference first
// OR
if (APSIntPtrVal) {
    if (*APSIntPtrVal == 0) { ... }               // ✅ Check null then dereference
}
```

**KEY RULE:** `APSIntPtr` is `const llvm::APSInt*` - a **pointer** type. Must be:
- Checked for null: `if (ptr)` before dereferencing
- Dereferenced with `*`: `*ptr` or `ptr->getExtValue()`
- Compared using dereferenced value: `*ptr == 0`

#### 2. SymbolRef Type Error

**WRONG:**
```cpp
if (SymbolRef Sym = Val.getAsSymbol()) {
    // Trying to use Sym as SymbolRef type...
}
SVal SymVal = nonloc::SymbolVal(Sym);  // ❌ Wrong API
```

**CORRECT:**
```cpp
// Option 1: Use SymbolRef directly (it IS const SymExpr*)
if (SymbolRef Sym = Val.getAsSymbol()) {
    SValBuilder &SVB = C.getSValBuilder();
    SVal SymVal = SVB.makeSymbolVal(Sym);
    // Use SymVal
}

// Option 2: Just use the original SVal
if (auto DV = Val.getAs<DefinedSVal>()) {
    auto [StateTrue, StateFalse] = State->assume(DV, true);
}
```

**KEY RULE:**
- `SymbolRef` = `typedef const SymExpr* SymbolRef` (it's a pointer type!)
- `Val.getAsSymbol()` returns `const SymExpr*` which IS `SymbolRef`
- Use `SValBuilder::makeSymbolVal()` to create SVal from symbol

#### 3. getSymVal API Error

**WRONG:**
```cpp
const llvm::APSInt *Zero = nullptr;
State->getConstraintManager().getSymVal(State, Sym, Zero);  // ❌ Wrong signature
```

**CORRECT:**
```cpp
// Use assume() method with comparison
SValBuilder &SVB = C.getSValBuilder();
llvm::APInt ZeroVal(32, 0);
DefinedOrUnknownSVal ZeroConst = SVB.makeIntConst(ZeroVal);
DefinedOrUnknownSVal EqualsZero = SVB.evalBinOp(State, BO_EQ, SymVal, ZeroConst);

ProgramStateRef StTrue, StFalse;
std::tie(StTrue, StFalse) = State->assume(EqualsZero, true);
```

#### 4. Report Variable Name Error

**WRONG:**
```cpp
auto report = std::make_unique<PathSensitiveBugReport>(...);
report->addRange(...);
C.emitReport(std::move(report));
```

**CORRECT:**
```cpp
auto Report = std::make_unique<PathSensitiveBugReport>(...);  // Capital R
Report->addRange(...);
C.emitReport(std::move(Report));
```

### Copy-Paste Safe Patterns

#### Pattern 1: Null pointer dereference detection

```cpp
void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
    ProgramStateRef State = C.getState();

    // Check if location might be null
    if (Loc.getAs<loc::ConcreteInt>()) {
        // Concrete null pointer - definite bug
        ExplodedNode *N = C.generateErrorNode(State);
        if (N) {
            auto Report = std::make_unique<PathSensitiveBugReport>(*BT_NullDeref,
                "Dereference of null pointer", N);
            C.emitReport(std::move(Report));
        }
    } else if (const MemRegion *MR = Loc.getAsRegion()) {
        // Symbolic region - check constraints
        SValBuilder &SVB = C.getSValBuilder();
        SVal NullVal = SVB.makeNull();

        DefinedOrUnknownSVal IsNull = SVB.evalBinOp(State, BO_EQ,
            Loc.castAs<DefinedOrUnknownSVal>(),
            NullVal, SVB.getConditionType());

        ProgramStateRef StNotNull, StNull;
        std::tie(StNotNull, StNull) = State->assume(IsNull, true);

        if (StNull && !StNotNull) {
            // Definitely null
            ExplodedNode *N = C.generateErrorNode(StNull);
            if (N) {
                auto Report = std::make_unique<PathSensitiveBugReport>(*BT_NullDeref,
                    "Dereference of null pointer", N);
                C.emitReport(std::move(Report));
            }
        }
    }
}
```

#### Pattern 2: Checking pointer arguments

```cpp
void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
        SVal ArgVal = Call.getArgSVal(i);

        // Check if argument might be null
        if (const MemRegion *MR = ArgVal.getAsRegion()) {
            if (const MemRegion *R = MR->getBaseRegion()) {
                // Use constraint checking
                ProgramStateRef State = C.getState();
                SValBuilder &SVB = C.getSValBuilder();
                SVal NullVal = SVB.makeNull();

                DefinedOrUnknownSVal IsNull = SVB.evalBinOp(State, BO_EQ,
                    ArgVal.castAs<DefinedOrUnknownSVal>(),
                    NullVal, SVB.getConditionType());

                ProgramStateRef StNotNull, StNull;
                std::tie(StNotNull, StNull) = State->assume(IsNull, true);

                if (StNull && !StNotNull) {
                    // Definitely null - report
                    ExplodedNode *N = C.generateErrorNode(StNull);
                    if (N) {
                        auto Report = std::make_unique<PathSensitiveBugReport>(*_BT_NullArg,
                            "Null pointer passed as argument", N);
                        C.emitReport(std::move(Report));
                    }
                }
            }
        }
    }
}
```

### Pointer Type Handling - The #1 Source of Errors

**MANY types in LLVM-21 are pointers. You MUST understand pointer vs value:**

```cpp
// ❌ WRONG - Calling method on pointer without dereferencing
if (APSIntPtrVal.isZero()) ...

// ❌ WRONG - Comparing pointer address to integer value
if (APSIntPtrVal == 0) ...

// ✅ CORRECT - Dereference pointer first
if (*APSIntPtrVal == 0) ...

// ✅ CORRECT - Check null, then dereference
if (APSIntPtrVal && *APSIntPtrVal == 0) ...

// ✅ CORRECT - Use arrow operator (preferred)
if (APSIntPtrVal && APSIntPtrVal->getExtValue() == 0) ...
```

**Key Pattern - Always Check Null Before Dereference:**
```cpp
// For ANY pointer type (APSIntPtr, MemRegion*, etc.)
if (PointerVal && *PointerVal == 0) {  // ✅ Safe
    // Use *PointerVal
}
```

### std::optional Handling - getAsRegion(), getAs()

```cpp
// ❌ WRONG - Not checking if optional has value
const MemRegion *MR = Val.getAsRegion();
if (MR) { ... }

// ❌ WRONG - Using optional directly without extracting value
if (Val.getAsRegion()) { ... }

// ✅ CORRECT - Proper std::optional handling
if (std::optional<const MemRegion*> MR = Val.getAsRegion()) {
    if (*MR) {  // Check the inner pointer value
        // Use **MR (double dereference: optional -> pointer -> region)
        const MemRegion *Base = (*MR)->getBaseRegion();
    }
}

// ✅ CORRECT - has_value() method
auto MR = Val.getAsRegion();
if (MR.has_value()) {
    const MemRegion *R = *MR;  // Extract value from optional
    if (R) {
        // Safe to use R
    }
}

// ✅ CORRECT - Short form for common pattern
if (auto MR = Val.getAsRegion(); MR && *MR) {
    // Use *MR directly
}
```

### Utility Functions - CheckerContext Required

```cpp
// ❌ WRONG - Missing CheckerContext argument
const MemRegion *MR = getMemRegionFromExpr(Expr);
getMemRegionFromExpr(Expr, C, /*extra*/);

// ✅ CORRECT - These utility functions require CheckerContext
const MemRegion *MR = getMemRegionFromExpr(Expr, C);
if (MR) {
    MR = MR->getBaseRegion();  // Always call getBaseRegion()
}

// ❌ WRONG - EvaluateExprToInt wrong usage
EvaluateExprToInt(Result, Expr, C);

// ✅ CORRECT - Pass reference to store result
llvm::APSInt Result;
if (EvaluateExprToInt(Result, Expr, C)) {
    int value = Result.getExtValue();
}
```

### Type Reference Quick Reference

| Type | Is Pointer? | Correct Usage |
|------|-------------|--------------|
| `APSIntPtr` | ✅ Yes | `if (ptr && *ptr == 0)` or `ptr->getExtValue()` |
| `const MemRegion*` | ✅ Yes | `if (MR) MR->getBaseRegion()` |
| `std::optional<T*>` | ❌ No | `if (opt && *opt)` or `if (opt.has_value())` |
| `SVal` | ❌ No | Use `getAs<Type>()` to extract |
| `SymbolRef` | ✅ Yes (pointer) | Cannot convert to SVal directly |

### CRITICAL: SymbolRef to SVal Conversion (Common Error!)

**SymbolRef is NOT directly convertible to SVal. This is a very common mistake!**

```cpp
// ❌ WRONG - getAsSymbol() returns SymExpr*, not directly assignable to SymbolRef
SymbolRef Sym = Val.getAsSymbol();  // Type mismatch!

// ❌ WRONG - Cannot construct SVal from SymbolRef directly
SVal SymVal = SVal(Sym);  // ERROR

// ✅ CORRECT - SymbolRef IS const SymExpr*, so the assignment works
// (SymbolRef is typedef'd as const SymExpr*)
if (SymbolRef Sym = Val.getAsSymbol()) {
    // Sym is const SymExpr*, can be used with SValBuilder
    SValBuilder &SVB = C.getSValBuilder();
    SVal SymVal = SVB.makeSymbolVal(Sym);
    // Use SymVal
}

// ✅ EVEN BETTER - Just use the original SVal directly!
// If you already have an SVal, use it - no need to convert back and forth
SVal Val = State->getSVal(Expr, C.getLocationContext());
if (auto DV = Val.getAs<DefinedOrUnknownSVal>()) {
    auto [StateTrue, StateFalse] = State->assume(DV, true);
    // Use the state that proves the value
}

// ✅ CORRECT - For null pointer checking with symbols
SVal Val = State->getSVal(Expr, C.getLocationContext());
if (auto DV = Val.getAs<DefinedOrUnknownSVal>()) {
    auto [StateNotNull, StateNull] = State->assume(*DV);
    if (StateNull && !StateNotNull) {
        // Pointer is definitely null
    }
}
```

### Common Patterns to Use

**Checking a pointer's value:**
```cpp
// Pattern 1: Direct comparison
if (Ptr && *Ptr == 0) { ... }

// Pattern 2: Using getExtValue()
if (APSIntPtrVal && APSIntPtrVal->getExtValue() == 0) { ... }
```

**Working with optional returns:**
```cpp
// Pattern: getAsRegion()
if (auto MR = Val.getAsRegion(); MR && *MR) {
    const MemRegion *Base = (*MR)->getBaseRegion();
}

// Pattern: getAs<Loc>()
if (auto L = Val.getAs<Loc>()) {
    // Use *L
}
```

**Always include null safety:**
```cpp
// For any pointer or optional
if (value && *value == target) { ... }
if (optional && *optional) { ... }
```

## Pattern and Plan Paradigm

**When generating your checker, follow these formats for the vulnerability pattern and implementation plan:**

### Vulnerability Pattern Format

```
## Vulnerability Pattern

[Pattern Name]

Description:
- A function receives a pointer as a parameter
- The function directly dereferences the pointer (e.g., accesses member fields or calls methods via `->` operator) without first verifying the pointer is not null
- This can lead to undefined behavior/crash if the caller passes a null pointer

Code Example:
```cpp
void processObject(Object* obj) {
    // Missing: if (obj == nullptr) return;
    obj->doSomething();  // Potential null pointer dereference
    int x = obj->value;  // Potential null pointer dereference
}
```

Fix Example:
```cpp
void processObject(Object* obj) {
    if (obj == nullptr) {  // Added null check
        // Handle error or return early
        return;
    }
    obj->doSomething();  // Safe dereference after null check
    int x = obj->value;
}
```
```

### Implementation Plan Format

```
## Implementation Plan

1. [Step Name - e.g., Initialization and Modeling]
   • [Action 1]
   • [Action 2]
   • [Action 3]

2. [Step Name - e.g., Modeling Memory Allocation]
   • [Action 1]
   • [Action 2]
   • [Action 3]

3. [Step Name - e.g., Modeling Memory Deallocation]
   • [Action 1]
   • [Action 2]
   • [Action 3]

...

Each step should include:
- Clear objectives
- Specific callbacks to use (e.g., check::PreCall, check::Location)
- State tracking requirements (if any)
- Error detection and reporting logic
```

**Example Implementation Plan (MallocChecker style):**

```
## Implementation Plan

1. Initialization and Modeling of Memory Regions
   • Set up program–state maps (for example, a RegionState map keyed by the allocation's "symbol") that hold a "RefState" value
   • Register the checker with the CheckerRegistry and initialize bug types for various reports

2. Modeling Memory Allocation
   • In callbacks for allocation calls (e.g. for malloc, calloc, new), intercept the call (via checkPostCall or EvalCall)
   • Create a symbolic heap region for the returned pointer using helper functions
   • Initialize the region's state by storing a RefState showing that the memory has been allocated

3. Modeling Memory Deallocation
   • Intercept deallocation calls (free, delete) in checkPreCall or checkPostCall
   • Call helper functions to update state
   • Detect errors like double free, free on non-heap regions, etc.

4. Reporting Bugs
   • When an error condition is detected, invoke handler functions
   • Generate a non-fatal error node and create a PathSensitiveBugReport
```

## Input

### Vulnerability Description

{{vulnerability_pattern}}

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

### Reference Examples from Knighter Database

The following are complete examples from Knighter's checker database. Each example includes:
- **Pattern Description**: The vulnerability pattern being detected
- **Implementation Plan**: Step-by-step plan for implementing the checker
- **Checker Implementation**: Complete working code

Use these as reference to understand the structure and approach:

{{#each rag_context}}
---
**Example: {{this.title}}**

{{this.content}}

---
{{/each}}

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

## Complete Template Example - Minimal Null Pointer Checker

**This is an EXAMPLE of a SIMPLE, FOCUSED checker (only ~60 lines!)**

```cpp
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "utility.h"  // For helper functions

using namespace clang;
using namespace ento;

namespace {
// Simple null pointer dereference checker
class NullPointerDereferenceChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  NullPointerDereferenceChecker() : BT(new BugType(this, "Null Pointer Dereference", "Security")) {}

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

void NullPointerDereferenceChecker::checkLocation(SVal Loc, bool IsLoad,
                                                     const Stmt *S,
                                                     CheckerContext &C) const {
  // Only check dereferences (loads and stores)
  if (!IsLoad) return;

  // Get the pointer being dereferenced
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;

  // Get the symbol for the pointer
  ProgramStateRef State = C.getState();
  SVal PtrVal = State->getSVal(Loc, C.getLocationContext());

  // Check if the pointer is definitely null
  if (auto DV = PtrVal.getAs<DefinedOrUnknownSVal>()) {
    auto [StateNotNull, StateNull] = State->assume(*DV);
    if (StateNull && !StateNotNull) {
      // Definitely null - report bug!
      ExplodedNode *N = C.generateNonFatalErrorNode(StateNull);
      if (!N) return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Dereference of null pointer", N);
      C.emitReport(std::move(Report));
    }
  }
}

// Plugin registration - REQUIRED
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<NullPointerDereferenceChecker>(
      "security.NullPointerDereference",
      "Detects null pointer dereferences",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
```

**Key Points:**
- **Single callback** (`check::Location`) - only what we need
- **No state tracking** - no REGISTER_MAP, no complex logic
- **Simple detection** - check if pointer is null, report if so
- **~60 lines total** - this is the target size!

## Examples

{{#if examples}}
**Reference Examples:**

{{examples}}
{{/if}}

## Verification

Before finalizing, verify:
- [ ] **Total code is 100-200 lines maximum**
- [ ] Uses `CheckerRegistry.h`, NOT `BuiltinCheckerRegistration.h`
- [ ] Has `clang_registerCheckers()` function
- [ ] **Single callback only** - don't add extra callbacks
- [ ] **No state tracking macros** (REGISTER_MAP, etc.)
- [ ] **No helper function bloat** - only if essential
- [ ] [ ] **Checker is SPECIFIC to the bug pattern (not generic)**
- [ ] [ ] **Every line relates to detecting the described vulnerability**
- [ ] [ ] **No generic utility functions copied from utility.h**
- [ ] NULL checks are in place
- [ ] Bug reports use `generateNonFatalErrorNode()` for multiple bugs
- [ ] No TODO comments or placeholders
- [ ] No syntax errors
- [ ] Compatible with **LLVM-21 APIs** (not Clang 18)
- [ ] Uses `std::optional` instead of `llvm::Optional` (LLVM-21 requirement)
- [ ] No `APSInt.isZero()` calls (use proper pointer dereferencing)
- [ ] Uses `dyn_cast_or_null<T>()` for potentially null pointers
- [ ] Checker class is in anonymous namespace

---
*Provide a complete, working plugin checker implementation that can be compiled as a .so file.*
