## Role

You are an expert in developing and analyzing Clang Static Analyzer checkers, with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

## Instruction

The following checker fails to compile. Your task is to **fix the compilation errors while preserving the SPECIFIC vulnerability detection logic**.

**CRITICAL: Your repair must:**
1. Fix ALL compilation errors
2. **PRESERVE the original vulnerability detection intent** - Do NOT turn specific checkers into generic ones
3. **Keep the detection logic specific** - Do not replace concrete logic with placeholders or TODOs
4. **Return the complete, compilable checker code**

## What Your Repair MUST Do

✅ **DO:**
- Fix API compatibility issues (LLVM-21)
- Fix missing headers, type mismatches, syntax errors
- Preserve the SPECIFIC vulnerability detection logic
- Keep concrete implementations (no placeholders)

❌ **DO NOT:**
- Replace specific detection logic with generic placeholders
- Add TODO comments or "implement your logic here"
- Turn a specific checker into a generic framework
- Remove actual detection code and replace with stubs

## Fixing Common Errors

### First: Check Code Structure

Before fixing APIs, **verify the basic code structure is complete**:

1. **All braces match** - Count `{` and `}`, ensure they match
2. **All statements end with `;`** - Especially after class declarations
3. **All functions/methods are complete** - No truncated implementations
4. **No incomplete blocks** - Every `{` must have a matching `}`

### Then: Fix API Issues

1. **Use the correct API**: The current API may not exist, or the class has no such member. Replace it with an appropriate one.

2. **Use correct arguments**: Ensure the arguments passed to the API have the correct types and the correct number.

3. **Change variable types**: Adjust the types of some variables based on the error messages.

4. **Include valid headers**: Be careful with header files. Make sure the header file exists.
   - Valid: `"clang/StaticAnalyzer/Core/Checker.h"`
   - Invalid: `"clang/StaticAnalyzer/Core/PathDiagnostic.h"` (doesn't exist)

**The version of Clang environment is Clang-21. You should consider the API compatibility.**

## LLVM-21 Specific Fixes

1. **Use `std::optional` instead of `llvm::Optional`**:
   ```cpp
   // WRONG (deprecated)
   Optional<DefinedOrUnknownSVal> SizeSVal;

   // CORRECT
   std::optional<DefinedOrUnknownSVal> SizeSVal;
   ```

2. **APSInt.isZero() does not exist**:
   ```cpp
   // WRONG
   if (APSIntVal.isZero()) ...

   // CORRECT
   if (APSIntVal == 0 || APSIntVal.isNull()) ...
   ```

3. **ParentMap API change**:
   ```cpp
   // WRONG
   C.getAnalysisManager().getParentMap()

   // CORRECT
   C.getLocationContext()->getParentMapContext()
   ```

4. **SVal.getAsRegion() returns std::optional**:
   ```cpp
   // CORRECT
   if (std::optional<const MemRegion*> MR = Val.getAsRegion()) {
       // Use *MR
   }
   ```

5. **For utility functions**:
   ```cpp
   // Include this instead of copying utility functions
   #include "utility.h"
   ```

## LLVM-21 Type System Critical Fixes (HIGH PRIORITY)

### Problem 1: Pointer Types - APSIntPtr, MemRegion*, etc.

**CRITICAL:** Many types in LLVM-21 are **pointers** (`*`). You must **dereference** them before using.

#### APSIntPtr (const llvm::APSInt*)

```cpp
// ❌ WRONG - Trying to call method on pointer type
if (APSIntPtrVal.isZero()) ...

// ❌ WRONG - Comparing pointer directly to int (pointer vs int comparison)
if (APSIntPtrVal == 0) ...

// ✅ CORRECT - Dereference pointer first, then compare
if (*APSIntPtrVal == 0) ...

// ✅ CORRECT - Check null pointer first, then dereference
if (APSIntPtrVal && *APSIntPtrVal == 0) ...

// ✅ CORRECT - Use arrow operator (preferred)
if (APSIntPtrVal && APSIntPtrVal->isZero()) ...

// ✅ CORRECT - Get integer value
if (APSIntPtrVal && APSIntPtrVal->getExtValue() == 0) ...
```

#### Key Understanding:
```cpp
APSIntPtr    = const llvm::APSInt*    // This is a POINTER!
APSInt       = llvm::APSInt         // This is a VALUE

// To get value from pointer:
*APSIntPtrVal                      // Dereference
APSIntPtrVal->getExtValue()        // Call method on pointer
```

### Problem 2: std::optional Handling - getAsRegion(), getAs()

```cpp
// ❌ WRONG - Not checking if optional has value
const MemRegion *MR = Val.getAsRegion();
if (MR) { ... }  // This might compile but is not the correct way

// ❌ WRONG - Trying to use optional directly
if (Val.getAsRegion()) { ... }

// ✅ CORRECT - Proper std::optional handling
if (std::optional<const MemRegion*> MR = Val.getAsRegion()) {
    if (*MR) {
        // Use **MR (double dereference: optional -> pointer -> value)
        const MemRegion *Base = (*MR)->getBaseRegion();
    }
}

// ✅ CORRECT - Alternative: has_value() method
auto MR = Val.getAsRegion();
if (MR.has_value()) {
    const MemRegion *R = *MR;
    if (R) {
        // Use R
    }
}

// ✅ CORRECT - Short form with structured binding
if (auto MR = Val.getAsRegion(); MR && *MR) {
    // Use *MR
}
```

### Problem 3: Function Signature - getMemRegionFromExpr, EvaluateExprToInt

```cpp
// ❌ WRONG - Wrong number of arguments
const MemRegion *MR = getMemRegionFromExpr(Expr);
const MemRegion *MR = getMemRegionFromExpr(Expr, C, /*extra_arg*/);

// ✅ CORRECT - These utility functions require CheckerContext
const MemRegion *MR = getMemRegionFromExpr(Expr, C);
if (MR) MR = MR->getBaseRegion();

// ❌ WRONG - EvaluateExprToInt returns bool, void result
EvaluateExprToInt(Result, Expr, C);

// ✅ CORRECT - Pass reference to store result
llvm::APSInt Result;
if (EvaluateExprToInt(Result, Expr, C)) {
    int value = Result.getExtValue();
}
```

### Problem 4: Null Safety Pattern (Always use!)

```cpp
// ❌ WRONG - No null check before dereference
const MemRegion *MR = getMemRegionFromExpr(E, C);
const MemRegion *Base = MR->getBaseRegion();  // CRASH if MR is null!

// ✅ CORRECT - Always check null pointers first
const MemRegion *MR = getMemRegionFromExpr(E, C);
if (MR) {
    const MemRegion *Base = MR->getBaseRegion();
    // Use Base
}

// ✅ CORRECT - For pointer chains
if (auto MR = Val.getAsRegion(); MR && *MR) {
    const MemRegion *Base = (*MR)->getBaseRegion();
    // Safe to use Base
}
```

### Type Reference Quick Guide

| Type | Is Pointer? | How to Get Value | How to Check |
|------|-------------|-----------------|--------------|
| `APSIntPtr` | ✅ Yes | `*ptr` or `ptr->getExtValue()` | `if (ptr)` |
| `const MemRegion*` | ✅ Yes | `ptr->getBaseRegion()` | `if (ptr)` |
| `std::optional<T*>` | ❌ No | `*opt` (gives `T*`) | `if (opt)` or `opt.has_value()` |
| `SVal` | ❌ No | Use `getAs<Type>()` | N/A |

### Common Error Patterns and Fixes

#### Error: "invalid operands to binary expression ('APSIntPtr' and 'int')"

```cpp
// Cause: Comparing pointer to int directly
if (APSIntPtrVal == 0) { ... }

// Fix: Dereference pointer first
if (*APSIntPtrVal == 0) { ... }
```

#### Error: "no member named 'isZero' in 'clang::ento::APSIntPtr'"

```cpp
// Cause: Calling method on pointer without dereferencing
if (APSIntPtrVal.isZero()) { ... }

// Fix: Use arrow operator or dereference
if (APSIntPtrVal->isZero()) { ... }
// OR
if (*APSIntPtrVal == 0) { ... }
```

#### Error: "no viable conversion from 'const llvm::APSInt*' to 'std::optional<llvm::APSInt>'"

```cpp
// Cause: Trying to assign pointer to std::optional value
std::optional<llvm::APSInt> Opt = APSIntPtrVal;

// Fix: Dereference pointer to get value, then wrap in optional
if (APSIntPtrVal) {
    std::optional<llvm::APSInt> Opt = *APSIntPtrVal;
}
```

## Copy-Paste Safe Patterns

When in doubt, use these proven patterns from Knighter checkers:

### Pattern 1: Null pointer dereference detection

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

### Pattern 2: Checking pointer arguments

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

### Pattern 3: Creating SVal from Symbol

```cpp
// ✅ CORRECT
if (SymbolRef Sym = Val.getAsSymbol()) {  // SymbolRef IS const SymExpr*
    SValBuilder &SVB = C.getSValBuilder();
    SVal SymVal = SVB.makeSymbolVal(Sym);
    // Now SymVal can be used in assume(), etc.
}
```

### Pattern 4: Comparing APSIntPtr values

```cpp
// ✅ CORRECT
if (APSIntPtrVal1 && APSIntPtrVal2) {
    if (*APSIntPtrVal1 == *APSIntPtrVal2) {
        // Values are equal
    }
}

// ✅ CORRECT (with null check)
if (APSIntPtrVal) {
    if (*APSIntPtrVal == 0) {
        // Pointer is null
    }
}
```

## Remember: When in Doubt

1. **Check types**: Is it a pointer? If yes, dereference with `*` or `->`
2. **Use SValBuilder**: For creating SVal from symbols/regions
3. **Use assume()**: For constraint checking (returns pair of states)
4. **Check for null**: Always check pointer validity before dereferencing
5. **Follow Knighter examples**: Knighter checkers are compiled and verified

## Common Hallucinated APIs (DO NOT USE)

The following APIs **DO NOT EXIST** - LLM may hallucinate them. Use the correct alternatives:

### ❌ `evaluateToInt` / `evaluateAsInt`
**Does NOT exist!**

```cpp
// WRONG - Hallucinated function
int size = evaluateToInt(SizeExpr, C);

// CORRECT - Use utility.h function
llvm::APSInt Result;
if (EvaluateExprToInt(Result, SizeExpr, C)) {
    int size = Result.getExtValue();
}
```

### ❌ `getMaxSignedBits` in APInt
**Does NOT exist!**

```cpp
// WRONG - Hallucinated method
int maxVal = APSIntVal.getMaxSignedBits();

// CORRECT - Use getBitWidth() for size
int bitWidth = APSIntVal.getBitWidth();
// Or use comparison operators directly
if (APSIntVal >= 0 && APSIntVal < MaxValue) ...
```

### ❌ Static method calls without object
```cpp
// WRONG - getMemRegionFromExpr is NOT static
const MemRegion *MR = getMemRegionFromExpr(E);

// CORRECT - This is a utility function, pass both E and C
const MemRegion *MR = getMemRegionFromExpr(E, C);
// Always call getBaseRegion() on the result
if (MR) MR = MR->getBaseRegion();
```

### ❌ `inferSymbolMaxVal` as static method
```cpp
// WRONG - Cannot call without CheckerContext
const llvm::APSInt *Max = inferSymbolMaxVal(Sym);

// CORRECT - Must pass CheckerContext
const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C);
```

### ❌ `nonloc::SymbolVal(Sym)` - SymbolRef to SVal conversion
**CRITICAL: This is a very common error!**

```cpp
// ❌ WRONG - nonloc::SymbolVal does NOT accept SymbolRef directly
SymbolRef Sym = Val.getAsSymbol();
SVal SymVal = nonloc::SymbolVal(Sym);  // ERROR: no viable conversion

// ❌ WRONG - Cannot construct SVal from SymbolRef
SVal SymVal = SVal(Sym);  // ERROR

// ✅ CORRECT - Use SValBuilder to create SVal from SymbolRef
SymbolRef Sym = Val.getAsSymbol();
if (Sym) {
    SValBuilder &SVB = C.getSValBuilder();
    SVal SymVal = SVB.makeSymbolVal(Sym);
    // Use SymVal
}

// ✅ CORRECT - Alternative: Use the original SVal directly
// If you already have an SVal, just use it - no need to convert
SVal Val = State->getSVal(Expr, C.getLocationContext());
if (SymbolRef Sym = Val.getAsSymbol()) {
    // Use Val directly instead of trying to create new SVal from Sym
    State = State->assume(Val.castAs<DefinedSVal>(), true);
}

// ✅ CORRECT - For constraint operations, use the original SVal
ProgramStateRef State = C.getState();
SVal Val = State->getSVal(Expr, C.getLocationContext());
if (auto DV = Val.getAs<DefinedSVal>()) {
    // Use *DV for assume() operations
    auto [StateTrue, StateFalse] = State->assume(*DV);
}
```

### ❌ Other common hallucinations
- `getStringSize(StringExpr)` - Use actual strlen or `StringLiteral` length
- `getArraySizeDirect(ArrayExpr)` - Use `getArraySizeFromExpr`
- `isMemoryCopyFunction(Call)` - Check function name manually

## Bug Report Types (LLVM-21)

- `PathSensitiveBugReport(const BugType &bt, StringRef shortDesc, const ExplodedNode *errorNode)`
- `PathSensitiveBugReport(const BugType &bt, StringRef shortDesc, StringRef desc, const ExplodedNode *errorNode)`

## Repair Examples

### Example 0: Common Syntax Structure Errors

**Errors:**
```
error: expected '}'
error: expected unqualified-id
error: expected ';' after class
```

**Common Causes:**
1. Missing closing brace `}` for class or function
2. Missing semicolon `;` after class declaration
3. Malformed class definition

**Fix Guidelines:**
```cpp
// WRONG - Missing semicolon after class
class MyChecker : public Checker<check::PreCall> {
  // ...
}
// Missing semicolon here!

// CORRECT - Complete class with proper structure
class MyChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  MyChecker() : BT(new BugType(this, "Name", "Category")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};  // ← Semicolon REQUIRED!

// Method implementation
void MyChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Implementation
  if (!C.getState()) return;

  // All braces must match
  ExplodedNode *N = C.generateNonFatalErrorNode(C.getState());
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, "Message", N);
  C.emitReport(std::move(Report));
}
```

### Example 1: Optional Type Fix

**Error:**
```
error: 'Optional' was not declared in this scope
```

**Fix:**
```cpp
// Before
Optional<DefinedOrUnknownSVal> SizeSVal;

// After
std::optional<DefinedOrUnknownSVal> SizeSVal;
```

### Example 2: Header Fix

**Error:**
```
fatal error: 'clang/StaticAnalyzer/Core/PathDiagnostic.h' file not found
```

**Fix:** Remove this include. PathDiagnostic is included through BugReporter.h.

### Example 3: API Change

**Error:**
```
error: 'class CheckerContext' has no member named 'getSVal'
```

**Fix:**
```cpp
// Old API (wrong)
SVal Val = C.getSVal(Expr);

// Correct API
ProgramStateRef State = C.getState();
SVal Val = State->getSVal(Expr, C.getLocationContext());
```

## Original Vulnerability Context

{context_section}

## Checker Code to Fix

```cpp
{checkercode}
```

## Error Messages

{errors}

## Output Format

Your response should be the **complete fixed checker code** in a single code block:

```cpp
{{whole fixed checker code here}}
```

**IMPORTANT:**
- Return the **whole** checker code after fixing
- **Preserve the SPECIFIC vulnerability detection logic**
- **Do NOT replace concrete implementations with placeholders**
- **Do NOT add TODO comments**
- Start directly with `#include`
