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
