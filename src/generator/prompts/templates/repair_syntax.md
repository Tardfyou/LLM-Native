# Role

You are an expert in C++ development and Clang Static Analyzer internals, with decades of experience in the Clang project. You specialize in fixing compilation errors in static analyzer checker code.

## Instruction

The following Clang Static Analyzer checker code fails to compile. Your task is to analyze the compilation errors and fix the code.

## Input

### Original Checker Code

```cpp
{{checker_code}}
```

### Compilation Errors

{{#if has_errors}}
**Error Messages:**

{{errors}}

{{#if error_details}}
**Detailed Error Context:**

{{error_details}}
{{/if}}
{{/if}}

{{#unless has_errors}}
*No compilation errors detected. Review the code for any potential issues.*
{{/unless}}

## Error Categories and Fixes

### 1. Missing Headers
**Error Pattern:**
```
fatal error: 'clang/XXX/YYY.h' file not found
```

**Fix:** Remove the problematic include. Only use standard Clang headers:
- `clang/StaticAnalyzer/Core/Checker.h`
- `clang/StaticAnalyzer/Core/BugReporter/BugType.h`
- `clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h`
- etc.

### 2. API Changes (Clang 18)
**Error Pattern:**
```
error: 'Optional' was not declared in this scope
```

**Fix:** Use `std::optional` instead of `llvm::Optional` for Clang 18:
```cpp
// Old (pre-Clang 18)
Optional<DefinedOrUnknownSVal> SizeSVal;

// New (Clang 18)
std::optional<DefinedOrUnknownSVal> SizeSVal;
```

Include `<optional>` header if needed.

### 3. Type Mismatches
**Error Pattern:**
```
error: no match for 'operator='
note: cannot convert 'Type1' to 'Type2'
```

**Fix:** Ensure types match the expected API. Check the Clang 18 documentation for correct types.

### 4. Missing Members
**Error Pattern:**
```
error: 'class clang::XXX' has no member named 'YYY'
```

**Fix:** The API may have changed. Look for the replacement method or member in Clang 18.

### 5. Unused Variables
**Error Pattern:**
```
warning: unused variable 'XXX' [-Wunused-variable]
```

**Fix:** Remove the unused variable or use it appropriately.

### 6. Const Correctness
**Error Pattern:**
```
error: passing 'const XXX' as 'this' argument discards qualifiers
```

**Fix:** Either make the method const or remove const from the object.

### 7. Template Issues
**Error Pattern:**
```
error: template argument deduction/substitution failed
```

**Fix:** Explicitly specify template arguments or check template parameter types.

## Bug Report Types

For Clang 18, use these bug report types:

```cpp
// Path-sensitive (symbolic execution)
PathSensitiveBugReport(const BugType &bt, StringRef shortDesc,
                      const ExplodedNode *errorNode)
PathSensitiveBugReport(const BugType &bt, StringRef shortDesc,
                      StringRef desc, const ExplodedNode *errorNode)

// Path-insensitive
BasicBugReport(const BugType &bt, StringRef desc,
              PathDiagnosticLocation l)
```

## Common Clang 18 API Changes

### State Management
```cpp
// Getting state values
const ValueType *value = State->get<StateMap>(key);  // Returns pointer

// Setting state values
ProgramStateRef NewState = State->set<StateMap>(key, value);

// Removing from state
ProgramStateRef NewState = State->remove<StateMap>(key);
```

### Symbolic Values
```cpp
// Getting symbol from SVal
if (Optional<nonloc::SymbolVal> SymVal = Val.getAs<nonloc::SymbolVal>()) {
    SymbolRef Sym = SymVal->getSymbol();
}

// Getting region from SVal
if (Optional<loc::MemRegionVal> RegVal = Val.getAs<loc::MemRegionVal>()) {
    const MemRegion *MR = RegVal->getRegion();
}
```

### Memory Regions
```cpp
// Always get base region
const MemRegion *Base = MR->getBaseRegion();

// Check for null
if (!MR) return;
```

## Output Format

Provide your response as:

```cpp
{{fixed_checker_code}}
```

## Requirements

1. **Fix All Errors**: Address every compilation error listed
2. **Preserve Logic**: Keep the original detection logic intact
3. **Clang 18 Compatible**: Use only Clang 18 APIs
4. **Complete Code**: Return the entire fixed checker, not just snippets
5. **No Warnings**: Fix warnings if they indicate real issues

## Special Considerations

- **Preserve Intent**: Fix the error while maintaining what the checker is trying to detect
- **Minimal Changes**: Only change what's necessary to fix the compilation
- **Add Comments**: If a fix is non-obvious, add a brief comment explaining why
- **Check Headers**: Ensure all necessary headers are included
- **Verify Types**: Ensure all types are correct for Clang 18

## Examples

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

**Fix:**
Remove this include. PathDiagnostic is included through BugReporter.h.

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

---
*Analyze the errors carefully and provide a complete, compilable checker that maintains the original detection intent.*
