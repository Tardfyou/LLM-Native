# Clang Static Analyzer Checker Development Best Practices

## Core Principles

### 1. NULL Safety First
**ALWAYS perform NULL checks after retrieving pointer types.**

```cpp
// Good pattern
const MemRegion *MR = getMemRegionFromExpr(E, C);
if (!MR) return;  // Early return on NULL
MR = MR->getBaseRegion();  // Now safe to use

// Bad pattern
const MemRegion *MR = getMemRegionFromExpr(E, C);
MR = MR->getBaseRegion();  // Potential NULL dereference!
```

### 2. Memory Region Handling
**ALWAYS invoke `getBaseRegion()` to get the base region before further operations.**

```cpp
// Correct approach
const MemRegion *MR = Loc.getAsRegion();
if (!MR) return;
MR = MR->getBaseRegion();  // Essential: get base region first
// Now safe to use MR for comparisons, storage, etc.
```

**DO NOT perform `IgnoreImplicit()` before invoking `getMemRegionFromExpr()`.**

```cpp
// Bad: IgnoreImplicit() may lose important context
const Expr *Stripped = E->IgnoreImplicit();
const MemRegion *MR = getMemRegionFromExpr(Stripped, C);

// Good: Let getMemRegionFromExpr handle the expression
const MemRegion *MR = getMemRegionFromExpr(E, C);
```

### 3. Symbol vs MemRegion Tracking
**Choose the right tracking mechanism based on value type:**
- **Pointer types** (e.g., `int*`, `void*`): Use `MemRegion*` to mark them
- **Basic types** (e.g., `int`, `char`, `bool`): Use `SymbolRef`

```cpp
// For pointer values
REGISTER_MAP_WITH_PROGRAMSTATE(PtrStateMap, const MemRegion*, PtrState)

// For integer/symbolic values
REGISTER_MAP_WITH_PROGRAMSTATE(IntStateMap, SymbolRef, IntState)
```

### 4. Error Reporting Strategy
**Use `generateNonFatalErrorNode()` rather than `generateErrorNode()`.**

This allows the analyzer to continue exploring the path and report multiple bugs in a single file.

```cpp
// Good: Allows finding multiple bugs
ExplodedNode *ErrorNode = C.generateNonFatalErrorNode(State);
if (!ErrorNode) return;
auto Report = std::make_unique<PathSensitiveBugReport>(
    *BT, "Description", ErrorNode);
C.emitReport(std::move(Report));

// Bad: Stops after first bug
ExplodedNode *ErrorNode = C.generateErrorNode(State);
```

### 5. Bug Report Messages
**Keep error messages SHORT and CLEAR.**

```cpp
// Good: Concise and actionable
"Potential use-after-free on 'ptr'"
"Missing NULL check before dereferencing 'buffer'"
"Possible buffer overflow: 'size' may exceed 'capacity'"

// Bad: Too verbose and confusing
"The analyzer has detected a potential issue where the variable 'ptr' "
"which has been previously freed at line X is now being dereferenced "
"at line Y which could lead to undefined behavior according to the C "
"standard..."
```

### 6. Function Name Verification
**Use `ExprHasName()` for accurate function name checking.**

```cpp
// Bad: May fail with macros or overloaded operators
const IdentifierInfo *Callee = Call.getCalleeIdentifier();
if (!Callee || Callee->getName() != "check_add_overflow") return;

// Good: Handles macros and edge cases correctly
const Expr *OriginExpr = Call.getOriginExpr();
if (!OriginExpr || !ExprHasName(OriginExpr, "check_add_overflow", C)) return;

// For type checking, use corresponding Clang APIs
if (C.getASTContext().getTypeSize(Ty) < 32) { ... }
```

## Symbolic Value Handling

### Inferring Maximum Values
**When inferring maximum values, invoke `inferSymbolMaxVal()` for each component.**

```cpp
// For compound expressions like a * b
const llvm::APSInt *MaxA = inferSymbolMaxVal(SymA, C);
const llvm::APSInt *MaxB = inferSymbolMaxVal(SymB, C);

if (MaxA && MaxB) {
    llvm::APInt MaxProduct = MaxA->umul_ov(*MaxB, Overflow);
    // Use MaxProduct for further analysis
}
```

### Constraint Checking
**Always check if constraints exist before using them.**

```cpp
// Good: Check for constraint existence
const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C);
if (MaxVal) {
    // Constraint exists, use it
    if (*MaxVal > Limit) {
        // Report bug
    }
} else {
    // No constraint available - use conservative approach
    // Don't report bug, or use weaker warning
}
```

## Pointer Aliasing Analysis

### Using Program State for Aliasing
**For pointer analysis, use program state maps with `checkBind` callback.**

```cpp
// Register program state for tracking pointer relationships
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)

// Track aliasing when pointers are bound
void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
    // Update aliasing information when a pointer value is assigned
    if (const MemRegion *DestRegion = getMemRegionFromExpr(dyn_cast<Expr>(S), C)) {
        if (const MemRegion *SrcRegion = Val.getAsRegion()) {
            ProgramStateRef State = C.getState();
            State = State->set<PtrAliasMap>(DestRegion->getBaseRegion(),
                                            SrcRegion->getBaseRegion());
            C.addTransition(State);
        }
    }
}
```

## Undecidable Situations

### When Information is Missing
**If you're not sure whether there is a bug due to missing information (e.g., undecidable array size), DO NOT report it.**

```cpp
// Good: Check if size is determinable
llvm::APInt ArraySize;
if (!getArraySizeFromExpr(ArraySize, ArrayExpr, C)) {
    // Can't determine size - skip reporting to avoid false positives
    return;
}

// Now we can safely use ArraySize
if (Index >= ArraySize) {
    // Report potential out-of-bounds access
}
```

## Callback Selection

### Choose the Right Callback

**For `if` statement conditions:**
- Use `checkBranchCondition` to evaluate the condition
- Use `checkPreStmt`/`checkPostStmt` with `IfStmt` to inspect the branches

**For function calls:**
- Use `checkPreCall` for pre-call checks (arguments, callee)
- Use `checkPostCall` for post-call checks (return value, side effects)
- Use `evalCall` if you want to completely evaluate the call yourself

**For memory operations:**
- Use `checkLocation` for loads and stores
- Use `checkBind` to track value assignments

**For function lifecycle:**
- Use `checkBeginFunction` for setup at function entry
- Use `checkEndFunction` for cleanup at function exit

## Macro Handling

### Working with Macro Values
**When dealing with macros (like `CMD_XXX`), use `getNameAsString()` for comparison.**

```cpp
// For checking macro values in conditions
if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Condition)) {
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(BO->getLHS())) {
        std::string MacroName = DRE->getNameInfo().getAsString();
        if (MacroName == "CMD_READ") {
            // Handle the specific command
        }
    }
}
```

## Code Organization

### Follow the Plan
**Please follow the implementation plan consistently.**

The plan is designed to ensure all necessary steps are completed in the correct order. Skipping steps or reordering may lead to missing functionality or subtle bugs.

### No Placeholder Logic
**DO NOT use placeholder logic or TODO comments in the checker.**

```cpp
// Bad: Placeholder
// TODO: implement the actual check logic
return;

// Good: Complete implementation
if (Condition) {
    ReportBug(C);
    return;
}
```

### Complete Function Implementations
**Always implement complete, runnable functions.**

Don't leave function bodies empty or with just `return;` statements. Every function should have a clear purpose and complete implementation.

## Edge Cases and Robustness

### Handle All Cast Types
**Be aware of different cast types and their implications.**

```cpp
// Handle various cast expressions
if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    switch (CE->getCastKind()) {
        case CK_BitCast:
            // Handle reinterpret_cast-like behavior
            break;
        case CK_IntegralToPointer:
            // Handle integer-to-pointer conversion
            break;
        case CK_PointerToIntegral:
            // Handle pointer-to-integer conversion
            break;
        // ... handle other cases
    }
}
```

### Consider Integer Overflow
**Check for integer overflow in arithmetic operations.**

```cpp
// Use umul_ov for unsigned multiplication
bool Overflow = false;
llvm::APInt Result = Size.umul_ov(Count, Overflow);
if (Overflow) {
    // Report potential integer overflow
}
```

### Respect C/C++ Semantics
**Follow the language semantics precisely.**

```cpp
// For short-circuit evaluation in logical operators
if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isLogicalOp()) {
        // RHS may not be evaluated if LHS determines the result
        // Handle accordingly
    }
}
```

## Performance Considerations

### Early Returns
**Use early returns to avoid unnecessary computation.**

```cpp
// Good: Check preconditions first
if (!C.getState()) return;
if (!E) return;
if (C.getState()->isNull()) return;

// Now do the expensive operations
```

### State Updates
**Only create new program states when necessary.**

```cpp
// Good: Batch state updates
ProgramStateRef State = C.getState();
State = State->set<TrackedMap>(Key1, Val1);
State = State->set<TrackedMap>(Key2, Val2);
C.addTransition(State);  // Single transition

// Bad: Multiple transitions for related updates
ProgramStateRef State = C.getState();
State = State->set<TrackedMap>(Key1, Val1);
C.addTransition(State);
State = C.getState();  // Gets old state back!
State = State->set<TrackedMap>(Key2, Val2);
C.addTransition(State);  // Wrong! Lost first update
```

## Testing Your Checker

### Test Case Structure
**Create test cases that cover:**
1. **True Positives**: Cases where the bug should be detected
2. **True Negatives**: Similar but safe code that should NOT trigger
3. **Edge Cases**: Boundary conditions, null cases, etc.

```cpp
// Test for buffer overflow checker
void test_true_positive() {
    char buf[10];
    strcpy(buf, "this_string_is_too_long");  // Should trigger
}

void test_true_negative() {
    char buf[10];
    strncpy(buf, "safe", sizeof(buf));  // Should NOT trigger
}

void test_edge_case() {
    char buf[10];
    strncpy(buf, "123456789", 9);  // Exactly fits, should NOT trigger
}
```

## Common Pitfalls to Avoid

### 1. Forgetting Base Region
```cpp
// Bug: Forgetting to get base region
const MemRegion *MR = Loc.getAsRegion();
if (TrackedRegions.count(MR)) { ... }  // May miss matches

// Fix: Always get base region
const MemRegion *MR = Loc.getAsRegion();
if (MR) MR = MR->getBaseRegion();
if (TrackedRegions.count(MR)) { ... }
```

### 2. Ignoring Implicit Operations
```cpp
// Bug: Stripping implicit casts too early
const Expr *Stripped = E->IgnoreImpCasts();
const MemRegion *MR = getMemRegionFromExpr(Stripped, C);

// Fix: Let utility functions handle implicit operations
const MemRegion *MR = getMemRegionFromExpr(E, C);
```

### 3. Incorrect Callback Usage
```cpp
// Bug: Using checkPreCall when checkPostCall is needed
void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    // Can't access return value here!
    SVal RetVal = Call.getReturnValue();  // Wrong!
}

// Fix: Use checkPostCall for return values
void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    SVal RetVal = Call.getReturnValue();  // Correct
}
```

### 4. Missing State Transitions
```cpp
// Bug: Modifying state but not creating transition
ProgramStateRef State = C.getState();
State = State->set<MyMap>(Key, Value);
// Forgot: C.addTransition(State);
return;  // State change lost!

// Fix: Always add transition after modifying state
ProgramStateRef State = C.getState();
State = State->set<MyMap>(Key, Value);
C.addTransition(State);
```

## API Compatibility (LLVM-21)

### Use Modern APIs
**LLVM-21 uses different APIs than earlier versions.**

```cpp
// ❌ llvm::Optional - Deprecated in LLVM-21
llvm::Optional<Loc> L = val.getAs<Loc>();

// ✅ std::optional - Use this for LLVM-21
std::optional<Loc> L = val.getAs<Loc>();

// ❌ APSInt::isZero() - Does not exist
if (Value.isZero()) { ... }

// ✅ Direct comparison - Use this instead
if (Value == 0 || Value.isNull()) { ... }

// ❌ dyn_cast for potentially null pointers
const TypedValueRegion *TVR = dyn_cast<TypedValueRegion>(MR);

// ✅ dyn_cast_or_null for better null safety
const TypedValueRegion *TVR = dyn_cast_or_null<TypedValueRegion>(MR);

// ❌ Old ParentMap API
const ParentMap &PM = C.getAnalysisManager().getParentMap();
const Stmt *Parent = PM.getParent(S);

// ✅ New ParentMapContext API
const ParentMapContext &PMC = C.getLocationContext()->getParentMapContext();
const Stmt *Parent = PMC.getParent(S);
```

### Type Casting Best Practices (LLVM-21)

```cpp
// For SVal extraction (returns std::optional)
std::optional<Loc> L = val.getAs<Loc>();
if (L) {
    // Safe to dereference
}

// For MemRegion operations (returns std::optional)
std::optional<const MemRegion*> MR = Loc.getAsRegion();
if (MR && MR->has_value()) {
    const MemRegion *R = *MR;
    R = R->getBaseRegion();  // Always get base region
}

// For type casting on potentially null pointers
if (const TypedValueRegion *TVR = dyn_cast_or_null<TypedValueRegion>(MR)) {
    // Safe to use TVR
}
```

### Header Includes
**Be careful when including headers - verify they exist.**

```cpp
// Good: Use standard Clang headers
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

// Bad: May not exist in Clang 18
#include "clang/StaticAnalyzer/Core/PathDiagnostic.h"  // Wrong path
```

## Summary Checklist

Before finalizing your checker, verify:

- [ ] All NULL checks are in place
- [ ] `getBaseRegion()` is called after `getMemRegionFromExpr()`
- [ ] `generateNonFatalErrorNode()` is used for bug reporting
- [ ] Error messages are short and clear
- [ ] `ExprHasName()` is used for function name verification
- [ ] No placeholder logic or TODO comments
- [ ] All functions are complete and runnable
- [ ] Program state transitions are properly created
- [ ] Macro values use `getNameAsString()` for comparison
- [ ] Undecidable cases are handled conservatively
- [ ] Appropriate callbacks are selected for the analysis task
- [ ] Code follows the implementation plan

---
*Following these best practices will help ensure your checker is reliable, maintainable, and effective at detecting bugs while minimizing false positives.*
