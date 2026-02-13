# Role

You are an expert in Clang Static Analyzer development, specializing in debugging and fixing semantic issues in checker implementations. You have deep knowledge of path-sensitive analysis and symbolic execution.

## Instruction

The following Clang Static Analyzer checker compiles successfully but produces incorrect results (false positives, false negatives, or crashes). Your task is to analyze and fix the semantic issues.

## Input

### Checker Code

```cpp
{{checker_code}}
```

### Bug Pattern

{{bug_pattern}}

### Implementation Plan

{{implementation_plan}}

### Issues Reported

{{#if false_positives}}
**False Positives** (reports bugs in safe code):

{{false_positives}}
{{/if}}

{{#if false_negatives}}
**False Negatives** (misses actual bugs):

{{false_negatives}}
{{/if}}

{{#if crashes}}
**Crashes or Errors**:

{{crashes}}
{{/if}}

### Test Cases

{{#if test_cases}}
**Test Case Results:**

{{test_cases}}
{{/if}}

### Reference Code

{{#if reference_patch}}
**Original Fix Patch:**

```diff
{{reference_patch}}
```
{{/if}}

{{#if working_example}}
**Working Reference Implementation:**

```cpp
{{working_example}}
```
{{/if}}

## Common Semantic Issues

### 1. Incorrect Callback Selection
**Problem**: Using wrong callback for the analysis task.

**Example Fix**:
```cpp
// Wrong: Can't get return value in checkPreCall
void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    SVal RetVal = Call.getReturnValue();  // Always undefined!
}

// Correct: Use checkPostCall for return values
void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    SVal RetVal = Call.getReturnValue();  // Correct value
}
```

### 2. Missing Base Region
**Problem**: Not getting base region before comparisons/storage.

**Example Fix**:
```cpp
// Wrong
const MemRegion *MR = getMemRegionFromExpr(E, C);
if (TrackedRegions.count(MR)) { ... }  // May miss matches

// Correct
const MemRegion *MR = getMemRegionFromExpr(E, C);
if (!MR) return;
MR = MR->getBaseRegion();
if (TrackedRegions.count(MR)) { ... }
```

### 3. State Transition Issues
**Problem**: Not creating proper state transitions.

**Example Fix**:
```cpp
// Wrong: Modifying state but not transitioning
ProgramStateRef State = C.getState();
State = State->set<MyMap>(Key, Value);
// Missing: C.addTransition(State);

// Correct
ProgramStateRef State = C.getState();
State = State->set<MyMap>(Key, Value);
C.addTransition(State);
```

### 4. Missing NULL Checks
**Problem**: Dereferencing NULL pointers.

**Example Fix**:
```cpp
// Wrong
const MemRegion *MR = Loc.getAsRegion();
MR = MR->getBaseRegion();  // Potential NULL dereference

// Correct
const MemRegion *MR = Loc.getAsRegion();
if (!MR) return;
MR = MR->getBaseRegion();
```

### 5. Over-aggressive Reporting
**Problem**: Reporting bugs for cases that aren't actually buggy.

**Example Fix**:
```cpp
// Wrong: Reports on unknown values too
llvm::APSInt MaxVal;
if (!inferSymbolMaxVal(Sym, C) || MaxVal > Limit) {
    ReportBug(C);  // Reports on unknown!
}

// Correct: Only report when we know there's a problem
const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C);
if (MaxVal && *MaxVal > Limit) {
    ReportBug(C);  // Only reports when proven
}
```

### 6. Incorrect State Key
**Problem**: Using wrong type for state map keys.

**Example Fix**:
```cpp
// Wrong: Uses SVal as key (unstable)
REGISTER_MAP_WITH_PROGRAMSTATE(Map, SVal, bool)
SVal Key = C.getSVal(E);

// Correct: Use stable MemRegion
REGISTER_MAP_WITH_PROGRAMSTATE(Map, const MemRegion*, bool)
const MemRegion *Key = getMemRegionFromExpr(E, C);
if (Key) Key = Key->getBaseRegion();
```

### 7. Not Handling All Cast Types
**Problem**: Missing checks through implicit casts.

**Example Fix**:
```cpp
// Wrong: May miss cases due to casts
if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    // Handle DRE
}

// Correct: Look through implicit casts
const Expr *Stripped = E->IgnoreImpCasts();
if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Stripped)) {
    // Handle DRE
}
```

### 8. Incorrect Symbol vs Region Choice
**Problem**: Tracking wrong type of value.

**Example Fix**:
```cpp
// Wrong for pointer values
REGISTER_MAP_WITH_PROGRAMSTATE(PtrMap, SymbolRef, bool)
SymbolRef Sym = Val.getAsSymbol();

// Correct for pointers
REGISTER_MAP_WITH_PROGRAMSTATE(PtrMap, const MemRegion*, bool)
const MemRegion *MR = Val.getAsRegion();
```

## Analysis Process

1. **Identify the Issue Type**:
   - False positive: Reports on safe code
   - False negative: Misses actual bugs
   - Crash: Analyzer crashes
   - Performance: Too slow or reports too much

2. **Find the Root Cause**:
   - Check callback selection
   - Verify state management
   - Examine conditional logic
   - Review reporting conditions

3. **Design the Fix**:
   - Minimal changes to preserve working logic
   - Add missing checks
   - Correct API usage
   - Improve state tracking

4. **Verify the Fix**:
   - Should still detect the original bug pattern
   - Should not produce false positives on safe code
   - Should handle edge cases

## Output Format

Provide:

```markdown
## Issue Analysis

[Describe what's wrong and why]

## Fix Applied

[Explain the changes made]

## Fixed Code

```cpp
{{fixed_code}}
```

## Explanation

[Detailed explanation of the fix and why it works]
```

## Requirements

1. **Preserve Correct Behavior**: Don't break cases that work
2. **Fix Identified Issues**: Address all reported problems
3. **Maintain Clarity**: Keep code readable and maintainable
4. **Add Comments**: Explain non-obvious fixes
5. **Test Edge Cases**: Consider NULL, unknown values, etc.

## Best Practices Reminder

- Always check for NULL after getting MemRegion
- Always call getBaseRegion() on MemRegions
- Use generateNonFatalErrorNode() for bug reports
- Create state transitions after modifying state
- Use stable keys (MemRegion) for state maps
- Handle unknown values conservatively
- Don't report bugs on uncertain cases

---
*Analyze the semantic issues carefully and provide a corrected checker that accurately detects the intended bug pattern.*
