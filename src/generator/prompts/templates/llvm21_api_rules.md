# LLVM-21 Critical API Rules (MUST FOLLOW)

## ⚠️ CRITICAL: Common API Mistakes That Cause Compilation Errors

### 0. ProgramState->get<T>() Returns Double Pointer (MOST CRITICAL!)

**CRITICAL:** In LLVM-21, `ProgramState->get<MapType>(Key)` returns `const Value*const *` (double pointer), NOT `const Value*`!

```cpp
// ❌ WRONG - Treating as single pointer
REGISTER_MAP_WITH_PROGRAMSTATE(MyMap, const MemRegion*, bool)
const bool *Value = State->get<MyMap>(Key);  // This is WRONG!
if (Value) {  // This checks the outer pointer
    return *Value;  // Only one dereference - WRONG!
}

// ❌ WRONG - Direct assignment (MOST COMMON ERROR!)
const MemRegion *Alias = State->get<PtrAliasMap>(CheckedMR);  // Type mismatch!
// Error: cannot initialize a variable of type 'const MemRegion *'
//        with an rvalue of type 'const MemRegion *const *'

// ❌ WRONG - Wrapping in std::optional
std::optional<const MemRegion*> MR = State->get<PtrAliasMap>(Key);  // Still wrong!

// ✅ CORRECT - Proper double pointer handling
REGISTER_MAP_WITH_PROGRAMSTATE(MyMap, const MemRegion*, bool)

// get<> returns: const bool*const * (double pointer)
// To get the value: Check outer pointer, then dereference twice
const bool *const *ValuePtr = State->get<MyMap>(Key);
if (ValuePtr && *ValuePtr) {
    bool Value = **ValuePtr;  // Double dereference!
}

// ✅ CORRECT - Simplified pattern (RECOMMENDED)
const bool *Value = State->get<MyMap>(Key);
if (Value && *Value) {
    // Use **Value for the actual boolean
    return true;
}

// ✅ CORRECT - For MemRegion maps (like PtrAliasMap)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion*, const MemRegion*)
const MemRegion *const *AliasPtr = State->get<PtrAliasMap>(CheckedMR);
if (AliasPtr && *AliasPtr) {
    const MemRegion *Alias = *AliasPtr;  // Single dereference to get the value
    // Use Alias
}

// ✅ CORRECT - In condition (most compact)
if (const MemRegion *const *AliasPtr = State->get<PtrAliasMap>(CheckedMR); AliasPtr && *AliasPtr) {
    const MemRegion *Alias = *AliasPtr;
    // Use Alias
}
```

**KEY RULE:** `State->get<MapType>(Key)` returns `const Value*const *`. You must:
1. Check if the outer pointer is not null: `if (Ptr)`
2. Check if the inner pointer is not null: `&& *Ptr`
3. Dereference ONCE to get the value: `*Ptr`

**COMMON ERROR PATTERNS TO AVOID:**
```cpp
// ❌ ERROR PATTERN 1: Direct assignment
const MemRegion *Alias = State->get<PtrAliasMap>(Key);  // WRONG!

// ❌ ERROR PATTERN 2: Single check and dereference
if (const MemRegion *Alias = State->get<PtrAliasMap>(Key)) {  // Checks outer pointer only!
    // Dereferencing Alias without checking inner pointer - CRASH!
}

// ❌ ERROR PATTERN 3: Double dereference without null check
const MemRegion *Alias = *(State->get<PtrAliasMap>(Key));  // CRASH if get() returns nullptr!
```

**BEST PRACTICE:** Avoid using `REGISTER_MAP_WITH_PROGRAMSTATE` unless absolutely necessary. Most simple checkers can track state using simpler methods.

**CRITICAL:** In LLVM-21, `ProgramState->get<MapType>(Key)` returns `const Value*const *` (double pointer), NOT `const Value*`!

```cpp
// ❌ WRONG - Treating as single pointer
REGISTER_MAP_WITH_PROGRAMSTATE(MyMap, const MemRegion*, bool)
const bool *Value = State->get<MyMap>(Key);  // This is WRONG!
if (Value) {  // This checks the outer pointer
    return *Value;  // Only one dereference - WRONG!
}

// ❌ WRONG - Direct assignment
const MemRegion *MR = State->get<PtrAliasMap>(Key);  // Type mismatch!

// ❌ WRONG - Wrapping in std::optional
std::optional<const MemRegion*> MR = State->get<PtrAliasMap>(Key);  // Still wrong!

// ✅ CORRECT - Proper double pointer handling
REGISTER_MAP_WITH_PROGRAMSTATE(MyMap, const MemRegion*, bool)

// get<> returns: const bool*const * (double pointer)
// To get the value: Check outer pointer, then dereference twice
const bool *const *ValuePtr = State->get<MyMap>(Key);
if (ValuePtr && *ValuePtr) {
    bool Value = **ValuePtr;  // Double dereference!
}

// ✅ CORRECT - Simplified pattern
const bool *Value = State->get<MyMap>(Key);
if (Value && *Value) {
    // Use **Value for the actual boolean
    return true;
}

// ✅ CORRECT - For MemRegion maps
REGISTER_MAP_WITH_PROGRAMSTATE(RegionMap, const MemRegion*, int)
const int *const *IntPtr = State->get<RegionMap>(MR);
if (IntPtr && *IntPtr) {
    int Value = **IntPtr;
}
```

**KEY RULE:** `State->get<MapType>(Key)` returns `const Value*const *`. You must:
1. Check if the outer pointer is not null: `if (Ptr)`
2. Check if the inner pointer is not null: `&& *Ptr`
3. Dereference twice to get the value: `**Ptr`

**DO NOT** use `REGISTER_MAP_WITH_PROGRAMSTATE` in plugin checkers unless you fully understand this API!

The following are the most common errors that appear in generated code. **AVOID THESE PATTERNS:**

### 1. APSIntPtr Type Error

**WRONG:**
```cpp
if (APSIntPtrVal.isZero()) { ... }              // ❌ isZero() doesn't exist
if (APSIntPtrVal == 0) { ... }                  // ❌ APSIntPtr is a POINTER!
return ConcreteVal->getValue() == 0;            // ❌ getValue() returns APInt, not int
if (ConcreteVal->getValue() == 0) { ... }       // ❌ Same issue
```

**CORRECT:**
```cpp
// Option 1: Use getExtValue() - RECOMMENDED
if (APSIntPtrVal && APSIntPtrVal->getExtValue() == 0) { ... }  // ✅ Check null, then use getExtValue()
return ConcreteVal->getExtValue() == 0;              // ✅ Direct return with getExtValue()

// Option 2: Dereference twice (pointer -> APSInt -> APInt value)
if (APSIntPtrVal && (*APSIntPtrVal) == 0) { ... }   // ✅ Check null, then compare APSInt

// Option 3: Step-by-step with null check
if (APSIntPtrVal) {
    if (APSIntPtrVal->getExtValue() == 0) { ... }   // ✅ Most explicit and safe
}
```

**KEY RULE:** `APSIntPtr` is `const llvm::APSInt*` - a **pointer** type. Must be:
- Checked for null: `if (ptr)` before dereferencing
- Use `getExtValue()` to get integer value: `ptr->getExtValue() == 0`
- `getValue()` on APSInt returns `APInt&`, not a comparable integer
- `getExtValue()` returns `int64_t` which can be directly compared with 0

### 2. SymbolRef Type Error

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

### 3. getSymVal API Error

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

#### 4. TypedValueRegion::getDecl() Error

**WRONG:**
```cpp
if (const TypedValueRegion *TVR = dyn_cast<TypedValueRegion>(MR)) {
    const Decl *D = TVR->getDecl();  // ❌ getDecl() doesn't exist in TypedValueRegion
}
```

**CORRECT:**
```cpp
// TypedValueRegion doesn't have getDecl() in LLVM-21
// Use different approach based on the region type
if (const VarRegion *VR = dyn_cast<VarRegion>(MR)) {
    const VarDecl *VD = VR->getDecl();  // ✅ VarRegion has getDecl()
} else if (const FieldRegion *FR = dyn_cast<FieldRegion>(MR)) {
    const FieldDecl *FD = FR->getDecl();  // ✅ FieldRegion has getDecl()
} else if (const ElementRegion *ER = dyn_cast<ElementRegion>(MR)) {
    // ElementRegion doesn't have getDecl() - use super region
}
```

**KEY RULE:** `TypedValueRegion` is a base class that doesn't have `getDecl()`. Use:
- `VarRegion::getDecl()` for variable regions
- `FieldRegion::getDecl()` for field regions
- Cast to the specific region type first

### 5. Report Variable Name Error

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

### 6. State->isNull() / State->isNonNull() API Error

**WRONG:**
```cpp
// State->isNull() and State->isNonNull() don't exist or have wrong signatures
return State->isNull(*LocVal).isConstrainedTrue();  // ❌ Wrong API
return State->isNonNull(*LocVal).isConstrainedTrue();  // ❌ Wrong API
```

**CORRECT:**
```cpp
// Use State->assume() to check constraints
ProgramStateRef StNull, StNotNull;
std::tie(StNull, StNotNull) = State->assume(LocVal->castAs<DefinedOrUnknownSVal>());

if (StNull && !StNotNull) {
    // Definitely null
    return true;
}
if (StNotNull && !StNull) {
    // Definitely non-null
    return false;
}
// Otherwise: unknown
```

**OR for simple null check:**
```cpp
// Use assume() with pair destructuring
auto [StNotNull, StNull] = State->assume(LocVal->castAs<DefinedOrUnknownSVal>());

if (StNull && !StNotNull) {
    return true;  // Is null
}
return false;  // Is non-null or unknown
```

**KEY RULE:** Use `State->assume(SVal)` which returns `std::pair<ProgramStateRef, ProgramStateRef>`:
- `.first` = state where condition is true (non-null for pointers)
- `.second` = state where condition is false (null for pointers)

## Quick Reference Card for Common Operations

### Checking if an SVal is null

```cpp
// ✅ CORRECT
if (auto MR = Val.getAsRegion()) {
    if (const MemRegion *R = MR->getBaseRegion()) {
        // Check if R is null by checking constraints
        SValBuilder &SVB = C.getSValBuilder();
        SVal NullVal = SVB.makeNull();
        DefinedOrUnknownSVal IsNull = SVB.evalBinOp(C.getState(), BO_EQ,
            Val.castAs<DefinedOrUnknownSVal>(),
            NullVal, SVB.getConditionType());
        // Use IsNull...
    }
}
```

### Creating SVal from Symbol

```cpp
// ✅ CORRECT
if (SymbolRef Sym = Val.getAsSymbol()) {  // SymbolRef IS const SymExpr*
    SValBuilder &SVB = C.getSValBuilder();
    SVal SymVal = SVB.makeSymbolVal(Sym);
    // Now SymVal can be used in assume(), etc.
}
```

### Comparing APSIntPtr values

```cpp
// ✅ CORRECT - Using getExtValue() (RECOMMENDED)
if (APSIntPtrVal) {
    if (APSIntPtrVal->getExtValue() == 0) {
        // Value is zero
    }
}

// ✅ CORRECT - Return statement
return ConcreteVal->getExtValue() == 0;  // Direct return with getExtValue()

// ✅ CORRECT - Comparing two APSIntPtr values
if (APSIntPtrVal1 && APSIntPtrVal2) {
    if (APSIntPtrVal1->getExtValue() == APSIntPtrVal2->getExtValue()) {
        // Values are equal
    }
}

// ⚠️ ALSO CORRECT - Dereferencing twice (pointer -> APSInt -> APInt comparison)
if (APSIntPtrVal) {
    if ((*APSIntPtrVal) == 0) {  // APSInt overloads operator== with APInt
        // Value is zero
    }
}

// ❌ WRONG - getValue() returns APInt& which can't compare directly with int
return ConcreteVal->getValue() == 0;  // ERROR: APInt cannot compare with int

// ❌ WRONG - APSIntPtr is a pointer, can't compare directly
if (APSIntPtrVal == 0) { ... }  // ERROR: Comparing pointer with int
```

## Copy-Paste Safe Patterns

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

## Remember: When in Doubt

1. **Check types**: Is it a pointer? If yes, dereference with `*` or `->`
2. **Use SValBuilder**: For creating SVal from symbols/regions
3. **Use assume()**: For constraint checking (returns pair of states)
4. **Check for null**: Always check pointer validity before dereferencing
5. **Follow Knighter examples**: Knighter checkers are compiled and verified
