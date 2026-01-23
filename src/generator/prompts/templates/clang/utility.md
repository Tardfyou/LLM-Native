# Clang Static Analyzer Utility Functions

These utility functions are available in `src/generator/include/utility.h` and `utility.cpp`.

Copy them into your checker as needed, or include the header file if linking with the utility library.

## AST Traversal Utilities

```cpp
// Going upward in an AST tree, and find the Stmt of a specific type
template <typename T>
const T* findSpecificTypeInParents(const Stmt *S, CheckerContext &C) {
    const Stmt *Current = S;
    while (Current && Current->getStmtClass() != T::StmtClass) {
        const ParentMap &PM = C.getParentMap();
        Current = PM.getParent(Current);
    }
    return dyn_cast_or_null<T>(Current);
}

// Going downward in an AST tree, and find the Stmt of a specific type
// Only return one of the statements if there are many
template <typename T>
const T* findSpecificTypeInChildren(const Stmt *S) {
    if (!S) return nullptr;

    class ChildFinder : public ConstStmtVisitor<ChildFinder> {
    public:
        const T* Result = nullptr;
        void VisitStmt(const Stmt *Statement) {
            if (Result) return;  // Already found
            if (const T* SpecificNode = dyn_cast<T>(Statement)) {
                Result = SpecificNode;
                return;
            }
            // Visit children
            for (const Stmt *Child : Statement->children()) {
                if (Child) Visit(Child);
                if (Result) return;
            }
        }
    };

    ChildFinder Finder;
    Finder.Visit(S);
    return Finder.Result;
}
```

## Expression Evaluation

```cpp
/// Evaluate an expression to an integer constant
/// @param EvalRes The result will be stored here
/// @param expr The expression to evaluate
/// @param C The checker context
/// @return true if evaluation succeeded, false otherwise
bool EvaluateExprToInt(llvm::APSInt &EvalRes, const Expr *expr, CheckerContext &C) {
    Expr::EvalResult ExprRes;
    if (expr->EvaluateAsInt(ExprRes, C.getASTContext())) {
        EvalRes = ExprRes.Val.getInt();
        return true;
    }
    return false;
}

/// Evaluate an expression to a boolean constant
/// @param result The boolean result will be stored here
/// @param expr The expression to evaluate
/// @param C The checker context
/// @return true if evaluation succeeded, false otherwise
bool EvaluateExprToBool(bool &result, const Expr *expr, CheckerContext &C) {
    llvm::APSInt IntVal;
    if (EvaluateExprToInt(IntVal, expr, C)) {
        result = IntVal.getBoolValue();
        return true;
    }
    return false;
}
```

## Symbolic Value Inference

```cpp
/// Infer the maximum possible value of a symbol
/// @param Sym The symbol to query
/// @param C The checker context
/// @return Pointer to the maximum value, or nullptr if unknown
const llvm::APSInt *inferSymbolMaxVal(SymbolRef Sym, CheckerContext &C) {
    ProgramStateRef State = C.getState();
    const llvm::APSInt *maxVal = State->getConstraintManager().getSymMaxVal(State, Sym);
    return maxVal;
}

/// Infer the minimum possible value of a symbol
/// @param Sym The symbol to query
/// @param C The checker context
/// @return Pointer to the minimum value, or nullptr if unknown
const llvm::APSInt *inferSymbolMinVal(SymbolRef Sym, CheckerContext &C) {
    ProgramStateRef State = C.getState();
    const llvm::APSInt *minVal = State->getConstraintManager().getSymMinVal(State, Sym);
    return minVal;
}

/// Infer if a symbol is equal to a specific value
/// @param Sym The symbol to query
/// @param Val The value to check against
/// @param C The checker context
/// @return true if the symbol is known to be equal to Val
bool isSymbolEqualTo(SymbolRef Sym, const llvm::APSInt &Val, CheckerContext &C) {
    ProgramStateRef State = C.getState();
    const llvm::APSInt *KnownVal = State->getConstraintManager().getSymVal(State, Sym);
    return KnownVal && *KnownVal == Val;
}
```

## Array and String Operations

```cpp
/// Get the size of a statically-sized array from an expression
/// @param ArraySize Will store the array size
/// @param E The expression (should be a DeclRefExpr to an array variable)
/// @return true if array size was successfully retrieved
bool getArraySizeFromExpr(llvm::APInt &ArraySize, const Expr *E) {
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E->IgnoreImplicit())) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
            QualType QT = VD->getType();
            if (const ConstantArrayType *ArrayType = dyn_cast<ConstantArrayType>(QT.getTypePtr())) {
                ArraySize = ArrayType->getSize();
                return true;
            }
        }
    }
    return false;
}

/// Get the length of a string literal
/// @param StringSize Will store the string length
/// @param E The expression (should be a StringLiteral)
/// @return true if string size was successfully retrieved
bool getStringSize(llvm::APInt &StringSize, const Expr *E) {
    if (const auto *SL = dyn_cast<StringLiteral>(E->IgnoreImpCasts())) {
        StringSize = llvm::APInt(32, SL->getLength());
        return true;
    }
    return false;
}

/// Get the size of a memory region if it's a known-sized region
/// @param Size Will store the region size
/// @param MR The memory region
/// @return true if size was successfully retrieved
bool getRegionSize(llvm::APInt &Size, const MemRegion *MR) {
    if (!MR) return false;

    // Check for AllocaRegion (stack allocation)
    if (const AllocaRegion *AR = dyn_cast<AllocaRegion>(MR)) {
        if (const Expr *SizeExpr = AR->getAllocExpr()) {
            // Note: This requires evaluating the expression in context
            // Implementation depends on specific context availability
        }
    }

    // Check for symbolic size
    // Implementation varies based on Clang version

    return false;
}
```

## Memory Region Operations

```cpp
/// Get the memory region from an expression
/// @param E The expression to get the region for
/// @param C The checker context
/// @return The memory region, or nullptr if not available
const MemRegion* getMemRegionFromExpr(const Expr* E, CheckerContext &C) {
    if (!E) return nullptr;

    ProgramStateRef State = C.getState();
    SVal Val = State->getSVal(E, C.getLocationContext());

    // Get the region from the SVal
    if (Optional<loc::MemRegionVal> RegionVal = Val.getAs<loc::MemRegionVal>()) {
        return RegionVal->getRegion();
    }

    return nullptr;
}

/// Get the base region of any memory region (strip subregions)
/// @param MR The memory region
/// @return The base region
inline const MemRegion* getBaseRegion(const MemRegion *MR) {
    return MR ? MR->getBaseRegion() : nullptr;
}

/// Check if two memory regions alias each other
/// @param MR1 First memory region
/// @param MR2 Second memory region
/// @param C The checker context
/// @return true if the regions are known to alias
bool regionsAlias(const MemRegion *MR1, const MemRegion *MR2, CheckerContext &C) {
    if (!MR1 || !MR2) return false;

    // Same region is trivially aliased
    if (MR1 == MR2) return true;

    // Check base regions
    const MemRegion *Base1 = MR1->getBaseRegion();
    const MemRegion *Base2 = MR2->getBaseRegion();

    if (Base1 && Base2 && Base1 == Base2) {
        return true;
    }

    // Check for symbolic aliasing using program state
    ProgramStateRef State = C.getState();
    // Implementation depends on specific alias analysis available

    return false;
}
```

## Function Call Analysis

```cpp
/// Information about functions known to dereference parameters
struct KnownDerefFunction {
    const char *Name;                           ///< The function name
    llvm::SmallVector<unsigned, 4> Params;      ///< Parameter indices that get dereferenced
};

/// Table of functions known to dereference specific parameters
static constexpr KnownDerefFunction DerefTable[] = {
    // String functions
    {"strcpy", {1}},
    {"strncpy", {1}},
    {"strcmp", {0, 1}},
    {"strncmp", {0, 1}},
    {"strlen", {0}},
    {"strcat", {0, 1}},
    {"strncat", {0, 1}},

    // Memory functions
    {"memcpy", {0, 1, 2}},
    {"memmove", {0, 1, 2}},
    {"memcmp", {0, 1, 2}},
    {"memset", {0}},

    // I/O functions
    {"printf", {0}},  // format string
    {"sprintf", {0}},
    {"snprintf", {0}},
    {"scanf", {0}},
    {"sscanf", {0, 1}},

    {nullptr, {}}  // Sentinel
};

/// Check if a function call is known to dereference certain parameters
/// @param Call The function call to examine
/// @param DerefParams Output vector to store parameter indices that are dereferenced
/// @return true if the function is found in the known-dereference table
bool functionKnownToDeref(const CallEvent &Call,
                         llvm::SmallVectorImpl<unsigned> &DerefParams) {
    if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
        StringRef FnName = ID->getName();

        for (const auto &Entry : DerefTable) {
            if (Entry.Name && FnName.equals(Entry.Name)) {
                DerefParams.append(Entry.Params.begin(), Entry.Params.end());
                return true;
            }
        }
    }
    return false;
}

/// Check if a call is to a specific function by name
/// @param Call The call event
/// @param FnName The function name to check
/// @return true if the call is to the named function
bool isCallToFunction(const CallEvent &Call, StringRef FnName) {
    if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
        return ID->getName() == FnName;
    }
    return false;
}
```

## Source Text Analysis

```cpp
/// Check if the source text of an expression contains a specified name
/// @param E The expression to check
/// @param Name The name to look for
/// @param C The checker context
/// @return true if the expression's source text contains the name
bool ExprHasName(const Expr *E, StringRef Name, CheckerContext &C) {
    if (!E) return false;

    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();

    CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
    StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);

    return ExprText.contains(Name);
}

/// Get the source text of an expression
/// @param E The expression
/// @param C The checker context
/// @return The source text as a string
StringRef getExprSourceText(const Expr *E, CheckerContext &C) {
    if (!E) return StringRef();

    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();

    CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
    return Lexer::getSourceText(Range, SM, LangOpts);
}
```

## Type Checking Utilities

```cpp
/// Check if a type is a pointer type
/// @param QT The qual type to check
/// @return true if QT is a pointer type
bool isPointerType(QualType QT) {
    return !QT.isNull() && QT->isPointerType();
}

/// Check if a type is an array type
/// @param QT The qual type to check
/// @return true if QT is an array type
bool isArrayType(QualType QT) {
    return !QT.isNull() && QT->isArrayType();
}

/// Check if a type is a record (struct/class) type
/// @param QT The qual type to check
/// @return true if QT is a record type
bool isRecordType(QualType QT) {
    return !QT.isNull() && QT->isRecordType();
}

/// Get the pointee type of a pointer type
/// @param QT The qual type (should be a pointer type)
/// @return The pointee type, or null if QT is not a pointer
QualType getPointeeType(QualType QT) {
    if (isPointerType(QT)) {
        return QT->getPointeeType();
    }
    return QualType();
}

/// Get the element type of an array type
/// @param QT The qual type (should be an array type)
/// @return The element type, or null if QT is not an array
QualType getArrayElementType(QualType QT) {
    if (const ArrayType *AT = QT->getAsArrayTypeUnsafe()) {
        return AT->getElementType();
    }
    return QualType();
}
```

## Program State Management

```cpp
/// Create a new program state with a tracked value
/// @param State The current program state
/// @param Key The key to track
/// @param Value The value to associate with the key
/// @return New program state with the tracking information
template<typename KeyTy, typename ValTy>
ProgramStateRef setTrackedValue(ProgramStateRef State, KeyTy Key, ValTy Value) {
    return State->add<KeyTy>(Key, Value);
}

/// Remove a tracked value from program state
/// @param State The current program state
/// @param Key The key to remove
/// @return New program state without the key
template<typename KeyTy>
ProgramStateRef removeTrackedValue(ProgramStateRef State, KeyTy Key) {
    return State->remove<KeyTy>(Key);
}

/// Check if a value is being tracked in program state
/// @param State The current program state
/// @param Key The key to check
/// @return true if the key is being tracked
template<typename KeyTy>
bool isValueTracked(ProgramStateRef State, KeyTy Key) {
    return State->contains<KeyTy>(Key);
}
```

## Bug Reporting Helpers

```cpp
/// Create a non-fatal bug report (allows finding multiple bugs in one path)
/// @param BT The bug type
/// @param Desc Short description of the bug
/// @param Location The location where the bug was detected
/// @param C The checker context
/// @return Unique pointer to the bug report
std::unique_ptr<PathSensitiveBugReport> createNonFatalBugReport(
    const BugType &BT,
    StringRef Desc,
    PathDiagnosticLocation Location,
    CheckerContext &C) {

    // Use generateNonFatalErrorNode to allow continued exploration
    ExplodedNode *ErrorNode = C.generateNonFatalErrorNode(C.getState());
    if (!ErrorNode) return nullptr;

    return std::make_unique<PathSensitiveBugReport>(BT, Desc, ErrorNode, Location);
}

/// Create a basic bug report (for path-insensitive bugs)
/// @param BT The bug type
/// @param Desc Short description of the bug
/// @param Location The location where the bug was detected
/// @return Unique pointer to the basic bug report
std::unique_ptr<BasicBugReport> createBasicBugReport(
    const BugType &BT,
    StringRef Desc,
    PathDiagnosticLocation Location) {

    return std::make_unique<BasicBugReport>(BT, Desc, Location);
}
```

## Null and Undefined Value Checking

```cpp
/// Check if an SVal represents a null pointer
/// @param Val The symbolic value to check
/// @return true if Val is known to be null
bool isNullPtr(SVal Val) {
    if (Optional<loc::ConcreteInt> ConcreteVal = Val.getAs<loc::ConcreteInt>()) {
        return ConcreteVal->getValue().isZero();
    }
    return false;
}

/// Check if an SVal represents an undefined value
/// @param Val The symbolic value to check
/// @return true if Val is undefined
bool isUndefined(SVal Val) {
    return Val.isUndef();
}

/// Check if a state has a constraint indicating null
/// @param State The program state
/// @param Sym The symbol to check
/// @return true if the symbol is constrained to be null
bool isConstrainedNull(ProgramStateRef State, SymbolRef Sym) {
    if (!Sym) return false;

    // Check if symbol is constrained to equal 0
    const llvm::APSInt *Zero = nullptr;
    if (State->getConstraintManager().getSymVal(State, Sym, Zero)) {
        return Zero && Zero->isZero();
    }

    return false;
}

/// Check if a state has a constraint indicating non-null
/// @param State The program state
/// @param Sym The symbol to check
/// @return true if the symbol is constrained to be non-null
bool isConstrainedNonNull(ProgramStateRef State, SymbolRef Sym) {
    if (!Sym) return false;

    // Assume non-null if not constrained to null
    // This is a conservative approximation
    return !isConstrainedNull(State, Sym);
}
```

## Macro and Attribute Detection

```cpp
/// Check if a function declaration has a specific attribute
/// @param FD The function declaration
/// @param AttrKind The attribute kind to check
/// @return true if the function has the attribute
bool functionHasAttribute(const FunctionDecl *FD, attr::Kind AttrKind) {
    if (!FD) return false;

    for (const Attr *A : FD->attrs()) {
        if (A->getKind() == AttrKind) {
            return true;
        }
    }
    return false;
}

/// Check if a statement is within a macro expansion
/// @param S The statement
/// @param C The checker context
/// @return true if the statement is from a macro
bool isInMacro(const Stmt *S, CheckerContext &C) {
    if (!S) return false;

    SourceLocation Loc = S->getBeginLoc();
    return Loc.isMacroID();
}

/// Get the name of a macro if the location is in a macro expansion
/// @param Loc The source location
/// @param C The checker context
/// @return The macro name, or empty string if not in a macro
StringRef getMacroName(SourceLocation Loc, CheckerContext &C) {
    if (!Loc.isMacroID()) return StringRef();

    const SourceManager &SM = C.getSourceManager();
    return SM.getImmediateMacroCallerLoc(Loc).printToString(SM);
}
```

## Loop and Control Flow Analysis

```cpp
/// Check if we're inside a loop
/// @param C The checker context
/// @return true if current location is inside a loop
bool isInLoop(CheckerContext &C) {
    const LocationContext *LCtx = C.getLocationContext();
    const Stmt *S = LCtx->getCurrentStatement();

    // Search parent stack for loop statements
    for (const LocationContext *CurrentLC = LCtx; CurrentLC; CurrentLC = CurrentLC->getParent()) {
        if (const Stmt *ParentStmt = CurrentLC->getCurrentStatement()) {
            if (isa<ForStmt>(ParentStmt) || isa<WhileStmt>(ParentStmt) ||
                isa<DoStmt>(ParentStmt) || isa<CXXForRangeStmt>(ParentStmt)) {
                return true;
            }
        }
    }

    return false;
}

/// Get the enclosing loop statement if any
/// @param C The checker context
/// @return The loop statement, or nullptr if not in a loop
const Stmt *getEnclosingLoop(CheckerContext &C) {
    const LocationContext *LCtx = C.getLocationContext();

    for (const LocationContext *CurrentLC = LCtx; CurrentLC; CurrentLC = CurrentLC->getParent()) {
        if (const Stmt *ParentStmt = CurrentLC->getCurrentStatement()) {
            if (isa<ForStmt>(ParentStmt) || isa<WhileStmt>(ParentStmt) ||
                isa<DoStmt>(ParentStmt) || isa<CXXForRangeStmt>(ParentStmt)) {
                return ParentStmt;
            }
        }
    }

    return nullptr;
}
```

## Size and Length Computations

```cpp
/// Compute a safe buffer size considering potential overflow
/// @param Count The count of elements
/// @param ElemSize The size of each element
/// @param C The checker context
/// @return The computed size, or None if overflow detected
Optional<llvm::APInt> computeSafeSize(const llvm::APInt &Count,
                                      const llvm::APInt &ElemSize,
                                      CheckerContext &C) {
    bool Overflow = false;
    llvm::APInt Result = Count.umul_ov(ElemSize, Overflow);

    if (Overflow) {
        return None;  // Overflow detected
    }

    return Result;
}

/// Check if a size computation might overflow
/// @param Count The count expression
/// @param ElemSize The element size expression
/// @param C The checker context
/// @return true if overflow is possible
bool sizeMayOverflow(const Expr *Count, const Expr *ElemSize, CheckerContext &C) {
    llvm::APSInt CountVal, SizeVal;

    if (EvaluateExprToInt(CountVal, Count, C) &&
        EvaluateExprToInt(SizeVal, ElemSize, C)) {
        bool Overflow = false;
        CountVal.umul_ov(SizeVal, Overflow);
        return Overflow;
    }

    // Can't determine statically - assume possible overflow
    return true;
}
```

## Type Casting Analysis

```cpp
/// Check if a cast is potentially dangerous (e.g., losing precision)
/// @param CastE The cast expression
/// @param C The checker context
/// @return true if the cast is potentially dangerous
bool isDangerousCast(const CastExpr *CastE, CheckerContext &C) {
    if (!CastE) return false;

    QualType SrcType = CastE->getSubExpr()->getType();
    QualType DstType = CastE->getType();

    const ASTContext &ASTCtx = C.getASTContext();

    // Check for size truncation
    unsigned SrcBits = ASTCtx.getTypeSize(SrcType);
    unsigned DstBits = ASTCtx.getTypeSize(DstType);

    if (DstBits < SrcBits) {
        // Potentially losing information
        return true;
    }

    // Check for signed to unsigned conversion of potentially negative values
    if (SrcType->isSignedIntegerType() && DstType->isUnsignedIntegerType()) {
        return true;
    }

    // Check for pointer to integer casts of different sizes
    if (SrcType->isPointerType() && DstType->isIntegerType()) {
        unsigned PtrBits = ASTCtx.getTargetInfo().getPointerWidth(
            SrcType->getAs<PointerType>()->getPointeeType().getAddressSpace());

        if (DstBits < PtrBits) {
            return true;
        }
    }

    return false;
}
```

---
*Note: This utility library provides commonly used helper functions for Clang Static Analyzer checker development. All functions are designed to work with Clang 18+ APIs.*
