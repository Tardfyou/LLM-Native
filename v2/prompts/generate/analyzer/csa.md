CSA 目标：生成 Clang-18 插件式 checker 源文件，编译成 .so

必备头文件：
```cpp
#include "clang/AST/Expr.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/Version.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <memory>
```

必备导出：
```cpp
extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<YourChecker>("custom.YourChecker", "Description", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;
```

Clang-18 API 约束：

❌ 禁止使用的 API（不存在或签名不同）：
- `Stmt::getParent()` - 不存在
- `Stmt::getParentStmt()` - 不存在
- `Expr::getParent()` - 不存在
- 直接调用 `ASTContext::getParents()` - 返回类型复杂，需要额外头文件

✅ 正确的 API 用法：
- 获取函数名：`Call.getCalleeIdentifier()->getName()` 或 `CallEvent::getCalleeIdentifier()`
- 获取参数：`Call.getArgSVal(index)` 或 `Call.getArgExpr(index)`
- 获取参数数量：`Call.getNumArgs()`
- 获取内存区域：`SVal::getAsRegion()` 或 `Call.getArgSVal(0).getAsRegion()`
- 获取符号：`SVal::getAsSymbol()` 或 `SVal::getAsLocSymbol()`
- 获取类型：`MemRegion::getValueType()` 或 `TypedValueRegion::getValueType()`
- 获取静态大小：`ASTContext::getTypeSizeInChars(QualType).getQuantity()`
- 转换类型：`dyn_cast<T>(ptr)` 或 `cast<T>(ptr)`
- 检查字符串前缀：`StringRef::starts_with()` (Clang-18 用 starts_with，不是 startswith)
- 检查字符串后缀：`StringRef::ends_with()`
- 检查字符串包含：`StringRef::contains()` 或 `StringRef::contains_insensitive()`
- 获取 ASTContext：`C.getASTContext()` (CheckerContext 方法)
- 检查空指针常量：`Expr::isNullPointerConstant(ASTContext&, NullPointerConstantValueDependence)` 返回 `NullPointerConstantKind`
  - 正确：`E->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNotNull) == Expr::NPCK_Null`
  - 错误：`E->isNullPointerConstant(E->getType(), ...)` - 第一个参数必须是 ASTContext&

ProgramState 约束：
- 注册状态：`REGISTER_SET_WITH_PROGRAMSTATE(Name, Type)` 或 `REGISTER_MAP_WITH_PROGRAMSTATE(Name, Key, Value)`
- 添加状态：`State = State->add<Name>(value)`
- 检查状态：`State->contains<Name>(value)`
- 获取状态：`State->get<Name>(key)`

报告约束：
- `PathSensitiveBugReport` 需要 `ExplodedNode*`
- 生成节点：`C.generateNonFatalErrorNode()` 或 `C.generateErrorNode()`
- 添加范围：`Report->addRange(Expr->getSourceRange())`
- 发送报告：`C.emitReport(std::move(Report))`

检查模式推荐：
- `check::PreCall` / `check::PostCall` - 函数调用前后
- `check::PreStmt<MemberExpr>` - 成员访问前
- `check::Location` - 内存位置访问
- `check::Bind` - 值绑定

不要虚构 CSA API，不要使用未列出的方法签名。