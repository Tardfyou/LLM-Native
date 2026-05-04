CSA 目标：严格生成 Clang-18 插件式 checker 源文件，编译成 `.so`，用 `custom.<checker_name>` 验证。

必备导出：
```cpp
extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<YourChecker>("custom.YourChecker", "Description", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;
```

基础 API 约束：
- 注册名必须是 `custom.<checker_name>`，类名、文件主类名和 `checker_name` 保持一致。
- `REGISTER_SET_WITH_PROGRAMSTATE` / `REGISTER_MAP_WITH_PROGRAMSTATE` 放在类外。
- 不要使用 `Stmt::getParent()`、`Stmt::getParentStmt()`、`Expr::getParent()`。
- 不要直接使用 `ASTContext::getParents()`；generate 阶段通常不需要父节点反查。
- 不要调用 `MemRegion::getValueType()`；需要时先 `dyn_cast<TypedValueRegion>(MR)`。
- `StringRef` 使用 `starts_with()` / `ends_with()` / `contains()` / `contains_insensitive()`。
- 所有 `Expr*`、`Stmt*`、`MemRegion*`、`IdentifierInfo*`、`ValueDecl*` 使用前必须判空。

Clang-18 兼容硬约束（高优先级）：
- 必备头文件：
```
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
- 必备导出：
```
extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<YourChecker>("custom.YourChecker", "Description", "");
}
```
- 不要包含以下易错头：
  - `clang/StaticAnalyzer/Frontend/AnalysisManager.h`
  - `clang/StaticAnalyzer/Core/PathDiagnosticLocation.h`
- `check::ASTCodeBody` 签名固定为：
  - `void checkASTCodeBody(const Decl *D, AnalysisManager &, BugReporter &BR) const`
- 在 `checkASTCodeBody` 中不要访问 `AnalysisManager` 成员；把它当占位参数。
- `BugReporter::getSourceManager()` 返回 `const SourceManager &`；局部变量也必须写成 `const SourceManager &SM = BR.getSourceManager();`，不要写成非常量引用。
- `AnalysisManager`、`ASTContext`、`SourceManager` 这类只读上下文对象，默认按 `const &` 接。
- 不要使用 `BT->getName()` 参与 `EmitBasicReport` 调用。

报告约束：
- 路径敏感回调中使用 `PathSensitiveBugReport`，节点只能来自当前 `CheckerContext`。
- `check::ASTCodeBody` / `RecursiveASTVisitor` 没有 `CheckerContext` 和真实 `ExplodedNode`，必须用 `BR.EmitBasicReport(...)` 或 `BasicBugReport`。
- `C.generateNonFatalErrorNode()` 返回空时直接返回。
- `EmitBasicReport` 推荐固定写法（避免签名不匹配）：
  - `const SourceManager &SM = BR.getSourceManager();`
  - `PathDiagnosticLocation Loc(Node->getBeginLoc(), SM);`
  - `BR.EmitBasicReport(FD, this, "Title", "Category", "Description", Loc, Node->getSourceRange());`

建模优先级：
1. 先建立 patch-local 最小 trigger：changed file、changed function、被改表达式、同变量/字段的邻近 release/use/reassign/null/guard。
2. generate 首稿允许更贴补丁、更特化；只要仍锚定 patch-local 事实，命中偏多优于 0 hit。
3. 对删除危险调用/释放/写入的补丁，漏洞版 trigger 优先是被删除操作本身；修复版静默通常由该操作消失保证。
4. 对新增 guard/barrier 的补丁，先匹配原始 source/sink；首稿不强制把 guard/barrier 写成过滤条件。
5. 对替换 API 的补丁，先匹配旧 API 和相同角色参数，再考虑 safe API 排除。
6. 只有 patch 附近事实不够时，才考虑跨函数、ProgramState 或更复杂的路径敏感建模。
7. 如果新增 guard 的真实锚点是某个解析/读入/写入 API 对补丁字段的直接触达，漏洞版 trigger 可以直接落在该 API 触点；不要要求漏洞版源码里一定还存在结构化的缺失 guard 形状。
8. 变量来源既要考虑 `BinaryOperator` 赋值，也要考虑 `VarDecl` 声明初始化；识别写入/累积时既要覆盖 `=`，也要覆盖 `|=`、`+=` 等复合赋值，不能因为 RHS 不再显式引用 lhs 就漏掉 trigger。

删除释放/销毁类补丁的特别规则：
- 先在 changed function 内按源码顺序找同一资源的 earlier/later release/use/reassign/null；不要默认跳到调用者。
- 不要要求某个 callee 接收被释放资源，除非补丁或调用参数明确包含该资源。
- 识别释放实参时剥离 cast、paren、`&var`，优先比较 `VarDecl` / `FieldDecl` 身份。
- 如果被删除释放是第二次释放，不能把它当第一次释放再寻找后续 release；要检查它之前是否已有同资源 release。

CSA 落地策略：
- 默认优先 `check::ASTCodeBody` 做函数内结构扫描；这对 patch-local release/use/guard/order 模式更稳。
- 需要真实路径状态时再用 `check::PreCall` / `PostCall` / `Bind` / `BranchCondition` 和 ProgramState。
- 当 `ASTCodeBody` 很难稳定覆盖“精确 API 调用 / 字段赋值 / 解析入口”时，优先改用 `check::PreCall` / `PostCall` / `Bind` 直接挂到该 patch-local 触点，不要为了维持 AST 扫描形式把 trigger 做空。
- AST 扫描必须递归遍历 `if`、循环、嵌套 `CompoundStmt` 和表达式子树。
- 复杂表达式递归剥离 cast/paren，并遍历 `DeclRefExpr`、`MemberExpr`、`CallExpr`、`ArraySubscriptExpr`。
- 不要让 source、传播、guard、sink 全部强耦合到同一个易失条件里；先保证 patch 文件/函数内能触发。

生成质量目标：
- 首稿必须能解释为什么漏洞版 patch 附近会报警。
- 不要为了泛化、静默或漂亮 barrier 牺牲基本命中；不要退化成项目级宽泛规则。
- 编译/LSP 修复只能局部修 API 或报告构造，不能删除核心检测逻辑。
