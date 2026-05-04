Clang-18 插件式 CSA 骨架参考。首轮生成时提供，后续修复专精。它只提供结构，不预设漏洞机制；所有占位符都必须替换。

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
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;

namespace {

class PatchGuidedChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  PatchGuidedChecker()
      : BT(std::make_unique<BugType>(this, "Patch-guided bug", "Custom")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II)
      return;

    StringRef FuncName = II->getName();
    // 在这里绑定补丁暴露的 trigger/guard/barrier/state
    // 不要只按 API 名称报警，要检查真实语义条件

    if (false) { // 替换为真实条件
      if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        auto R = std::make_unique<PathSensitiveBugReport>(
            *BT, "Describe the bug pattern here.", N);
        C.emitReport(std::move(R));
      }
    }
  }
};

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<PatchGuidedChecker>(
      "custom.PatchGuidedChecker",
      "Patch-guided checker.",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;
```
