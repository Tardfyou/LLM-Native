你正在执行一个受控的 detector/query 精炼工作流。

**目标文件类型**：
- CSA：Clang-18 插件式 checker 源文件（.cpp），编译为 .so 动态插件
- CodeQL：.ql 查询文件，用于 CodeQL 数据库分析

{{TASK_PROMPT}}

当前轮次: {{ITERATION}} / {{MAX_ITERATIONS}}

系统会在你提交 `apply_patch` 后自动执行本地验证与结构审查。
不要请求编译、LSP、CodeQL 分析或 review；这些由工作流自动完成。

当前工作副本全文：
```text
{{ARTIFACT_TEXT}}
```

补丁全文：
```diff
{{PATCH_TEXT}}
```

附加上下文：
{{CONTEXT_NOTES}}

---

## 可选证据类型清单

当你觉得需要补充上下文信息时，可以从以下证据类型中选择需要获取的项：

| 证据类型 | 说明 | 适用场景 |
|---------|------|---------|
| `patch_fact` | 补丁事实摘要 | 需要理解补丁修复的漏洞模式、涉及的函数和文件 |
| `semantic_slice` | 语义切片（代码片段） | 需要补丁涉及的上下文代码文件对应代码切片信息 |
| `dataflow_candidate` | 数据流候选 | 需要理解数据如何在变量/API间流动 |
| `call_chain` | 调用链 | 需要理解函数调用关系、callee/caller |
| `path_guard` | 路径守卫条件 | 需要理解条件检查、边界守卫 |
| `allocation_lifecycle` | 分配生命周期 | 内存漏洞场景（use_after_free, double_free） |
| `state_transition` | 状态转换 | 状态机、锁状态、引用计数场景 |
| `directory_tree` | 目录层级信息 | 需要了解项目结构、文件位置、目录层级 |

**使用方式**：
- 在 `cot_analysis.evidence_needed` 中列出需要的证据类型
- 系统会在下一轮提供对应证据内容
- 不需要重复请求已提供的证据类型

---

## 目标文件结构约束

### CSA Checker (Clang-18 插件式)

必备头文件：
```cpp
#include "clang/AST/Expr.h"
#include "clang/Basic/SourceLocation.h"
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

必备导出（插件注册）：
```cpp
extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<YourChecker>("custom.YourChecker", "Description", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;
```

Clang-18 API 约束（禁止使用不存在的 API）：
- ❌ `Stmt::getParent()` / `Stmt::getParentStmt()` - 不存在
- ❌ `Expr::getParent()` - 不存在
- ❌ `StringRef::lower().str()` - `lower()` 已返回 `std::string`
- ✅ `StringRef::starts_with()` (不是 `startswith`)
- ✅ `State->get<MapName>(key)` 返回 `const Value*` 指针，不是 `std::optional`
- ✅ 获取函数名：`Call.getCalleeIdentifier()->getName()`
- ✅ 获取参数：`Call.getArgSVal(index)` 或 `Call.getArgExpr(index)`
- ✅ 获取内存区域：`SVal::getAsRegion()`
- ✅ 生成报告节点：`C.generateNonFatalErrorNode()` 或 `C.generateErrorNode()`

不要虚构 CSA API，不要使用未列出的方法签名。

### CodeQL Query (.ql)

约束：
- 量词变量必须在同一 `exists()` 参数列表中声明
- 不要引用外层兄弟量词里的局部变量
- 沿用骨架里的 exact CodeQL API 名称和类型名
- 不要臆造不存在的 CodeQL API、类型、成员方法

禁止改写：
- `SizeofExprOperator` → `sizeof(...)` ❌
- `GuardCondition.ensuresLt` → `ComparisonOperation` ❌
- `getTarget()` → 其他伪 API ❌
- `bbDominates` → 自定义支配关系 ❌

---

## 决策规则

**修改原则**：
- 只输出 unified diff（增量修改），禁止整文件重写
- 首轮只修改与补丁机制直接相关的函数体，不改文件头/include/注册代码

**CSA 特殊约束**：
- 不要引入无法确认签名的 API；不要臆造 `ProgramState`/`CheckerContext`/`SVal` 辅助方法
- 如果 patch 用显式长度检查加 bounded API 替换 risky API，围绕 removed risky API 与新增 guard/barrier 做精炼
- 如果 review 指出 helper 是 callee-only direct report，优先删除该 dispatch/helper
- 不要重复声明同名局部变量；不要提交带 `for now`/`placeholder` 等占位说明的补丁

**语义增强判断**：
- 如果当前实现仍主要依赖 API 名称、`strlen/strnlen`、变量名启发式，这还不算完成
- 要么推进到真实的 destination capacity / guard / region / state 语义，要么停止并保留基线

**失败修复策略**：
- 先从附加上下文定位最后一个失败工具的报错
- LSP/compile/parse 失败时，只修 API/参数/类型/量词作用域/include，不扩大语义改动
- patch 应用失败时，缩小 hunk 范围并严格对齐当前工作副本

**终止条件**：
- 通过质量门且无更强语义改进方案 → 输出 `finish`
- 不提交只改注释/排版/变量名的等价补丁

---

## CoT思考引导

**Step 1: 分析当前状态**
- 当前实现是否已捕获补丁核心漏洞机制？
- 是否缺少关键上下文信息（代码切片、调用链、守卫条件等）？

**Step 2: 判断下一步行动**
- 如果缺少上下文 → 选择需要的证据类型，输出 `request_evidence`
- 如果上下文足够且有修复方案 → 输出 `apply_patch`
- 如果已通过质量门且无需改进 → 输出 `finish`

**Step 3: 检查修改约束（apply_patch时）**
- 只输出 unified diff（增量修改），禁止整文件重写
- 首轮只修改与补丁机制直接相关的函数体

---

只输出一个 JSON 对象，不要添加解释，不要使用 Markdown 代码块。

JSON schema:
{
  "cot_analysis": {
    "current_semantics": "足够 / 不足",
    "missing_context": "描述缺少的上下文信息",
    "evidence_needed": ["证据类型列表，如 patch_fact, semantic_slice, call_chain 等"],
    "strategy": "语义增强 / 结构优化 / 保持现状"
  },
  "action": "request_evidence" | "apply_patch" | "finish",
  "summary": "一句话说明本轮意图",
  "evidence_types": "当 action 为 request_evidence 时填写需要的证据类型数组；否则为空数组",
  "patch": "当 action 为 apply_patch 时填写 unified diff；否则为空字符串",
  "resulting_content": "可选。当 patch 应用失败且需要 fallback 时填写完整文本；其他情况留空字符串"
}