你在执行 generate 的修复阶段。只处理这一次最新失败，不要顺手改别的。

{{TASK_PROMPT}}

当前目标文件名：{{CHECKER_NAME}}
当前产物路径：{{ARTIFACT_PATH}}

当前产物全文：
```text
{{ARTIFACT_TEXT}}
```

失败工具：{{LATEST_FAILURE_TITLE}}

失败详情：
```text
{{LATEST_FAILURE_TEXT}}
```

修复规则：
1. repair 阶段默认只修最新失败点，专注语法、API、类型、局部结构修复
2. 修复顺序：API/成员名 -> 参数类型/个数 -> 变量作用域 -> include/import
3. 确认 header 存在后再添加 include
4. 不要整文件重写，只做局部精确替换
5. 编译错误时专注于解决语法问题，不许删改已有漏洞语义建模
6. 如果失败是 semantic_no_hits、executed_no_hit 或“未命中验证目标”，允许最小化修正 trigger 方向或过窄条件；优先回到 patch-local 事实，不要扩大成项目级宽泛规则
7. 对删除危险操作的补丁，0 命中时优先检查是否把“删除处”误当成第一次事件、是否错误要求后续事件、是否强加了补丁中不存在的 callee/resource/dataflow 关系

CSA 特殊规则：
- 版本是 Clang-18，API 可能与旧版本不同
- `Stmt::getParent()` / `Stmt::getParentStmt()` 不存在，不要使用
- 获取父节点需要 `ParentMap` 或 `ASTContext::getParents()`，但这通常不需要
- 用 `StringRef::starts_with()` 而非 `startswith()`
- 路径敏感回调中才使用 `PathSensitiveBugReport`，节点必须来自当前 `CheckerContext`
- `check::ASTCodeBody` / `RecursiveASTVisitor` 中没有真实 `ExplodedNode`，不要使用 `PathSensitiveBugReport`，不要伪造 `ExplodedNode`
- 若 AST 扫描式 checker 因 `PathDiagnosticLocation::createBegin`、`ExplodedNode`、`generateErrorNode` 报错，保持已有漏洞语义建模不变，把报告构造局部替换为 `BR.EmitBasicReport(...)` 或 `BasicBugReport`
- 确保 `clang_registerCheckers` 和 `clang_analyzerAPIVersionString` 正确
- 如果 LSP 报告 API 不存在，删除该调用或换用正确 API

CodeQL 特殊规则：
- 量词变量必须在同一 exists() 中声明
- 不要跨量词引用局部变量
- 检查括号和量词闭合
- 同类 exact API、类型名或成员名错误连续两次仍未收敛时，不要继续猜；先回到仓库内已成功 `.ql` 样例或最小 probe，确认 exact symbol 后再改
- 如果 `old_snippet` 未命中，先基于当前产物全文重新定位并缩小 edit；同一旧片段连续未命中时，不要重复提交等价 patch

如果当前产物已经足够好且无需修复，输出 `finish`；否则输出 `apply_patch`。

只输出一个 JSON 对象，不要添加解释。

JSON schema:
{
  "action": "apply_patch" | "finish",
  "summary": "一句话说明本轮意图",
  "edits": [
    {
      "old_snippet": "当前产物中的唯一旧片段",
      "new_snippet": "替换后的新片段"
    }
  ]
}
