你在执行 generate 的修复阶段。只处理这一次最新失败，不要顺手改别的。

{{TASK_PROMPT}}

当前目标文件名：{{CHECKER_NAME}}
当前产物路径：{{ARTIFACT_PATH}}

当前产物全文：
```text
{{ARTIFACT_TEXT}}
```

补丁全文：
```diff
{{PATCH_TEXT}}
```

失败工具：{{LATEST_FAILURE_TITLE}}

失败详情：
```text
{{LATEST_FAILURE_TEXT}}
```

修复规则：
1. 只修失败点，不改变语义骨架
2. 修复顺序：API/成员名 -> 参数类型/个数 -> 变量作用域 -> include/import
3. 确认 header 存在后再添加 include
4. 不要整文件重写，只做局部精确替换

CSA 特殊规则：
- 版本是 Clang-18，API 可能与旧版本不同
- `Stmt::getParent()` / `Stmt::getParentStmt()` 不存在，不要使用
- 获取父节点需要 `ParentMap` 或 `ASTContext::getParents()`，但这通常不需要
- 用 `StringRef::starts_with()` 而非 `startswith()`
- BugReport 只用 `PathSensitiveBugReport` 或 `BasicBugReport`
- 确保 `clang_registerCheckers` 和 `clang_analyzerAPIVersionString` 正确
- 如果 LSP 报告 API 不存在，删除该调用或换用正确 API

CodeQL 特殊规则：
- 量词变量必须在同一 exists() 中声明
- 不要跨量词引用局部变量
- 检查括号和量词闭合

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