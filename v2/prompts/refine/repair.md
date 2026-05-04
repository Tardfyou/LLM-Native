你在执行 refine 的修复阶段。只处理这一次最新失败，不要回头重做补丁机制分析。

{{TASK_PROMPT}}

当前产物路径：{{ARTIFACT_PATH}}

当前产物全文：
```text
{{ARTIFACT_TEXT}}
```

最后一次失败工具：{{LATEST_FAILURE_TITLE}}
当前焦点行：{{LATEST_FAILURE_LINES}}

失败详情：
```text
{{LATEST_FAILURE_TEXT}}
```

修复规则：
1. repair 只修最新失败点，优先消除语法、API、类型、量词、局部结构错误
2. 本大轮已经离开 decide；无论失败来自 LSP、审查、编译、CSA 功能验证还是 CodeQL analyse，都不要回头重做补丁机制分析
3. 只提交唯一且可精确命中的局部替换；如果当前产物无需修复，输出 `finish`
4. 不要通过删掉机制判断、退回到更窄的 API/名称匹配、或把检测重新绑回 patch-site 来“修复”失败
5. 修复成功后系统会重新跑同一套验证门；只有本大轮全部通过后，才会回到下一轮 decide

CSA 特殊规则：
- Clang-18 下不要使用不存在的 API
- `Stmt::getParent()` / `Stmt::getParentStmt()` / `Expr::getParent()` 都不要用
- `StringRef::starts_with()` 是正确 API
- `State->get<MapName>(key)` 返回的是指针语义，不是 `std::optional`
- 如果失败来自 review finding，优先删掉伪语义 helper 或把 helper 绑定到真实 guard/region/state

CodeQL 特殊规则：
- 量词变量必须在同一 `exists()` 参数列表中声明
- 不要跨量词引用局部变量
- 先修作用域、括号、API 名称、类型，再考虑别的
- 不要臆造 `IntegerLiteral`、`IntLiteral` 之类不存在的类型名；遇到字面量相关失败，优先改写成仓库内已验证可用的表达方式

只输出一个 JSON 对象，不要添加解释。

JSON schema:
{
  "action": "apply_patch" | "finish",
  "summary": "一句话说明本轮修复意图",
  "edits": [
    {
      "old_snippet": "当前产物中的唯一旧片段",
      "new_snippet": "替换后的新片段"
    }
  ]
}
