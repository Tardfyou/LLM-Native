你正在执行一个受控的 detector/query 精炼工作流。

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

决策规则：
- 优先做最小修改；不要整文件重写。
- 首轮 `apply_patch` 只应修改与 findings/补丁机制直接相关的函数体；不要无故改文件头注释、include 区或注册代码。
- 对 CSA，不要引入你无法确认签名的 API；特别不要臆造 `ProgramState`/`CheckerContext`/`SVal` 辅助方法。

CSA API 约束 (Clang-18)：
- `Stmt::getParent()` / `Stmt::getParentStmt()` 不存在，不要使用
- `StringRef::lower()` 返回 `std::string`，不要再调用 `.str()`
- `State->get<MapName>(key)` 返回 `const Value*` 指针，不是 `std::optional`
- 用 `StringRef::starts_with()` 而非 `startswith()`
- 如果 LSP 报告 API 不存在，删除该调用或换用正确 API

- 对 CSA，如果 patch 用显式长度检查加 bounded API 替换 risky API，优先围绕 removed risky API 与新增 guard/barrier 做精炼；不要额外发明无补丁证据的 `sprintf`/新 sink 规则。
- 对 CSA，如果 review 指出 helper 是 callee-only direct report，优先删除该 dispatch/helper，或让它真实读取当前 call 的实参与 guard；不要靠未使用的 `ProgramStateRef State = C.getState();` 或 `assume(...).isValid()` 来“伪装”有语义。
- 如果当前基线已经通过严格精炼质量门，且你没有明确、更强的语义改进方案，直接输出 `finish`；不要提交只改注释、排版、分支顺序或变量名的等价补丁。
- 如果当前实现仍主要依赖 API 名称、`strlen/strnlen`、变量名中 `len/size/bytes` 等启发式来声明“缺少 destination size/capacity validation”，这还不算完成；你要么继续把逻辑推进到真实的 destination capacity / guard / region / state 语义，要么停止并保留基线。
- 结构修补只能作为第一步；只有当候选在语义上明显更接近 patch 机制时，才值得提交。
- 对 CSA，不要重复声明同名局部变量；不要提交带 `for now`、`placeholder`、`in a more complete implementation` 一类占位说明的补丁。
- 如果已有上下文足够，直接输出 `apply_patch`。
- 先从 `附加上下文` 中定位最后一个失败工具的报错；下一轮补丁只修那个报错直接指向的问题。
- 如果上一轮是 LSP / compile / CodeQL parse 失败，这一轮只允许修 API、参数、类型、量词作用域、未使用变量、include/import；不要顺手扩大语义改动面。
- 当 action 为 `apply_patch` 时，只有在 `patch` 与 `resulting_content` 表示同一组局部修改时，才提供 `resulting_content`。
- 如果上一轮 `apply_patch` 失败，不要用 `resulting_content` 去整文件重写；应先缩小 hunk 并严格贴合当前工作副本。
- 只有缺少关键源码或目录信息时，才输出 `read_reference_file` 或 `list_reference_dir`。
- 只有遇到真实 API / 语义不确定性时，才输出 `search_knowledge`。
- 如果上一次 `apply_patch` 失败，下一次补丁必须缩小 hunk 范围并严格对齐当前工作副本。
- 如果上一轮 `lsp_validate_artifact` 或 `compile_artifact` 失败，下一轮补丁只能修这些报错，不要继续扩大语义改动面。
- 如果当前工作副本已经满足目标且无需继续修改，输出 `finish`。

只输出一个 JSON 对象，不要添加解释，不要使用 Markdown 代码块。

JSON schema:
{
  "action": "apply_patch" | "read_reference_file" | "list_reference_dir" | "search_knowledge" | "finish",
  "summary": "一句话说明本轮意图",
  "path": "当 action 为 read_reference_file 或 list_reference_dir 时填写；否则为空字符串",
  "recursive": false,
  "query": "当 action 为 search_knowledge 时填写；否则为空字符串",
  "patch": "当 action 为 apply_patch 时填写 unified diff；否则为空字符串",
  "resulting_content": "强烈建议在 action 为 apply_patch 时填写补丁应用后的完整文本；其他 action 留空字符串"
}
