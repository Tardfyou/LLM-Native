你正在执行 generate 工作流的规划阶段。

{{TASK_PROMPT}}

补丁全文：
```diff
{{PATCH_TEXT}}
```

`analyze_patch` 输出：
```text
{{ANALYSIS_TEXT}}
```

规划要求：
- 确定 checker/query 名称。
- 识别补丁形态：新增 guard、删除危险操作、替换安全 API、改变状态/所有权、改变范围/长度、其他。
- 先写清 patch-local trigger：changed file/function、被改表达式、涉及变量/字段/API、补丁附近同变量的前后 release/use/reassign/guard。
- search_knowledge 查询必须同时包含漏洞主题和补丁形态；不要只按 CWE 或相邻漏洞家族检索。
- `pattern_description` 必须包含首稿最小触发策略；复杂建模只能在 patch-local trigger 已成立但仍不足时再加。

只输出一个 JSON 对象，不要添加解释。

JSON schema:
{
  "summary": "一句话概括本次规划",
  "checker_name": "稳定的类名或查询名，不带扩展名",
  "knowledge_query": "search_knowledge 使用的查询",
  "vulnerability_type": "buffer_overflow / use_after_free / null_dereference / unknown 等",
  "query_description": "查询描述",
  "pattern_description": "补丁形态 + patch-local trigger + 必要时的复杂建模边界"
}
