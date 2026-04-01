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
- 确定 checker/query 名称
- 给出 search_knowledge 查询，目标是找到与补丁机制一致的骨架
- 查询应包含漏洞主题、核心 API、guard/barrier/state 线索

只输出一个 JSON 对象，不要添加解释。

JSON schema:
{
  "summary": "一句话概括本次规划",
  "checker_name": "稳定的类名或查询名，不带扩展名",
  "knowledge_query": "search_knowledge 使用的查询",
  "vulnerability_type": "buffer_overflow / use_after_free / null_dereference / unknown 等",
  "query_description": "查询描述",
  "pattern_description": "模式说明"
}