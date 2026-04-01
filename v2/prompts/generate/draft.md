你正在执行 generate 工作流的首稿阶段。

{{TASK_PROMPT}}

当前目标文件名：{{CHECKER_NAME}}
目标路径：{{ARTIFACT_PATH}}
RAG 符合性：{{RAG_MATCH}}

补丁全文：
```diff
{{PATCH_TEXT}}
```

`analyze_patch` 输出：
```text
{{ANALYSIS_TEXT}}
```

`search_knowledge` 输出：
```text
{{KNOWLEDGE_TEXT}}
```

`rag_check` 结论：
```text
{{RAG_CHECK_RESULT}}
```

参考骨架（首轮提供）：
{{REFERENCE_SKELETON}}

首稿要求：
- RAG 符合时：忠于检索骨架的 shape、回调组织和关键 include/import，只调整不匹配补丁机制的部分
- RAG 不符合时：自己产出首稿，参考骨架仅作为格式参考
- 首稿必须面向补丁暴露的真实机制，不是 patch-only 匹配
- 不要输出解释，不要输出 diff，不要输出多文件方案

只输出一个 JSON 对象，不要添加解释。

JSON schema:
{
  "summary": "一句话概括首稿策略",
  "checker_name": "可选；如需覆盖当前名字再填写",
  "content": "完整的首稿源码或查询正文"
}