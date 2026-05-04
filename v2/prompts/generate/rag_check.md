你正在判断 RAG 检索结果是否符合当前补丁所体现的漏洞类型。

补丁全文：
```diff
{{PATCH_TEXT}}
```

`analyze_patch` 输出：
```text
{{ANALYSIS_TEXT}}
```

RAG 检索结果：
```text
{{KNOWLEDGE_TEXT}}
```

判断标准：
1. 漏洞类型是否一致。
2. 补丁形态是否一致，例如“新增 guard”和“删除危险释放”不是同一类骨架。
3. trigger 和 fixed 静默机制是否一致；不能只因为 CWE 相近就复用。
4. API、AST 类型、回调/查询结构是否适用于当前补丁。

符合条件：
- 漏洞类型、补丁形态、trigger/barrier 机制都匹配。
- 骨架能帮助建立 patch-local trigger，不会强加补丁和源码中看不到的跨过程或 guard 条件。

不符合条件：
- 只有漏洞大类相近，但补丁形态不同。
- 骨架要求当前补丁没有的 source/sink/guard/dataflow。
- 骨架会把 patch-local trigger 过滤为空。

只输出一个 JSON 对象，不要添加解释。

JSON schema:
{
  "match": true/false,
  "reason": "判断理由",
  "reuse_strategy": "符合时说明如何复用骨架；不符合时说明将自己生成"
}
