你正在判断 RAG 检索结果是否符合当前补丁漏洞。

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
1. 检索结果的漏洞类型是否与补丁一致
2. 检索结果的 trigger/guard/barrier 机制是否与补丁匹配
3. 检索结果的 API 和类型是否适用于补丁涉及的代码

符合条件：
- 漏洞类型匹配
- 核心机制（如 buffer guard、relookup、null check）一致
- API 可复用

不符合条件：
- 漏洞类型不匹配
- 机制完全不同
- API 不适用

只输出一个 JSON 对象，不要添加解释。

JSON schema:
{
  "match": true/false,
  "reason": "判断理由",
  "reuse_strategy": "符合时说明如何复用骨架；不符合时说明将自己生成"
}