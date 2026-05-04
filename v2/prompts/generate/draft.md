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
- RAG 符合时：复用其稳定 API 和组织方式，但不能保留不符合当前补丁形态的 trigger/guard。
- RAG 不符合时：自己产出首稿，参考骨架仅作为格式参考。
- 首稿先实现最小 patch-local trigger，再考虑泛化。
- 对删除危险操作的补丁：漏洞版 trigger 是被删除操作；修复版静默通常来自操作消失。先查同函数内同资源的前后 release/use/reassign/null/guard，局部事实不足再考虑跨过程。
- 对新增 guard/barrier 的补丁：trigger 不应依赖 guard；先匹配原始 source/sink，再用 `not hasGuard` 或等价条件过滤。
- 对替换安全 API 的补丁：trigger 优先匹配旧 API 与相同角色参数，fixed 静默来自旧 API 消失或安全 API 出现。
- 不要要求 callee 接收某个资源，除非补丁或源码参数明确显示该资源传给 callee。
- 不要把多层支配、全局数据流、调用链作为首稿硬条件；它们只能在 patch-local trigger 已经成立后补充过滤。
- 不要输出解释，不要输出 diff，不要输出多文件方案。

务必只输出一个可解析 JSON 对象，不要添加任何无关解释。
- 不要输出 Markdown 代码块，不要在 JSON 前后添加说明文字、思考过程、编号或注释。
- `summary` 和 `checker_name` 必须是单个 JSON 字符串；`content` 必须是单个完整字符串字段，直接承载完整源码/查询正文。
- 若无法完成，也必须返回合法 JSON；不要因为解释、截断或额外段落导致 JSON 解析失败。

JSON schema:
{
  "summary": "一句话概括首稿策略",
  "checker_name": "可选；如需覆盖当前名字再填写",
  "content": "完整的首稿源码或查询正文"
}
