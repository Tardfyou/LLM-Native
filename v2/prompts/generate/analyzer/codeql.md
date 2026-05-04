CodeQL 目标：生成稳定、可解析、可执行、补丁差分语义明确的 `.ql` 查询。

核心目标：
- 查询应命中漏洞版本中 patch 涉及文件/函数/语句附近的真实缺陷模式。
- 首稿先保证 patch-local trigger；复杂数据流、支配关系、调用链只能在 trigger 已成立后补充过滤。
- generate 首稿允许更贴补丁、更特化；只要仍锚定 patch-local 事实，命中偏多优于 0 hit。
- 不要写成项目级宽泛模式；收窄条件必须来自 patch 或验证源码中的可观察事实。

建模优先级：
1. 识别补丁形态：新增 guard、删除危险操作、替换 API、状态/所有权变化、范围/长度变化、其他。
2. 建立最小 trigger：changed file/function、被改表达式、涉及变量/字段/API、同函数内前后 release/use/reassign/null/guard。
3. 对删除危险操作的补丁，漏洞版 trigger 优先是被删除操作本身；fixed 静默通常来自该操作不存在，不要强行构造 `hasPatchGuard`。
4. 对新增 guard/barrier 的补丁，先匹配原始 source/sink；首稿不强制同步写 `not hasGuard(...)` / `not hasBarrier(...)`。
5. 对替换 API 的补丁，先匹配旧 API 和关键参数角色，再用 safe API 或旧 API 消失表达修复版静默。
6. 如果 patch-local 真锚点是解析/读入/赋值触点，而漏洞版源码里不再保留结构化“缺失 guard”形状，可以直接报告该触点；不要为了 fixed 静默把查询拧成 0 命中。
7. 变量来源既要覆盖 `AssignExpr/Assignment`，也要覆盖声明初始化；识别写入/累积既要覆盖 `=`，也要覆盖 `|=`、`+=` 等复合赋值，不要把 patch-local 真实写入漏成 0 命中。

删除释放/销毁类补丁的特别规则：
- 先在 changed function 内按行号顺序找同一资源的 earlier/later release/use/reassign/null。
- 如果被删除调用可能是第二次 release，要找它之前的同资源 release；不要只找后续 release。
- 不要要求失败 callee 接收该资源，除非调用参数里确实出现同一资源。
- 识别释放实参时不要要求 `call.getArgument(i)` 本身就是 `VariableAccess`，应从参数表达式子树抽取变量访问。

CodeQL API 约束：
- 首稿必须先经过 `generate_codeql_query` 再落盘。
- 查询文件顶部必须有完整元数据块，至少包含 `@name`、`@description`、`@kind problem`、`@problem.severity`、`@precision`、`@id`。
- `@name` 必须与 checker/query 名称一致或高度对应；`@id` 必须唯一稳定，推荐 kebab-case：`cpp/custom/<checker-name-kebab>`，不要使用 `cpp/custom/buffer_overflow`、`cpp/custom/query` 这类泛 ID。
- 不要臆造不存在的 CodeQL API、类型、成员方法或 AST/DataFlow 名称。
- 量词变量必须在同一 `exists()` 参数列表中声明；不要跨兄弟量词引用局部变量。
- `getEnclosingFunction()` 只用于支持该 API 的具体 AST 类型。
- 不要把 `getParent*()` 当成通用包含关系证明；优先从 `IfStmt.getCondition()`、`ForStmt.getControllingExpr()`、`ArrayExpr.getArrayOffset()`、`BinaryOperation.getAnOperand()` 等结构入口向下递归。
- 不要用 `toString()` 作为主要语义判断；变量一致性优先用 `VariableAccess.getTarget()`，字段一致性用 `FieldAccess.getTarget()`。
- `FieldAccess` 没有 `getField()`；字段声明统一用 `FieldAccess.getTarget()`。
- `FunctionCall` / `Call` 不要假设存在 `getNumArgument()`；实参数量固定或由补丁可知时，直接访问对应槽位如 `getArgument(2)`，或先用具体可用 API 验证后再写。
- 对 `ThrowReaderException`、`free`、`DestroyImage`、`DestroyImageList` 这类 patch-local 危险调用，优先直接匹配调用名和关键实参角色，不要先引入不确定的高阶调用 API。
- `stmt.getAChild*() = expr`、`loop.getAChild*() = expr` 只能作为辅助，不要作为唯一硬条件。

推荐分层：
```ql
predicate inPatchScope(Element e) { ... }
predicate isPatchLocalTrigger(Element anchor) { ... }
predicate fixedHasBarrier(Element anchor) { ... } // 仅新增 guard/barrier 补丁需要

from Element anchor
where inPatchScope(anchor)
  and isPatchLocalTrigger(anchor)
  and not fixedHasBarrier(anchor)
select anchor, "..."
```

质量检查：
- 先确认 patch 文件/函数内 trigger 候选能匹配，再加过滤。
- `select` 的每条结果都应能解释为 patch 修复前存在、修复后消失或被 barrier 阻断。
- 若 patch 新增的是对某些字段/API 的后置校验，而漏洞版只稳定暴露这些字段/API 的读入或消费触点，优先固定这些触点，再决定是否额外表达 barrier。
- 0 命中通常说明 trigger 过窄或方向反了，优先检查行号顺序、删除操作是否被误当第一次事件、以及是否强加了源码中没有的关系。

验证流程：`review_artifact -> codeql_analyze`
