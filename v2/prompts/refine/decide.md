你正在执行 refine 的 decide 阶段。

目标：分析当前 checker/query 距离补丁体现的漏洞机制还差什么，再决定是结束、补证据、继续修改，还是进入验证。不要把“命中范围缩窄”误判成“更贴近机制”。

{{TASK_PROMPT}}

当前轮次: {{ITERATION}} / {{MAX_ITERATIONS}}

系统说明：
- 当前工作副本在进入 decide 前已经读取完毕
- refine 开始时系统若做过一次基线质量评估，结果会出现在“附加上下文”里
- 你提交 `apply_patch` 后，系统会先基于当前最新工作副本做精确 snippet 替换，再回到 decide；不会立刻进入 validate
- 本阶段可以连续多次 `apply_patch`，必须一直补到你认为这一大轮语义建模已经足够，再输出 `validate`
- 只有当你输出 `validate`，系统才会进入本大轮验证：CSA 依次跑 LSP、审查、编译、功能验证；CodeQL 依次跑审查、analyse
- 一旦进入 validate，本大轮不会再回到 decide；所有 LSP/审查/编译/功能验证/analyse 失败都只交给 repair 循环做最新失败的最小修复
- 本大轮质量门全部通过后，系统会把通过验证的产物作为新基线，再进入下一轮 decide；如果这个新基线已经足够好，应直接 `finish`
- validate 失败后的错误修复会进入独立 repair 阶段，不要在 decide 里为未来可能出现的报错预写修补

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

---

## 可选证据类型

如果你判断当前上下文不足以做出高质量语义修改，只能从下面类型里选需要的语义证据：

| 证据类型 | 说明 | 典型用途 |
|---------|------|---------|
| `patch_fact` | 补丁事实摘要 | 提炼漏洞类型、修复模式、涉及函数 |
| `semantic_slice` | 语义切片 | 查看 patch 涉及文件/函数周边代码 |
| `dataflow_candidate` | 数据流候选 | 判断源到汇、长度/指针/状态传播 |
| `call_chain` | 调用链 | 判断 caller/callee 关系和跨函数传播 |
| `path_guard` | 路径守卫 | 判断补丁新增 guard、边界条件、barrier |
| `allocation_lifecycle` | 分配生命周期 | UAF / double free / leak 场景 |
| `state_transition` | 状态转换 | 锁、引用计数、状态机、标志位场景 |
| `directory_tree` | 目录结构 | 定位文件层级和相关源码位置 |

不要重复请求已经提供过的证据。

---

## decide 阶段的思考方式

先完成下面这些判断，但不要把它们展开成冗长 JSON；`summary` 只写一句短话。

### Step 1: 先判断当前实现是不是已经够好
- 基线质量评估是否已经通过？
- 如果这是上一大轮验证通过后返回的 decide，当前工作副本就是新基线；只要它已经足够好，必须直接 `finish`
- 当前 checker/query 是否已经覆盖 patch 背后体现的核心漏洞机制，而不只是命中补丁里出现过的 API、字符串、变量名？
- 当前实现的核心抽象是否已经能迁移到同类漏洞，而不是只能复用到这一个 patch-site / callee / literal？
- 如果继续修改，只会制造等价改动、无验证收益、或会把语义重新拉回启发式匹配，就应该直接结束
- 如果当前实现质量极低，小修只会继续维持错误抽象时，就要判断是否需要大改
- 当前版本能否做到最基本的：漏洞代码报警，补丁后代码静默

### Step 2: 识别当前 checker/query 的不足
- 它是不是仍主要依赖 API 名称、字符串、`strlen/strnlen`、变量名包含 `len/size/bytes` 之类表面启发式，或者只是把“较宽的名字匹配”换成了“较窄的名字匹配”？如果是，这仍然不算机制建模。
- 它能否检测“补丁背后体现的漏洞类型”，还是只能检测“这一个 patch 里出现过的表面写法”？
- patch 新增的是 guard、capacity 绑定、state 约束、barrier、生命周期修复、数值域修复还是权限/权威重查？当前实现缺了哪一块？
- 这类漏洞的关键机制角色分别是什么，例如触发源、关键中间状态、累计量、对象关系、边界比较、sink、失效条件、静默条件？当前实现漏掉了哪些角色？
- 如果当前已经知道需要同时补多个彼此关联的机制角色，就应成组补齐，不要拆成很多细碎 patch

### Step 2.5: 做机制链检查
- 在决定 `apply_patch` / `validate` / `finish` 之前，先把这类漏洞抽象成一条最小机制链：前置上下文 -> 关键累计量 / 关键状态 / 关键对象关系 -> 更新或传播 -> guard / barrier / widening / ownership / capacity 约束 -> sink 或危险使用 -> patch 引入的修复动作
- 逐项检查当前实现覆盖了哪些角色，还缺哪些角色
- 如果当前实现只抓住链中的一个局部代理角色，或者只能解释“为什么这里会报”却解释不了“为什么表面相似但机制不同的位置不该报”，说明抽象仍然过宽

### Step 3: 决定本轮动作
- `request_evidence`：证据不足，先补最关键的 1-3 类证据
- `apply_patch`：证据足够，但当前轮机制建模还没完成；提交一组成体系的修改，然后继续 decide
- `validate`：只有当机制链已经基本闭合，剩余风险主要是实现细节、API、类型、语法或结构问题时，才进入验证
- `finish`：当前产物已经足够好，或没有安全的高价值改进空间；只有在无需继续精炼时才使用，不要把它当成“先去验证”的替代动作
---
## 修改约束
- `apply_patch` 一律使用精确 snippet 替换
- 每个 edit 都必须基于你刚刚读到的最新工作副本；`old_snippet` 必须能在当前全文中唯一命中
- 一次可提交多个 edits，但它们必须属于同一轮成体系修改，且按顺序都能在更新中的最新文本里继续唯一命中
- 除 `edits` 外，每个字符串字段尽量只写一句短话
- 当你已明确判断“原始 checker 质量较低，现有结构不可保留”时，允许单文件内的大面积重写，但仍必须拆成一组可精确命中的 snippet 替换
- 若已判断原始 checker 质量过低，可连同错误 helper/状态组织一起重构
- 不要把本来应一次完成的一组相关语义修改故意拆成很多微小 patch；如果同一批证据已经足以支撑更完整的机制升级，就应一次做完整
- 不要因为想尽快跑 validate，就只提交象征性的小改动；validate 应发生在语义建模阶段基本收束之后

CSA 额外约束：
- 不要虚构 API，不要引入当前工作副本和已读参考里都未确认签名的 helper
- 如果 patch 体现“显式长度检查 + bounded API”替换旧写法，精炼重点必须是旧机制缺 guard / capacity 证明，而不是维护一份 risky API 黑名单
- 如果当前实现还是 callee-only direct report、变量名启发式、伪状态占位，那说明还没真正贴近补丁机制

CodeQL 额外约束：
- 量词变量必须在同一 `exists()` 中声明
- 不要发明不存在的 API、类型或成员
- 不要用伪支配关系、伪 guard API 替代现有骨架里已有的真实 API
- 不要臆造 `IntegerLiteral`、`IntLiteral` 这类当前 CodeQL C/C++ 库里不存在的类型名；涉及字面量时优先复用仓库内现有成功 `.ql` 用法或改写成更通用的表达式/常量谓词
---
只输出一个 JSON 对象，不要添加解释，不要使用 Markdown 代码块。
字段顺序固定：`action` -> `summary` -> `evidence_types` -> `edits`。

返回格式尽量保持最小：
- 不要新增任何未要求字段
- `summary` 一句短话介绍
- `request_evidence` 时只填 `evidence_types`，`edits` 必须是空数组
- `apply_patch` 时只填 `edits`，`evidence_types` 必须是空数组
- `validate` / `finish` 时 `evidence_types` 和 `edits` 都必须是空数组

JSON schema:
{
  "action": "request_evidence" | "apply_patch" | "validate" | "finish",
  "summary": "一句话说明本轮意图，保持简短",
  "evidence_types": ["当 action 为 request_evidence 时填写 1-3 个证据类型；否则为空数组"],
  "edits": [
    {
      "old_snippet": "当前工作副本中唯一命中的旧片段",
      "new_snippet": "替换后的新片段"
    }
  ]
}
