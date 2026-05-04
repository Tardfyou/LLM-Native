分析器: {{ANALYZER_ID}}
工作目录: {{WORK_DIR}}
当前工作副本: {{TARGET_PATH}}
基线路径: {{SOURCE_PATH}}
补丁路径: {{PATCH_PATH}}
验证路径: {{VALIDATE_PATH}}
证据源码目录: {{EVIDENCE_DIR}}

核心任务：
对当前工作代码副本执行精炼，在当前 refinement 工作目录内产出可采纳候选。基本要求：命中补丁前漏洞，补丁后尽量静默，对背后漏洞建模充分语义。

执行要求：
- 从 `read_artifact` 开始，先理解已有实现。
- 需要查看补丁或项目上下文时，使用 `read_patch`、`read_reference_file`、`list_reference_dir`。
- decide 阶段先判断当前基线是否已经足够好；如果质量评估已过关且没有明确高价值改进空间，可以直接结束。
- decide 阶段负责补丁/现有实现分析、证据选择和语义 patch；它可以连续多次打语义 patch，直到你明确决定进入 validate。validate 失败后的局部修复由独立 repair 阶段处理。
- 一个大轮次内的顺序固定为：decide 语义补强循环 -> validate/repair 修复验证循环 -> 下一大轮 decide；进入 validate 后本大轮不会再回到 decide。
- CSA 的验证门是 LSP 和审查先行，然后编译和功能验证；CodeQL 的验证门是审查和 analyse。任何验证失败都只由 repair 修最新失败。
- 如果基线已经足够好，允许不做任何修改直接结束；`refine` 的目标是提升质量，不是强行制造 diff。
- 每次大轮验证全部通过后，系统会把当前产物作为新的基线重新进入 decide；如果智能体判断这个新基线已经够好，必须直接结束。
- 不要把 checker/query 缩到只命中当前 patch 位置或几个补丁相关名字；优先建模触发条件、传播链、容量/边界关系、状态转换、guard/barrier、生命周期、数值域约束。
- 名称、API、字符串、变量名只能辅助定位，不能成为 refine 后的核心抽象。
- 如果决定精炼，就优先补 guard/barrier/region/capacity/state 语义；单纯换一种 API 名称匹配写法不算有效精炼。
- 同一轮证据已足够时，应合并成一组成体系改动，不要每次只改一两个局部条件。
- 进入 validate 的前提是：这一轮语义建模已基本完成，剩余风险主要是 API、类型、语法或结构问题。
- 修改时使用 `apply_artifact_patch`，但提交内容应为精确 snippet 替换，不要再手写统一 diff。
- 一旦某次 patch 已成功落盘，后续 patch 必须重新以当前工作副本为基线；不要继续按落盘前的旧文件结构生成 diff。
- decide 阶段提交给 `apply_artifact_patch` 的 edits 必须是可唯一命中的 `old_snippet` / `new_snippet`；不要再依赖多 hunk patch 上下文。
- 在首次修改落盘前，不要先去编译一个未改动的基线副本。
- `review_artifact` 如果失败，必须根据 findings 直接继续修改，而不是重复阅读或重复检索。
- 在本地质量门通过前不要声称完成。
