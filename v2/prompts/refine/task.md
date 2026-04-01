分析器: {{ANALYZER_ID}}
工作目录: {{WORK_DIR}}
当前工作副本: {{TARGET_PATH}}
基线路径: {{SOURCE_PATH}}
补丁路径: {{PATCH_PATH}}
验证路径: {{VALIDATE_PATH}}

任务：
对当前工作副本执行精炼，使其更贴近补丁真实机制，并在当前 refinement 工作目录内产出可采纳候选。

执行要求：
- 从 `read_artifact` 开始，先理解已有实现。
- 需要查看补丁或项目上下文时，使用 `read_patch`、`read_reference_file`、`list_reference_dir`。
- 本地上下文通常已经足够；`search_knowledge` 仅在真实 API/语义不确定时使用，而且最多一次。
- 如果基线已经足够好，允许不做任何修改直接结束；`refine` 的目标是提升质量，不是强行制造 diff。
- 如果决定精炼，就必须优先提升补丁相关的 guard/barrier/region/capacity/state 语义；单纯换一种 API 名称匹配写法，不算有效精炼。
- 修改时使用 `apply_artifact_patch`。
- 在首次修改落盘前，不要先去编译一个未改动的基线副本。
- `review_artifact` 如果失败，必须根据 findings 直接继续最小修改，而不是重复阅读或重复检索。
- 在本地质量门通过前不要声称完成。

附加上下文：
{{EXTRA_CONTEXT}}
