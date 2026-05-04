分析器: {{ANALYZER_ID}}
分析器名称: {{ANALYZER_NAME}}
工作目录: {{WORK_DIR}}
补丁路径: {{PATCH_PATH}}
验证路径: {{VALIDATE_PATH}}
最大模型轮次: {{MAX_ITERATIONS}}

任务：在固定工作流内，为当前分析器产出一个稳定的 detector/query。

生成策略硬约束：
- 先用补丁文件、补丁函数、补丁附近 AST/调用/赋值/释放事实建立最小 trigger。
- 首稿先命中 patch-local 最小锚点，再考虑 guard/barrier、支配关系或额外数据流过滤。
- generate 首稿允许更贴补丁、更特化；只要仍锚定 patch 文件/函数/语句附近，命中偏多优于 0 hit。
- 函数锚点必须优先服从 patch hunk 和验证源码里的真实定义/修改位置；字段名、调用链或上层流程函数只能作为辅证，不能替代真正被改动的目标函数。
- 对删除危险调用/释放/写入的补丁，先匹配漏洞版中被删除的操作本身，再检查同函数内同变量的前后 release/use/reassign/guard；不要默认跳到调用者或跨过程所有权。
- 对新增 guard/barrier 的补丁，先匹配原本会到达的 source/sink；首稿不强制同步表达修复版排除条件。
- 变量来源既要考虑赋值，也要考虑声明初始化；写入既要考虑 `=`，也要考虑 `|=`、`+=` 等复合赋值。
- 不要让复杂数据流、支配关系、RAG 骨架或泛化要求把 patch-local trigger 过滤为空。

分析器硬约束：
{{ANALYZER_POLICY}}
