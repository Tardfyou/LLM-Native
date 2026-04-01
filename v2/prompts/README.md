# Prompt Layout

`v2` 现已改为 manifest 驱动的分层提示词体系。运行时入口在 `v2/src/prompts/repository.py`，所有正式使用的 prompt 都必须先在 `manifest.yaml` 注册，再由代码通过 `prompt_id` 访问。

当前目录结构：

- `manifest.yaml`
- `generate/`
- `refine/`
- `orchestrator/`
- `analysis/`

主要 prompt id：

- `generate.agent.system`
- `generate.agent.task`
- `generate.agent.plan`
- `generate.agent.draft`
- `generate.agent.repair`
- `generate.agent.analyzer.csa`
- `generate.agent.analyzer.codeql`
- `generate.agent.reference.csa`
- `generate.agent.reference.codeql`
- `refine.agent.system`
- `refine.agent.task`
- `refine.agent.decide`
- `orchestrator.analyzer_selection`
- `analysis.patch`

约束：

- `generate` 与 `refine` 已拆成两个独立系统；`refine` 只消费 `generate` 落盘后的结果契约，不再复用 generate prompt。
- `generate` 运行时采用 LangGraph 控制流，固定顺序为 `analyze_patch -> search_knowledge -> draft/materialize -> validate -> apply_patch repair`。
- CSA prompt 必须显式对齐 LLVM/Clang 18 插件式 checker 约束，包含正确的 `CheckerRegistry` 头文件与 `CLANG_VERSION_STRING` 版本导出。
- 新增 prompt 时先设计目录层级，再登记到 `manifest.yaml`，不要继续在 Python 中内联模型指令。
- 未被主流程引用的旧 prompt 应直接删除，避免“文档存在但运行不用”的漂移。
