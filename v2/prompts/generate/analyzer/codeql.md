CodeQL 目标：生成稳定、可解析、可执行的 .ql 查询

约束：
- 首稿必须先经过 generate_codeql_query 再落盘
- 检索骨架质量高时，保留 query skeleton、核心谓词分层和 trigger/barrier 关系
- 沿用骨架里的 exact CodeQL API 名称和类型名，不要"翻译"成相似名字
- 不要臆造不存在的 CodeQL API、类型、成员方法或 AST/DataFlow 名称
- 量词变量必须在同一 exists() 参数列表中声明
- 不要引用外层兄弟量词里的局部变量

禁止改写：
- SizeofExprOperator -> sizeof(...)
- GuardCondition.ensuresLt -> ComparisonOperation
- getTarget() -> 其他伪 API
- bbDominates -> 自定义支配关系

验证流程：review_artifact -> codeql_analyze
修复时只做最小增量修改，不整体改写