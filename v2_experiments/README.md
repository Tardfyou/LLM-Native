# v2 Experiments

该目录用于管理 `v2` 的正式实验资产，建议流程如下：

1. 在 `manifests/samples.csv` 中录入样本。
   `Vul4C` 主体样本可参考 `manifests/vul4c_seed_selection.csv`，补位样本可参考 `manifests/supplement_git_selection.csv`。
   对应物化脚本分别为 `v2/scripts/materialize_vul4c_samples.py` 和 `v2/scripts/materialize_git_commit_samples.py`。
2. 先执行 `experiment audit` 生成样本审查记录。
3. 逐样本补全 `quality_status=approved`、`reviewer`、`reviewed_at`、`selection_reason`。
4. 仅当自动预检通过且人工审查信息完整时，样本才允许进入正式实验。
5. 执行 `experiment run --all` 批量跑实验。
6. 在 `tables/` 中查看自动汇总的 CSV 与 Markdown 表。

当前实验设计默认约定：
- 仅启用 20 个正式实验样本参与生成实验，覆盖 10 类 CWE，每类保留 2 个高质量样本。
- 标记 `run_refine=true` 的 10 个样本参与证据收集与精炼实验，覆盖 10 类 CWE，每类保留 1 个最佳样本。
- 标记 `run_backend_compare=true` 的 10 个精炼样本同时参与 `CSA/CodeQL` 后端对比。
