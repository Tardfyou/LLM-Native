# 样本审查记录: git_cwe120_openmpt_cve201917113

## 基本信息
- 项目: openmpt
- CWE: CWE-120
- 漏洞类型: classic buffer overflow
- 预设分析器: csa
- 质量状态: approved
- 审核人: Codex
- 审核时间: 2026-04-22T13:14:08+08:00

## 自动预检
- patch 存在: true
- 漏洞版本存在: true
- 修复版本存在: true
- 证据路径存在: true
- 漏洞/修复版本已区分: true
- 补丁目标文件数: 1
- 已命中补丁目标文件: 1
- 自动预检通过: true

## 自动发现
- 无自动预检问题

## 运行门禁
- 人工审查信息完整: true
- 允许进入正式实验: true
- 缺失项:
- 无

## 人工审查清单
- [ ] 补丁主要描述单一且清晰的漏洞机制
- [ ] 漏洞版本与修复版本配对准确
- [ ] 样本适合静态分析验证
- [ ] 可纳入正式实验

## 备注
- 选择理由: 输出缓冲区长度限制与漏洞根因直接对应，补丁语义集中
- 质量备注: 人工复审通过：补丁集中、漏洞机制可归因、漏洞/修复版本配对正确 | 候选补位样本 | materialized_from=upstream_git; repo_url=https://github.com/OpenMPT/openmpt.git; fix_commit=927688ddab43c2b203569de79407a899e734fabe; parent_commit=47a3b0663202d3e8b3f2f6231052a344cd8134e3; target_relpath=libopenmpt/libopenmpt_modplug.c; cve=CVE-2019-17113
