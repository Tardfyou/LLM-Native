# 样本审查记录: vul4c_cwe416_libming_cve20188964

## 基本信息
- 项目: libming
- CWE: CWE-416
- 漏洞类型: use after free
- 预设分析器: csa
- 质量状态: rejected
- 审核人: Codex
- 审核时间: 2026-04-22T12:31:55+08:00

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
- 人工审查信息完整: false
- 允许进入正式实验: false
- 缺失项:
- quality_status 不是 approved

## 人工审查清单
- [ ] 补丁主要描述单一且清晰的漏洞机制
- [ ] 漏洞版本与修复版本配对准确
- [ ] 样本适合静态分析验证
- [ ] 可纳入正式实验

## 备注
- 选择理由: 人工复审淘汰：与 vul4c_cwe416_libming_cve20188806 为重复补丁，且同样存在 CWE 语义不符问题
- 质量备注: 人工复审淘汰：与 vul4c_cwe416_libming_cve20188806 为重复补丁，且同样存在 CWE 语义不符问题 | 候选精炼样本 | materialized_from=Vul4C; target_relpath=util/decompile.c; cve=CVE-2018-8964
