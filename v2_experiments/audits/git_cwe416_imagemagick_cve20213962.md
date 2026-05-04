# 样本审查记录: git_cwe416_imagemagick_cve20213962

## 基本信息
- 项目: imagemagick
- CWE: CWE-416
- 漏洞类型: use after free
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
- 选择理由: 释放位置后移补丁极小，直接反映 use-after-free 生命周期修正
- 质量备注: 人工复审通过：补丁集中、漏洞机制可归因、漏洞/修复版本配对正确 | 候选补位样本 | materialized_from=upstream_git; repo_url=https://github.com/ImageMagick/ImageMagick.git; fix_commit=82775af03bbb10a0a1d0e15c0156c75673b4525e; parent_commit=7fef3c3ac8ef5397f8a7f318a5316f09a2c999c7; target_relpath=coders/dcm.c; cve=CVE-2021-3962
