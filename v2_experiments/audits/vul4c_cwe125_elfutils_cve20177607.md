# 样本审查记录: vul4c_cwe125_elfutils_cve20177607

## 基本信息
- 项目: elfutils
- CWE: CWE-125
- 漏洞类型: out-of-bounds read
- 预设分析器: csa
- 质量状态: approved
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
- 选择理由: 读取边界判断补丁简单清晰
- 质量备注: 移出正式实验样本：目标文件使用 GCC nested function，Clang/CSA 无法真实解析 | materialized_from=Vul4C; target_relpath=src/readelf.c; cve=CVE-2017-7607
