"""
Report Triage System
报告分类系统 - 参考KNighter的check_report实现

使用LLM来判断分析报告是TP(真阳性)还是FP(假阳性)
"""

import logging
from typing import Dict, Any, Optional
from pathlib import Path

# 使用绝对导入（PYTHONPATH 包含 src/）
from generator.models.refinement_models import TriageResult, ReportData
from model.llm_client import LLMClient

logger = logging.getLogger(__name__)


class ReportTriage:
    """
    报告分类器

    使用LLM辅助判断静态分析报告是否为真实的漏洞
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        """
        初始化报告分类器

        Args:
            llm_client: LLM客户端实例（可选）
        """
        self.llm_client = llm_client
        self._default_prompt_template = self._load_default_template()

    def _load_default_template(self) -> str:
        """加载默认的分类提示词模板"""
        return """You are a static analysis expert. Your task is to determine whether a reported bug is a true positive (actual bug) or a false positive (not a bug).

# Vulnerability Pattern to Detect:
{{pattern}}

# Bug Report Content:
```{{report_content}}
```

# Analysis:
Please analyze this report and determine:
1. Does this report actually demonstrate the vulnerability pattern we're looking for?
2. Is the code behavior shown actually buggy, or is this a false positive?

Your response should be formatted as follows:
- **Assessment**: [True Positive / False Positive]
- **Reasoning**: [Detailed explanation of your analysis]

If the report does NOT demonstrate the bug pattern (i.e., it's a false positive), start your reasoning with "NotABug:".

Please provide your analysis below:
"""

    def triage_report(
        self,
        report_data: ReportData,
        pattern: str,
        patch: str = "",
        temperature: float = 0.01,  # 使用低温度以获得更确定的结果
        use_llm: bool = True
    ) -> TriageResult:
        """
        对报告进行分类

        Args:
            report_data: 报告数据
            pattern: 漏洞模式
            patch: 可选的补丁内容
            temperature: LLM温度参数
            use_llm: 是否使用LLM（如果为False，使用简单规则）

        Returns:
            分类结果
        """
        if not use_llm:
            # 使用简单的基于规则的分类
            return self._rule_based_triage(report_data, pattern)

        # 使用LLM分类
        return self._llm_based_triage(report_data, pattern, patch, temperature)

    def _llm_based_triage(
        self,
        report_data: ReportData,
        pattern: str,
        patch: str,
        temperature: float
    ) -> TriageResult:
        """基于LLM的分类"""
        if not self.llm_client:
            logger.warning("No LLM client available, falling back to rule-based triage")
            return self._rule_based_triage(report_data, pattern)

        try:
            # 构建提示词
            prompt = self._default_prompt_template.replace("{{pattern}}", pattern)
            prompt = prompt.replace("{{report_content}}", report_data.report_content)

            if patch:
                patch_section = f"\n# Original Patch (for reference):\n```\n{patch}\n```\n"
                prompt = prompt.replace("{{patch}}", patch_section)
            else:
                prompt = prompt.replace("{{patch}}", "")

            # 调用LLM - 使用配置中的 max_tokens
            max_tokens = getattr(self.llm_client.config, 'max_tokens', 10000)
            response = self.llm_client.generate(
                prompt,
                temperature=temperature,
                max_tokens=max_tokens
            )

            # 解析响应
            is_fp = self._parse_is_fp(response)
            reasoning = self._extract_reasoning(response)
            confidence = self._estimate_confidence(response)

            return TriageResult(
                is_fp=is_fp,
                reasoning=reasoning,
                confidence=confidence
            )

        except Exception as e:
            logger.error(f"Error during LLM-based triage: {e}")
            return self._rule_based_triage(report_data, pattern)

    def _rule_based_triage(
        self,
        report_data: ReportData,
        pattern: str
    ) -> TriageResult:
        """
        基于规则的简单分类

        使用关键词匹配来判断
        """
        content = report_data.report_content.lower()
        pattern_lower = pattern.lower()

        # 提取pattern中的关键词
        pattern_keywords = self._extract_keywords(pattern_lower)

        # 计算匹配度
        match_count = sum(1 for keyword in pattern_keywords if keyword in content)

        # 简单规则：如果匹配度太低，可能是FP
        is_fp = match_count < len(pattern_keywords) / 3

        reasoning = f"Rule-based classification: {match_count}/{len(pattern_keywords)} keywords matched. "
        reasoning += "Likely false positive due to low pattern match." if is_fp else "Likely true positive based on keyword matching."

        confidence = 0.5  # 规则方法置信度较低

        return TriageResult(
            is_fp=is_fp,
            reasoning=reasoning,
            confidence=confidence
        )

    def _parse_is_fp(self, response: str) -> bool:
        """从LLM响应中解析是否为FP"""
        response_lower = response.lower()

        # 检查明确的标记
        if "notabug:" in response_lower:
            return True

        # 检查assessment部分
        if "**assessment**:" in response_lower:
            assessment_part = response_lower.split("**assessment**:")[1].split("\n")[0]
            if "false positive" in assessment_part or "not a bug" in assessment_part:
                return True
            elif "true positive" in assessment_part or "actual bug" in assessment_part:
                return False

        # 默认保守策略：如果不确定，认为是TP
        return False

    def _extract_reasoning(self, response: str) -> str:
        """提取推理过程"""
        if "**reasoning**:" in response.lower():
            parts = response.lower().split("**reasoning**:")
            if len(parts) > 1:
                reasoning = parts[1].strip()
                # 移除可能的后续标记
                for marker in ["**assessment**:", "**confidence**:"]:
                    if marker in reasoning:
                        reasoning = reasoning.split(marker)[0].strip()
                return reasoning

        return response.strip()

    def _estimate_confidence(self, response: str) -> float:
        """估算置信度"""
        response_lower = response.lower()

        # 明确标记
        if "definitely" in response_lower or "certainly" in response_lower:
            return 0.9
        elif "likely" in response_lower or "probably" in response_lower:
            return 0.7
        elif "possibly" in response_lower or "maybe" in response_lower:
            return 0.5
        elif "uncertain" in response_lower or "not sure" in response_lower:
            return 0.3

        # 检查分析长度（更长的分析通常更详细）
        if len(response) > 500:
            return 0.7
        elif len(response) > 200:
            return 0.5

        return 0.4

    def _extract_keywords(self, text: str) -> list:
        """从文本中提取关键词"""
        # 简单实现：移除常见词，保留有意义的词
        stopwords = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by"}
        words = text.split()
        keywords = [w for w in words if len(w) > 3 and w not in stopwords]
        return list(set(keywords))

    def batch_triage(
        self,
        reports: list[ReportData],
        pattern: str,
        patch: str = "",
        temperature: float = 0.01
    ) -> list[TriageResult]:
        """
        批量分类报告

        Args:
            reports: 报告列表
            pattern: 漏洞模式
            patch: 可选的补丁
            temperature: LLM温度

        Returns:
            分类结果列表
        """
        results = []
        for i, report in enumerate(reports):
            logger.info(f"Triaging report {i+1}/{len(reports)}: {report.report_id}")
            result = self.triage_report(report, pattern, patch, temperature)
            results.append(result)

        # 统计
        fp_count = sum(1 for r in results if r.is_fp)
        tp_count = len(results) - fp_count

        logger.info(f"Triage complete: {tp_count} TPs, {fp_count} FPs")

        return results

    def set_llm_client(self, client: LLMClient):
        """设置LLM客户端"""
        self.llm_client = client

    def get_template_stats(self) -> Dict[str, Any]:
        """获取模板统计信息"""
        return {
            "has_default_template": bool(self._default_prompt_template),
            "template_length": len(self._default_prompt_template),
            "has_llm_client": self.llm_client is not None
        }
