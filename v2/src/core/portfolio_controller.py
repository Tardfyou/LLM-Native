"""
PATCHWEAVER 组合决策器

根据检测器生成结果、语义验证和证据覆盖，
在多个分析器产物中选出首选检测器，并给出组合使用建议。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .analyzer_base import AnalyzerDescriptor, AnalyzerResult, normalize_analyzer_id


@dataclass
class PortfolioCandidate:
    """单个分析器候选项。"""

    analyzer_id: str
    display_name: str
    score: float
    generation_success: bool
    semantic_success: bool
    accepted: bool = False
    evidence_records: int = 0
    missing_evidence: int = 0
    evidence_degraded: bool = False
    semantic_slice_records: int = 0
    verifier_backed_slices: int = 0
    slice_coverage: str = ""
    output_path: str = ""
    checker_name: str = ""
    pattern_fit: bool = False
    planner_recommended: bool = False
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer_id": self.analyzer_id,
            "display_name": self.display_name,
            "score": self.score,
            "generation_success": self.generation_success,
            "semantic_success": self.semantic_success,
            "accepted": self.accepted,
            "evidence_records": self.evidence_records,
            "missing_evidence": self.missing_evidence,
            "evidence_degraded": self.evidence_degraded,
            "semantic_slice_records": self.semantic_slice_records,
            "verifier_backed_slices": self.verifier_backed_slices,
            "slice_coverage": self.slice_coverage,
            "output_path": self.output_path,
            "checker_name": self.checker_name,
            "pattern_fit": self.pattern_fit,
            "planner_recommended": self.planner_recommended,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "strengths": list(self.strengths),
        }


@dataclass
class PortfolioDecision:
    """组合决策结果。"""

    preferred_analyzer: str = ""
    preferred_score: float = 0.0
    preferred_reason: str = ""
    preferred_checker_name: str = ""
    preferred_output_path: str = ""
    confidence: str = "low"
    recommended_bundle: List[str] = field(default_factory=list)
    complementary_usage: List[str] = field(default_factory=list)
    candidates: List[PortfolioCandidate] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "preferred_analyzer": self.preferred_analyzer,
            "preferred_score": self.preferred_score,
            "preferred_reason": self.preferred_reason,
            "preferred_checker_name": self.preferred_checker_name,
            "preferred_output_path": self.preferred_output_path,
            "confidence": self.confidence,
            "recommended_bundle": list(self.recommended_bundle),
            "complementary_usage": list(self.complementary_usage),
            "summary": self.summary,
            "candidates": [item.to_dict() for item in self.candidates],
        }


class PortfolioController:
    """解释型规则驱动的组合决策器。"""

    def __init__(
        self,
        descriptors: Iterable[AnalyzerDescriptor],
    ):
        self._descriptors = {
            normalize_analyzer_id(item.id): item
            for item in descriptors
            if item.id
        }

    def resolve(
        self,
        analyzer_results: Dict[str, AnalyzerResult],
        selected_analyzers: Optional[List[str]] = None,
        shared_analysis: Optional[Dict[str, Any]] = None,
    ) -> PortfolioDecision:
        ordered = [
            normalize_analyzer_id(item)
            for item in (selected_analyzers or analyzer_results.keys())
            if normalize_analyzer_id(item)
        ]
        seen = set()
        ordered_ids: List[str] = []
        for analyzer_id in ordered + list(analyzer_results.keys()):
            if analyzer_id and analyzer_id not in seen:
                ordered_ids.append(analyzer_id)
                seen.add(analyzer_id)

        primary_pattern = self._extract_primary_pattern(shared_analysis or {})
        planner_recommended = self._extract_planner_recommended(shared_analysis or {})

        candidates = [
            self._build_candidate(
                analyzer_id=analyzer_id,
                analyzer_result=analyzer_results.get(analyzer_id),
                primary_pattern=primary_pattern,
                planner_recommended=planner_recommended,
            )
            for analyzer_id in ordered_ids
            if analyzer_results.get(analyzer_id) is not None
        ]
        candidates.sort(
            key=lambda item: (
                item.score,
                item.semantic_success,
                item.generation_success,
            ),
            reverse=True,
        )

        preferred = next((item for item in candidates if item.accepted), None)
        decision = PortfolioDecision(
            candidates=candidates,
            preferred_analyzer=preferred.analyzer_id if preferred else "",
            preferred_score=preferred.score if preferred else 0.0,
            preferred_reason=self._build_preferred_reason(preferred),
            preferred_checker_name=preferred.checker_name if preferred else "",
            preferred_output_path=preferred.output_path if preferred else "",
            confidence=self._infer_confidence(preferred),
            recommended_bundle=self._build_bundle(candidates),
            complementary_usage=self._build_usage_guidance(candidates),
        )
        decision.summary = self._build_summary(decision, primary_pattern)
        return decision

    def _build_candidate(
        self,
        analyzer_id: str,
        analyzer_result: Optional[AnalyzerResult],
        primary_pattern: str,
        planner_recommended: List[str],
    ) -> PortfolioCandidate:
        descriptor = self._descriptors.get(analyzer_id)
        display_name = descriptor.name if descriptor else analyzer_id
        metadata = analyzer_result.metadata if analyzer_result else {}
        validation_result = getattr(analyzer_result, "validation_result", None)

        generation_success = bool(getattr(analyzer_result, "success", False))
        validation_success = bool(getattr(validation_result, "success", False))
        semantic_has_hits = self._semantic_validation_has_hits(validation_result)
        semantic_success = validation_success and semantic_has_hits
        feedback_failure_modes = self._feedback_failure_modes(metadata)
        validation_requested = bool((metadata or {}).get("validation_requested", False))
        accepted = generation_success if not validation_requested else (
            generation_success
            and semantic_success
        )
        evidence_records = int(metadata.get("evidence_records", 0) or 0)
        missing_evidence = len(metadata.get("missing_evidence", []) or [])
        evidence_degraded = bool(metadata.get("evidence_degraded", False) or missing_evidence)
        semantic_slice_records = int(metadata.get("semantic_slice_records", 0) or 0)
        verifier_backed_slices = int(metadata.get("verifier_backed_slices", 0) or 0)
        slice_coverage = str(metadata.get("slice_coverage", "") or "").strip()
        pattern_fit = bool(primary_pattern and descriptor and primary_pattern in (descriptor.best_for or []))
        planner_hit = analyzer_id in planner_recommended

        score = 0.0
        reasons: List[str] = []
        warnings: List[str] = []

        if generation_success:
            score += 40.0
            reasons.append("生成成功")
        else:
            score -= 100.0
            warnings.append("生成失败")

        if semantic_success:
            score += 12.0
            reasons.append("功能验证通过")
            if semantic_has_hits:
                score += 10.0
                reasons.append("命中验证目标")
            else:
                score -= 6.0
                warnings.append("功能验证通过但未命中漏洞目标")
        elif validation_result is not None:
            score -= 16.0
            warnings.append("语义验证未通过")
        elif validation_requested:
            score -= 20.0
            warnings.append("缺少语义验证结果")

        if pattern_fit:
            score += 12.0
            reasons.append(f"适配主模式 {primary_pattern}")

        if planner_hit:
            score += 8.0
            reasons.append("命中证据规划推荐")

        if evidence_records > 0:
            score += min(12.0, evidence_records * 0.8)
            reasons.append(f"收集证据 {evidence_records} 条")

        if semantic_slice_records > 0:
            score += min(10.0, semantic_slice_records * 2.0)
            reasons.append(f"语义切片 {semantic_slice_records} 条")

        if verifier_backed_slices > 0:
            score += min(8.0, verifier_backed_slices * 2.0)
            reasons.append(f"验证器支撑切片 {verifier_backed_slices} 条")

        if missing_evidence > 0:
            score -= min(30.0, missing_evidence * 6.0)
            warnings.append(f"缺失计划证据 {missing_evidence} 项")

        if evidence_degraded:
            score -= 4.0
            warnings.append("证据覆盖不足，结果降级")

        if slice_coverage == "partial":
            score -= 8.0
            warnings.append("语义切片覆盖仅为 partial")
        elif slice_coverage == "missing":
            score -= 18.0
            warnings.append("缺少可用语义切片")

        if getattr(analyzer_result, "output_path", ""):
            score += 3.0

        return PortfolioCandidate(
            analyzer_id=analyzer_id,
            display_name=display_name,
            score=round(score, 2),
            generation_success=generation_success,
            semantic_success=semantic_success,
            accepted=accepted,
            evidence_records=evidence_records,
            missing_evidence=missing_evidence,
            evidence_degraded=evidence_degraded,
            semantic_slice_records=semantic_slice_records,
            verifier_backed_slices=verifier_backed_slices,
            slice_coverage=slice_coverage,
            output_path=getattr(analyzer_result, "output_path", "") or "",
            checker_name=self._display_checker_name(analyzer_result),
            pattern_fit=pattern_fit,
            planner_recommended=planner_hit,
            reasons=reasons,
            warnings=warnings,
            strengths=list(descriptor.strengths if descriptor else []),
        )

    def _display_checker_name(self, analyzer_result: Optional[AnalyzerResult]) -> str:
        if analyzer_result is None:
            return ""
        raw_name = str(getattr(analyzer_result, "checker_name", "") or "").strip()
        metadata = getattr(analyzer_result, "metadata", {}) or {}
        synthesis_input = metadata.get("synthesis_input", {}) if isinstance(metadata.get("synthesis_input"), dict) else {}
        detector_hint = str(synthesis_input.get("detector_name_hint", "") or "").strip()
        if raw_name and raw_name.lower() not in {"query", "detector", "checker", "custom"}:
            return raw_name
        return detector_hint or raw_name

    def _semantic_validation_has_hits(self, validation_result: Optional[Any]) -> bool:
        if validation_result is None or not bool(getattr(validation_result, "success", False)):
            return False
        return bool(getattr(validation_result, "diagnostics", []) or [])

    def _feedback_failure_modes(self, metadata: Optional[Dict[str, Any]]) -> List[str]:
        bundle = (metadata or {}).get("validation_feedback_bundle", {}) or {}
        modes: List[str] = []
        for item in (bundle.get("records", []) or []):
            if not isinstance(item, dict):
                continue
            payload = item.get("semantic_payload", {}) or {}
            mode = str(payload.get("failure_mode", "") or "").strip()
            if mode and mode not in modes:
                modes.append(mode)
        return modes

    def _extract_primary_pattern(self, shared_analysis: Dict[str, Any]) -> str:
        patchweaver = (shared_analysis.get("patchweaver", {}) or {})
        graph = patchweaver.get("mechanism_graph", {}) or {}
        patterns = graph.get("primary_patterns", []) or []
        if patterns:
            return str(patterns[0]).strip().lower()

        strategy = shared_analysis.get("detection_strategy", {}) or {}
        primary = strategy.get("primary_pattern", "")
        if primary:
            return str(primary).strip().lower()

        vulnerability_patterns = shared_analysis.get("vulnerability_patterns", []) or []
        if vulnerability_patterns and isinstance(vulnerability_patterns[0], dict):
            return str(vulnerability_patterns[0].get("type", "")).strip().lower()
        return ""

    def _extract_planner_recommended(self, shared_analysis: Dict[str, Any]) -> List[str]:
        patchweaver = (shared_analysis.get("patchweaver", {}) or {})
        evidence_plan = patchweaver.get("evidence_plan", {}) or {}
        return [
            normalize_analyzer_id(item)
            for item in (evidence_plan.get("recommended_analyzers", []) or [])
            if normalize_analyzer_id(item)
        ]

    def _build_preferred_reason(self, preferred: Optional[PortfolioCandidate]) -> str:
        if not preferred:
            return "没有检测器通过功能验证"
        if preferred.accepted:
            if preferred.missing_evidence > 0:
                return "通过功能验证，但存在证据缺失降级，且综合得分最高"
            return "通过功能验证，且综合得分最高"
        return "未获得成功候选"

    def _infer_confidence(self, preferred: Optional[PortfolioCandidate]) -> str:
        if not preferred:
            return "low"
        if preferred.accepted:
            if preferred.missing_evidence > 0 or preferred.slice_coverage in {"missing", ""}:
                return "medium"
            if preferred.slice_coverage == "full" and preferred.verifier_backed_slices > 0:
                return "high"
            return "medium"
        return "low"

    def _build_bundle(self, candidates: List[PortfolioCandidate]) -> List[str]:
        bundle = [
            item.analyzer_id
            for item in candidates
            if item.accepted
        ]
        return bundle

    def _build_usage_guidance(self, candidates: List[PortfolioCandidate]) -> List[str]:
        guidance: List[str] = []
        present = {item.analyzer_id: item for item in candidates}

        if not any(item.accepted for item in candidates):
            guidance.append("当前没有检测器通过功能验证。")

        csa = present.get("csa")
        codeql = present.get("codeql")
        if csa and csa.generation_success:
            guidance.append("CSA 适合路径敏感、本地状态和生命周期约束验证。")
        if codeql and codeql.generation_success:
            guidance.append("CodeQL 适合跨函数、跨文件的数据流和 API 语义扩展。")
        if csa and codeql and csa.generation_success and codeql.generation_success:
            guidance.append("若两者都可用，优先将首选检测器用于主报告，另一检测器作为补充搜索面。")
        return guidance

    def _build_summary(self, decision: PortfolioDecision, primary_pattern: str) -> str:
        if not decision.preferred_analyzer:
            return "没有检测器通过功能验证"

        parts = [f"首选 {decision.preferred_analyzer}"]
        if primary_pattern:
            parts.append(f"主模式 {primary_pattern}")
        if decision.confidence:
            parts.append(f"置信度 {decision.confidence}")
        if decision.preferred_reason:
            parts.append(decision.preferred_reason)
        return "，".join(parts)
