"""
Rule-guided PATCHWEAVER preflight planner.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .evidence_schema import (
    EvidenceBundle,
    EvidenceLocation,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceScope,
)
from .evidence_types import EvidencePlan, EvidenceRequirement, EvidenceType, PatchFact
from .mechanism_graph import MechanismGraphBuilder


RISKY_CALL_KEYWORDS = (
    "strcpy",
    "strcat",
    "sprintf",
    "memcpy",
    "memmove",
    "malloc",
    "calloc",
    "realloc",
    "free(",
    "delete ",
    "system(",
    "popen(",
)


class PatchFactsExtractor:
    """Extract patch-scoped facts from diff text and patch metadata."""

    FUNCTION_NAME_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
    ISSUE_PATTERN = re.compile(r"\b(?:fixes|issue|bug|ticket|gh-|#)\s*[:#-]?\s*([A-Za-z0-9_.-]+)\b", re.IGNORECASE)
    EXCLUDED_CALL_NAMES = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
    }

    def extract(
        self,
        patch_path: str,
        patch_analysis: Dict[str, Any],
    ) -> List[PatchFact]:
        patch_text = self._read_text(patch_path)
        additions, deletions = self._collect_changed_lines(patch_text)
        added_guards = [line.strip() for line in additions if re.search(r"\b(if|switch|while)\s*\(", line)]
        removed_risky_ops = [
            line.strip()
            for line in deletions
            if any(keyword in line for keyword in RISKY_CALL_KEYWORDS)
        ]
        added_api_calls = self._extract_api_calls(additions)
        patch_functions = self._extract_patch_functions(patch_text)
        fix_patterns = self._extract_fix_patterns(patch_analysis, additions)
        patch_intent = self._extract_patch_intent(patch_text)
        reference_hints = self._extract_reference_hints(patch_text)

        strategy = patch_analysis.get("detection_strategy", {}) or {}
        patterns = patch_analysis.get("vulnerability_patterns", []) or []
        functions = sorted({
            func_name
            for pattern in patterns
            for func_name in (pattern.get("affected_functions", []) or [])
            if func_name
        } | set(patch_functions))

        facts = [
            PatchFact(
                fact_type="patch_overview",
                label="Patch overview",
                attributes={
                    "patch_path": patch_path,
                    "changed_files": patch_analysis.get("files_changed", []),
                    "changed_file_count": len(patch_analysis.get("files_changed", []) or []),
                    "added_line_count": len(additions),
                    "deleted_line_count": len(deletions),
                },
            ),
            PatchFact(
                fact_type="vulnerability_patterns",
                label="Vulnerability patterns inferred from patch",
                attributes={
                    "patterns": [item.get("type", "unknown") for item in patterns],
                    "descriptions": [item.get("description", "") for item in patterns],
                },
            ),
            PatchFact(
                fact_type="affected_functions",
                label="Functions implicated by removed or fixed code",
                attributes={"functions": functions},
            ),
            PatchFact(
                fact_type="detection_strategy",
                label="Existing patch analysis detection strategy",
                attributes=strategy,
            ),
        ]

        if added_guards:
            facts.append(
                PatchFact(
                    fact_type="added_guards",
                    label="Patch introduces or strengthens guards",
                    attributes={"guards": added_guards[:12]},
                )
            )

        if removed_risky_ops:
            facts.append(
                PatchFact(
                    fact_type="removed_risky_operations",
                    label="Patch removes risky operations",
                    attributes={"operations": removed_risky_ops[:12]},
                )
            )

        if fix_patterns:
            facts.append(
                PatchFact(
                    fact_type="fix_patterns",
                    label="Patch introduces reusable fix patterns",
                    attributes={"patterns": fix_patterns[:12]},
                )
            )

        if added_api_calls:
            facts.append(
                PatchFact(
                    fact_type="added_api_calls",
                    label="Patch introduces or highlights API usage",
                    attributes={"apis": added_api_calls[:12]},
                )
            )

        cross_file_deps = patch_analysis.get("cross_file_dependencies", []) or []
        if cross_file_deps:
            facts.append(
                PatchFact(
                    fact_type="cross_file_dependencies",
                    label="Patch spans cross-file relationships",
                    attributes={"dependencies": cross_file_deps},
                )
            )

        if patch_intent:
            facts.append(
                PatchFact(
                    fact_type="patch_intent",
                    label="Patch intent and commit-style summary",
                    attributes=patch_intent,
                )
            )

        if reference_hints.get("cves") or reference_hints.get("cwes") or reference_hints.get("issues"):
            facts.append(
                PatchFact(
                    fact_type="external_references",
                    label="External references recovered from patch text",
                    attributes=reference_hints,
                )
            )

        return facts

    def _read_text(self, patch_path: str) -> str:
        try:
            return Path(patch_path).read_text(encoding="utf-8")
        except Exception:
            return ""

    def _collect_changed_lines(self, patch_text: str) -> Sequence[List[str]]:
        additions: List[str] = []
        deletions: List[str] = []
        for raw_line in (patch_text or "").splitlines():
            if raw_line.startswith("+++ ") or raw_line.startswith("--- "):
                continue
            if raw_line.startswith("+"):
                additions.append(raw_line[1:])
            elif raw_line.startswith("-"):
                deletions.append(raw_line[1:])
        return additions, deletions

    def _extract_api_calls(self, lines: Sequence[str]) -> List[str]:
        apis: List[str] = []
        for line in lines:
            for match in self.FUNCTION_NAME_PATTERN.findall(str(line or "")):
                name = str(match).strip()
                if name and name not in self.EXCLUDED_CALL_NAMES and name not in apis:
                    apis.append(name)
        return apis

    def _extract_patch_functions(self, patch_text: str) -> List[str]:
        functions: List[str] = []
        for raw_line in (patch_text or "").splitlines():
            if raw_line.startswith("@@"):
                suffix = raw_line.split("@@", 2)[-1].strip()
                for match in self.FUNCTION_NAME_PATTERN.findall(suffix):
                    name = str(match).strip()
                    if name and name not in self.EXCLUDED_CALL_NAMES and name not in functions:
                        functions.append(name)
                continue

            if not raw_line or raw_line[:1] not in {" ", "-", "+"}:
                continue

            candidate = raw_line[1:].strip()
            if not candidate or candidate.startswith("#"):
                continue
            if not candidate.endswith("{"):
                continue
            for match in self.FUNCTION_NAME_PATTERN.findall(candidate):
                name = str(match).strip()
                if name and name not in self.EXCLUDED_CALL_NAMES and name not in functions:
                    functions.append(name)
        return functions

    def _extract_fix_patterns(
        self,
        patch_analysis: Dict[str, Any],
        additions: Sequence[str],
    ) -> List[str]:
        patterns: List[str] = []
        for item in patch_analysis.get("vulnerability_patterns", []) or []:
            for pattern in (item.get("fix_patterns", []) or []):
                token = str(pattern).strip()
                if token and token not in patterns:
                    patterns.append(token)

        lowered_additions = [str(line).strip().lower() for line in additions]
        heuristics = [
            ("null check", ("if (", "null")),
            ("bounds check", ("if (", "sizeof")),
            ("lock discipline", ("pthread_mutex_lock",)),
            ("safe copy", ("strncpy", "snprintf", "memcpy_s")),
            ("pointer nullification", ("= null", "= nullptr")),
        ]
        for label, markers in heuristics:
            if any(all(marker in line for marker in markers) for line in lowered_additions):
                if label not in patterns:
                    patterns.append(label)
        return patterns

    def _extract_patch_intent(self, patch_text: str) -> Dict[str, Any]:
        subject = ""
        summary_lines: List[str] = []
        for raw_line in (patch_text or "").splitlines():
            stripped = raw_line.strip()
            if not stripped:
                if summary_lines:
                    break
                continue
            if stripped.startswith("diff --git "):
                break
            lowered = stripped.lower()
            if lowered.startswith("subject:"):
                subject = stripped.split(":", 1)[-1].strip()
                if subject and subject not in summary_lines:
                    summary_lines.append(subject)
                continue
            if lowered.startswith(("from ", "date:", "index ", "--- ", "+++ ", "@@ ")):
                continue
            if stripped.startswith(("+", "-", "@@", "new file", "deleted file", "rename")):
                continue
            if len(stripped) <= 160 and stripped not in summary_lines:
                summary_lines.append(stripped)
            if len(summary_lines) >= 4:
                break

        summary = " | ".join(summary_lines[:3]).strip()
        keywords: List[str] = []
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{3,}", f"{subject} {summary}".lower()):
            if token not in keywords:
                keywords.append(token)
        payload: Dict[str, Any] = {}
        if subject:
            payload["subject"] = subject
        if summary:
            payload["summary"] = summary
        if keywords:
            payload["keywords"] = keywords[:8]
        return payload

    def _extract_reference_hints(self, patch_text: str) -> Dict[str, Any]:
        cves = sorted({match.upper() for match in self.CVE_PATTERN.findall(patch_text or "")})
        cwes = sorted({match.upper() for match in self.CWE_PATTERN.findall(patch_text or "")})
        issues = []
        for match in self.ISSUE_PATTERN.findall(patch_text or ""):
            token = str(match).strip()
            if token and token not in issues:
                issues.append(token)
        for match in re.findall(r"#(\d+)\b", patch_text or ""):
            token = str(match).strip()
            if token and token not in issues:
                issues.append(token)
        return {
            "cves": cves[:6],
            "cwes": cwes[:6],
            "issues": issues[:6],
        }


class EvidencePlanner:
    """Plan evidence requirements from patch semantics and analyzer capabilities."""

    def plan(
        self,
        patch_analysis: Dict[str, Any],
        patch_facts: List[PatchFact],
        mechanism_graph: Dict[str, Any],
        analyzer_catalog: List[Dict[str, Any]],
        selected_analyzers: Iterable[str],
    ) -> EvidencePlan:
        selected = [str(item).lower().strip() for item in selected_analyzers if str(item).strip()]
        strategy = patch_analysis.get("detection_strategy", {}) or {}
        patterns = patch_analysis.get("vulnerability_patterns", []) or []
        primary_pattern = self._resolve_primary_pattern(strategy, patterns, patch_facts)

        requirements: Dict[str, EvidenceRequirement] = {}
        hypotheses: List[str] = []
        planner_notes: List[str] = []
        escalation_triggers: List[str] = []
        fallback_collectors: List[str] = []

        self._require(
            requirements,
            EvidenceType.PATCH_FACT.value,
            reason="Patch semantics must anchor all downstream synthesis decisions.",
            priority=100,
            preferred_analyzers=[],
            confidence=1.0,
            mechanism_refs=["patch"],
        )

        if strategy.get("data_flow_tracking"):
            hypotheses.append("The patch changes a data propagation condition that should generalize beyond the edited lines.")
            self._require(
                requirements,
                EvidenceType.DATAFLOW_CANDIDATE.value,
                reason="Patch analysis requests data-flow tracking.",
                priority=95,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.DATAFLOW_CANDIDATE.value
                ),
                confidence=0.9,
                mechanism_refs=["strategy"],
            )
            self._require(
                requirements,
                EvidenceType.CALL_CHAIN.value,
                reason="Interprocedural call-chain context is needed to generalize the fix pattern.",
                priority=78,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.CALL_CHAIN.value
                ),
                confidence=0.78,
                mechanism_refs=["strategy"],
            )

        if strategy.get("cross_file_analysis"):
            hypotheses.append("The vulnerability mechanism crosses file boundaries and should not be captured with local-only reasoning.")
            self._require(
                requirements,
                EvidenceType.CONTEXT_SUMMARY.value,
                reason="Cross-file patch suggests build/module context is needed to scope evidence extraction.",
                priority=84,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.CONTEXT_SUMMARY.value
                ),
                confidence=0.8,
                mechanism_refs=["strategy"],
            )
            self._require(
                requirements,
                EvidenceType.SEMANTIC_SLICE.value,
                reason="Cross-file patch suggests a verifier-backed semantic slice is needed, not just a project summary.",
                priority=86,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.SEMANTIC_SLICE.value
                ),
                confidence=0.83,
                mechanism_refs=["strategy"],
            )

        pattern_types = {
            self._normalize_pattern_token(item.get("type", ""))
            for item in patterns
            if self._normalize_pattern_token(item.get("type", ""))
        }
        if primary_pattern and primary_pattern != "unknown":
            pattern_types.add(primary_pattern)
        if pattern_types & {"use_after_free", "double_free"}:
            hypotheses.append("The patch likely changes a resource lifecycle or stale-state transition.")
            self._require(
                requirements,
                EvidenceType.ALLOCATION_LIFECYCLE.value,
                reason="Lifetime-sensitive bug family requires allocation/free reasoning.",
                priority=92,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.ALLOCATION_LIFECYCLE.value
                ),
                confidence=0.92,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.STATE_TRANSITION.value,
                reason="Need local state transitions around free/delete and later uses.",
                priority=89,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.STATE_TRANSITION.value
                ),
                confidence=0.88,
                mechanism_refs=["pattern_0"],
            )

        if pattern_types & {"buffer_overflow", "null_dereference", "integer_overflow"}:
            hypotheses.append("The fix strengthens a guard or bound that should be captured as a reusable precondition.")
            self._require(
                requirements,
                EvidenceType.PATH_GUARD.value,
                reason="Patch likely adds a guard or bound check before a dangerous operation.",
                priority=90,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.PATH_GUARD.value
                ),
                confidence=0.87,
                mechanism_refs=["pattern_0"],
            )
        if "buffer_overflow" in pattern_types:
            self._require(
                requirements,
                EvidenceType.SEMANTIC_SLICE.value,
                reason="Buffer-overflow fixes need a verifier-backed semantic slice that binds the same destination, size carrier, and patch barrier.",
                priority=88,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.SEMANTIC_SLICE.value
                ),
                confidence=0.86,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.CONTEXT_SUMMARY.value,
                reason="Buffer-overflow fixes need a compact contract summary of removed risky sinks, patch-added barriers, and safe replacement APIs.",
                priority=82,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.CONTEXT_SUMMARY.value
                ),
                confidence=0.8,
                mechanism_refs=["pattern_0"],
            )

        if "race_condition" in pattern_types:
            hypotheses.append("The patch restores atomicity around shared-state updates and check-then-act windows.")
            self._require(
                requirements,
                EvidenceType.PATH_GUARD.value,
                reason="Need concrete guarded regions or synchronization boundaries around shared state.",
                priority=91,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.PATH_GUARD.value
                ),
                confidence=0.89,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.STATE_TRANSITION.value,
                reason="Race-condition fixes typically change shared-state transitions or lock discipline.",
                priority=90,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.STATE_TRANSITION.value
                ),
                confidence=0.88,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.API_CONTRACT.value,
                reason="Need concrete synchronization/API evidence such as mutex or atomic operations.",
                priority=82,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.API_CONTRACT.value
                ),
                confidence=0.8,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.CALL_CHAIN.value,
                reason="Cross-function shared-state access patterns should be summarized beyond the edited lines.",
                priority=72,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.CALL_CHAIN.value
                ),
                confidence=0.7,
                mechanism_refs=["pattern_0"],
            )

        if pattern_types & {"command_injection", "path_traversal", "sql_injection", "taint_tracking"}:
            hypotheses.append("The vulnerability depends on source-to-sink propagation and API semantics.")
            self._require(
                requirements,
                EvidenceType.API_CONTRACT.value,
                reason="Patch semantics likely involve source/sink or sanitizer APIs.",
                priority=86,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.API_CONTRACT.value
                ),
                confidence=0.8,
                mechanism_refs=["pattern_0"],
            )

        if any(fact.fact_type == "added_guards" for fact in patch_facts):
            planner_notes.append("Added guards detected in patch diff; path-sensitive evidence should stay near top priority.")
        if primary_pattern != "unknown" and not strategy.get("primary_pattern"):
            planner_notes.append(f"Primary pattern inferred from patch semantics: {primary_pattern}.")

        if not hypotheses:
            hypotheses.append("Patch likely encodes a reusable vulnerability mechanism but available metadata is weak; keep evidence collection broad.")

        affected_functions = [
            str(func_name).strip()
            for fact in patch_facts
            if fact.fact_type == "affected_functions"
            for func_name in (fact.attributes.get("functions", []) or [])
            if str(func_name).strip()
        ]
        if len(pattern_types) > 1:
            escalation_triggers.append("competing_patch_patterns")
        if primary_pattern == "unknown":
            escalation_triggers.append("weak_primary_pattern")
        if not affected_functions:
            escalation_triggers.append("no_anchor_function")
        if strategy.get("cross_file_analysis"):
            escalation_triggers.append("cross_file_mechanism")
        if any(fact.fact_type == "external_references" for fact in patch_facts):
            escalation_triggers.append("metadata_available")

        uncertainty_budget = "high" if len(escalation_triggers) >= 2 else ("medium" if escalation_triggers else "low")
        if uncertainty_budget != "low" or any(
            fact.fact_type in {"patch_intent", "external_references"} for fact in patch_facts
        ):
            fallback_collectors.append("metadata_intent")
            self._require(
                requirements,
                EvidenceType.METADATA_HINT.value,
                reason="Patch intent / external references should be aligned with analyzer evidence when uncertainty remains non-trivial.",
                priority=76 if uncertainty_budget == "high" else 68,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.METADATA_HINT.value
                ),
                confidence=0.74 if uncertainty_budget == "high" else 0.66,
                mechanism_refs=["patch"],
            )

        recommended_analyzers = self._rank_analyzers(analyzer_catalog, list(requirements.values()))
        coverage_gaps = self._detect_coverage_gaps(list(requirements.values()), selected, analyzer_catalog)
        if coverage_gaps:
            planner_notes.append("Selected analyzers do not cover every planned evidence primitive.")
            if "selected_coverage_gap" not in escalation_triggers:
                escalation_triggers.append("selected_coverage_gap")
            if "metadata_intent" not in fallback_collectors:
                fallback_collectors.append("metadata_intent")

        return EvidencePlan(
            primary_pattern=primary_pattern,
            hypotheses=hypotheses,
            requirements=sorted(
                requirements.values(),
                key=lambda item: (-item.priority, item.evidence_type),
            ),
            recommended_analyzers=recommended_analyzers,
            planner_notes=planner_notes,
            coverage_gaps=coverage_gaps,
            uncertainty_budget=uncertainty_budget,
            escalation_triggers=escalation_triggers,
            fallback_collectors=fallback_collectors,
        )

    def _resolve_primary_pattern(
        self,
        strategy: Dict[str, Any],
        patterns: List[Dict[str, Any]],
        patch_facts: List[PatchFact],
    ) -> str:
        direct = self._normalize_pattern_token(strategy.get("primary_pattern", ""))
        if direct and direct != "unknown":
            return direct
        for item in patterns:
            token = self._normalize_pattern_token(item.get("type", ""))
            if token and token != "unknown":
                return token
        inferred = self._infer_primary_pattern_from_patch_facts(patch_facts)
        return inferred or "unknown"

    def _normalize_pattern_token(self, token: Any) -> str:
        normalized = str(token or "").strip().lower().replace("-", "_").replace(" ", "_")
        return normalized or "unknown"

    def _infer_primary_pattern_from_patch_facts(self, patch_facts: List[PatchFact]) -> str:
        removed_ops: List[str] = []
        added_guards: List[str] = []
        added_apis: List[str] = []
        for fact in patch_facts:
            if fact.fact_type == "removed_risky_operations":
                removed_ops.extend(str(item).strip().lower() for item in (fact.attributes.get("operations", []) or []))
            elif fact.fact_type == "added_guards":
                added_guards.extend(str(item).strip().lower() for item in (fact.attributes.get("guards", []) or []))
            elif fact.fact_type == "added_api_calls":
                added_apis.extend(str(item).strip().lower() for item in (fact.attributes.get("apis", []) or []))

        removed_text = "\n".join(removed_ops)
        guard_text = "\n".join(added_guards)
        api_text = " ".join(added_apis)

        removed_buffer_ops = any(token in removed_text for token in ("strcpy", "strcat", "sprintf", "memcpy", "memmove"))
        added_bounds_barrier = any(token in guard_text for token in ("sizeof", "capacity", "out_size", "len", "bytes", "written"))
        added_safe_api = any(token in api_text for token in ("snprintf", "strncpy", "strncat", "memcpy", "memmove"))
        if removed_buffer_ops and (added_bounds_barrier or added_safe_api):
            return "buffer_overflow"

        removed_null_sink = any(token in removed_text for token in ("->", "*", "["))
        if removed_null_sink and any(token in guard_text for token in ("null", "!ptr", "!record", "!user")):
            return "null_dereference"

        return "unknown"

    def bootstrap_bundle(
        self,
        patch_facts: List[PatchFact],
        patch_analysis: Dict[str, Any],
        plan: EvidencePlan,
    ) -> EvidenceBundle:
        records: List[EvidenceRecord] = []
        file_details = patch_analysis.get("file_details", []) or []
        primary_file = file_details[0].get("path", "") if file_details else ""
        functions = []
        for fact in patch_facts:
            if fact.fact_type == "affected_functions":
                functions = fact.attributes.get("functions", []) or []
                break

        for index, fact in enumerate(patch_facts):
            scope = EvidenceScope(
                repo=Path(patch_analysis.get("patch_path", "")).name if patch_analysis.get("patch_path") else "",
                file=primary_file,
                function=functions[0] if functions else "",
            )
            records.append(
                EvidenceRecord(
                    evidence_id=f"pf_{index:03d}",
                    type=EvidenceType.PATCH_FACT.value,
                    analyzer="patch",
                    scope=scope,
                    location=EvidenceLocation(),
                    semantic_payload=fact.to_dict(),
                    provenance=EvidenceProvenance(
                        tool="patch-analysis",
                        artifact=fact.fact_type,
                        confidence=0.95,
                    ),
                )
            )

        missing_evidence = [
            item.evidence_type
            for item in plan.requirements
            if item.evidence_type != EvidenceType.PATCH_FACT.value
        ]

        return EvidenceBundle(
            records=records,
            missing_evidence=missing_evidence,
            collected_analyzers=["patch"],
        )

    def _require(
        self,
        requirements: Dict[str, EvidenceRequirement],
        evidence_type: str,
        reason: str,
        priority: int,
        preferred_analyzers: List[str],
        confidence: float,
        mechanism_refs: List[str],
    ):
        current = requirements.get(evidence_type)
        if current is None or priority > current.priority:
            requirements[evidence_type] = EvidenceRequirement(
                evidence_type=evidence_type,
                reason=reason,
                priority=priority,
                preferred_analyzers=preferred_analyzers,
                confidence=confidence,
                mechanism_refs=mechanism_refs,
            )

    def _find_supporting_analyzers(
        self,
        analyzer_catalog: List[Dict[str, Any]],
        evidence_type: str,
    ) -> List[str]:
        supported: List[str] = []
        for item in analyzer_catalog:
            analyzer_id = str(item.get("id", "")).lower().strip()
            if not analyzer_id:
                continue
            evidence_types = [str(x).strip() for x in item.get("evidence_types", []) or []]
            if evidence_type in evidence_types and analyzer_id not in supported:
                supported.append(analyzer_id)
        return supported

    def _rank_analyzers(
        self,
        analyzer_catalog: List[Dict[str, Any]],
        requirements: List[EvidenceRequirement],
    ) -> List[str]:
        scores: Dict[str, int] = {}
        for requirement in requirements:
            for analyzer_id in requirement.preferred_analyzers:
                scores[analyzer_id] = scores.get(analyzer_id, 0) + requirement.priority

        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        ordered = [name for name, _score in ranked]
        if ordered:
            return ordered

        return [
            str(item.get("id", "")).lower().strip()
            for item in analyzer_catalog
            if item.get("id")
        ]

    def _detect_coverage_gaps(
        self,
        requirements: List[EvidenceRequirement],
        selected_analyzers: List[str],
        analyzer_catalog: List[Dict[str, Any]],
    ) -> List[str]:
        if not selected_analyzers:
            return []

        selected_set = set(selected_analyzers)
        available = {
            str(item.get("id", "")).lower().strip(): set(item.get("evidence_types", []) or [])
            for item in analyzer_catalog
            if item.get("id")
        }

        gaps: List[str] = []
        for requirement in requirements:
            if requirement.evidence_type == EvidenceType.PATCH_FACT.value:
                continue
            supported = {
                analyzer_id
                for analyzer_id, evidence_types in available.items()
                if requirement.evidence_type in evidence_types
            }
            if supported and not (supported & selected_set):
                gaps.append(
                    f"{requirement.evidence_type} is not covered by selected analyzers {sorted(selected_set)}"
                )
        return gaps


class PatchWeaverPreflight:
    """End-to-end deterministic preflight for PATCHWEAVER phase A."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self._facts = PatchFactsExtractor()
        self._graph_builder = MechanismGraphBuilder()
        self._planner = EvidencePlanner()

    def analyze(
        self,
        patch_path: str,
        patch_analysis: Dict[str, Any],
        analyzer_catalog: List[Dict[str, Any]],
        selected_analyzers: Iterable[str],
    ) -> Dict[str, Any]:
        enriched_analysis = dict(patch_analysis or {})
        enriched_analysis["patch_path"] = patch_path

        patch_facts = self._facts.extract(patch_path, enriched_analysis)
        mechanism_graph = self._graph_builder.build(patch_facts, enriched_analysis)
        evidence_plan = self._planner.plan(
            patch_analysis=enriched_analysis,
            patch_facts=patch_facts,
            mechanism_graph=mechanism_graph.to_dict(),
            analyzer_catalog=analyzer_catalog,
            selected_analyzers=selected_analyzers,
        )
        evidence_plan = self._limit_plan(evidence_plan)
        evidence_bundle = self._planner.bootstrap_bundle(
            patch_facts=patch_facts,
            patch_analysis=enriched_analysis,
            plan=evidence_plan,
        )

        return {
            "summary": mechanism_graph.summary,
            "patch_facts": [fact.to_dict() for fact in patch_facts],
            "mechanism_graph": mechanism_graph.to_dict(),
            "evidence_plan": evidence_plan.to_dict(),
            "evidence_bundle": evidence_bundle.to_dict(),
        }

    def _limit_plan(self, plan: EvidencePlan) -> EvidencePlan:
        settings = self.config.get("patchweaver", {}) or {}
        limit = int(settings.get("max_planned_requirements", 8) or 8)
        if limit <= 0 or len(plan.requirements) <= limit:
            return plan

        return EvidencePlan(
            primary_pattern=plan.primary_pattern,
            hypotheses=plan.hypotheses,
            requirements=plan.requirements[:limit],
            recommended_analyzers=plan.recommended_analyzers,
            planner_notes=plan.planner_notes + [
                f"Planner output truncated to top {limit} evidence requirements by configuration."
            ],
            coverage_gaps=plan.coverage_gaps,
            uncertainty_budget=plan.uncertainty_budget,
            escalation_triggers=plan.escalation_triggers,
            fallback_collectors=plan.fallback_collectors,
        )
