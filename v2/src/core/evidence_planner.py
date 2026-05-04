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
    FUNCTION_SIGNATURE_PATTERN = re.compile(
        r"^\s*(?:[A-Za-z_][\w]*(?:[\s\*]+[A-Za-z_][\w]*)*[\s\*]+)?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{\s*$"
    )
    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
    ISSUE_PATTERN = re.compile(r"\b(?:fixes|issue|bug|ticket|gh-|#)\s*[:#-]?\s*([A-Za-z0-9_.-]+)\b", re.IGNORECASE)
    DECLARATION_PATTERN = re.compile(
        r"^\s*(?P<type>(?:const\s+|volatile\s+|signed\s+|unsigned\s+)*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)\s+(?P<vars>[^;=]+);\s*$"
    )
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
        type_widenings = self._collect_type_widenings(additions, deletions)
        removed_risky_ops = [
            line.strip()
            for line in deletions
            if any(keyword in line for keyword in RISKY_CALL_KEYWORDS)
        ]
        added_api_calls = self._extract_api_calls(additions)
        patch_functions = self._extract_patch_functions(patch_text)
        recovered_functions = self._recover_patch_functions_from_source(patch_path)
        patch_intent = self._extract_patch_intent(patch_text)
        intent_functions = self._extract_intent_functions(patch_intent)
        inferred_patterns = self._infer_patterns_from_patch(
            patch_analysis=patch_analysis,
            patch_intent=patch_intent,
            type_widenings=type_widenings,
            additions=additions,
            deletions=deletions,
        )
        fix_patterns = self._extract_fix_patterns(
            patch_analysis=patch_analysis,
            additions=additions,
            type_widenings=type_widenings,
            inferred_patterns=inferred_patterns,
        )
        reference_hints = self._extract_reference_hints(patch_text)

        strategy = patch_analysis.get("detection_strategy", {}) or {}
        patterns = patch_analysis.get("vulnerability_patterns", []) or []
        functions = sorted({
            func_name
            for pattern in patterns
            for func_name in (pattern.get("affected_functions", []) or [])
            if func_name
        } | set(patch_functions) | set(recovered_functions) | set(intent_functions))
        pattern_tokens = [
            item.get("type", "unknown")
            for item in patterns
            if str(item.get("type", "") or "").strip()
        ]
        for token in inferred_patterns:
            if token not in pattern_tokens:
                pattern_tokens.append(token)

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
                    "patterns": pattern_tokens,
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

        for item in type_widenings:
            facts.append(
                PatchFact(
                    fact_type="type_widening",
                    label="Patch widens arithmetic carriers",
                    attributes=item,
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
        current_function = ""
        for raw_line in (patch_text or "").splitlines():
            if raw_line.startswith("diff --git "):
                current_function = ""
                continue
            if raw_line.startswith("@@"):
                suffix = raw_line.split("@@", 2)[-1].strip()
                current_function = self._extract_function_signature_name(suffix)
                if current_function and current_function not in functions:
                    functions.append(current_function)
                continue

            if not raw_line or raw_line[:1] not in {" ", "-", "+"} or raw_line.startswith(("--- ", "+++ ")):
                continue

            candidate = raw_line[1:].strip()
            if not candidate or candidate.startswith("#"):
                continue
            signature_name = self._extract_function_signature_name(candidate)
            if signature_name:
                current_function = signature_name
                if raw_line[:1] in {"+", "-"} and signature_name not in functions:
                    functions.append(signature_name)
                continue
            if raw_line[:1] in {"+", "-"} and current_function and current_function not in functions:
                functions.append(current_function)
        return functions

    def _extract_function_signature_name(self, candidate: str) -> str:
        stripped = str(candidate or "").strip()
        if not stripped or not stripped.endswith("{"):
            return ""
        match = self.FUNCTION_SIGNATURE_PATTERN.match(stripped)
        if not match:
            return ""
        name = str(match.group(1) or "").strip()
        if not name or name in self.EXCLUDED_CALL_NAMES:
            return ""
        return name

    def _recover_patch_functions_from_source(self, patch_path: str) -> List[str]:
        try:
            from ..evidence.collectors.artifact_extractor import ProjectArtifactExtractor
        except Exception:
            return []

        patch_file = Path(str(patch_path or "")).expanduser().resolve()
        if not patch_file.exists():
            return []

        extractor = ProjectArtifactExtractor()
        functions: List[str] = []
        root_candidates = [
            candidate
            for candidate in [patch_file.parent, *patch_file.parents[:4]]
            if candidate and candidate.exists() and candidate.is_dir()
        ]

        for file_entry in extractor.parse_patch(str(patch_file)):
            patch_rel = str(file_entry.get("old_path") or file_entry.get("new_path") or "").strip()
            if not patch_rel:
                continue

            resolved = None
            for root in root_candidates:
                resolved = extractor.resolve_project_file(root, patch_rel)
                if resolved is not None and resolved.exists():
                    break
            if resolved is None or not resolved.exists():
                continue

            try:
                lines = resolved.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            for hunk in file_entry.get("hunks", []) or []:
                anchors = [
                    int(hunk.get("old_start", 0) or 0),
                    int(hunk.get("new_start", 0) or 0),
                ]
                for anchor in anchors:
                    if anchor <= 0:
                        continue
                    function_name, _parameters, _start, _end = extractor.find_function_context(lines, anchor)
                    if function_name and function_name not in functions:
                        functions.append(function_name)
                        break
        return functions[:8]

    def _extract_fix_patterns(
        self,
        patch_analysis: Dict[str, Any],
        additions: Sequence[str],
        type_widenings: Sequence[Dict[str, Any]],
        inferred_patterns: Sequence[str],
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
        if type_widenings:
            for label in ("integer widening", "counter widening", "wide accumulator"):
                if label not in patterns:
                    patterns.append(label)
        if "integer_overflow" in inferred_patterns and "overflow-safe accumulator" not in patterns:
            patterns.append("overflow-safe accumulator")
        if any(self._looks_like_overflow_guard(line) for line in lowered_additions):
            if "overflow bounds check" not in patterns:
                patterns.append("overflow bounds check")
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

    def _collect_type_widenings(
        self,
        additions: Sequence[str],
        deletions: Sequence[str],
    ) -> List[Dict[str, Any]]:
        widened: List[Dict[str, Any]] = []
        seen = set()
        deleted_decls = [item for item in (self._parse_declaration(line) for line in deletions) if item]
        added_decls = [item for item in (self._parse_declaration(line) for line in additions) if item]

        for old_type, old_vars, old_line in deleted_decls:
            old_rank = self._type_rank(old_type)
            if old_rank <= 0:
                continue
            for new_type, new_vars, new_line in added_decls:
                new_rank = self._type_rank(new_type)
                shared = [var for var in old_vars if var in new_vars]
                if new_rank <= old_rank or not shared:
                    continue
                key = (old_type, new_type, tuple(shared))
                if key in seen:
                    continue
                seen.add(key)
                widened.append(
                    {
                        "old_type": old_type,
                        "new_type": new_type,
                        "variables": shared[:8],
                        "variable_count": len(shared),
                        "deleted_declaration": old_line,
                        "added_declaration": new_line,
                    }
                )
        return widened[:4]

    def _parse_declaration(self, line: str) -> tuple[str, List[str], str] | None:
        stripped = str(line or "").strip()
        if not stripped or "(" in stripped or ")" in stripped or "=" in stripped:
            return None
        match = self.DECLARATION_PATTERN.match(stripped)
        if not match:
            return None
        type_name = self._normalize_type(match.group("type"))
        variables: List[str] = []
        for chunk in str(match.group("vars") or "").split(","):
            candidate = re.sub(r"\[[^\]]*\]", "", chunk).strip()
            symbol_match = re.search(r"([A-Za-z_]\w*)$", candidate)
            if symbol_match:
                variables.append(symbol_match.group(1))
        variables = [item for item in variables if item]
        if not type_name or not variables:
            return None
        return type_name, variables[:12], stripped

    def _normalize_type(self, raw_type: str) -> str:
        lowered = " ".join(str(raw_type or "").strip().lower().split())
        aliases = {
            "sqlite3_int64": "i64",
            "sqlite_int64": "i64",
            "int64_t": "i64",
            "long long int": "long long",
            "unsigned long long int": "unsigned long long",
            "sqlite3_uint64": "u64",
            "uint64_t": "u64",
        }
        return aliases.get(lowered, lowered)

    def _type_rank(self, type_name: str) -> int:
        normalized = self._normalize_type(type_name)
        if normalized in {"char", "short", "unsigned char", "unsigned short"}:
            return 1
        if normalized in {"int", "unsigned int", "long", "unsigned long"}:
            return 2
        if normalized in {"size_t", "ssize_t", "long long", "unsigned long long", "i64", "u64"}:
            return 3
        return 0

    def _extract_intent_functions(self, patch_intent: Dict[str, Any]) -> List[str]:
        subject = str(patch_intent.get("subject", "") or "")
        summary = str(patch_intent.get("summary", "") or "")
        functions: List[str] = []
        for token in re.findall(r"\b([A-Za-z_]\w{4,})\b", f"{subject} {summary}"):
            lowered = token.lower()
            if lowered in {"patch", "integer", "overflow", "fix", "subject", "fossilorigin", "name"}:
                continue
            if token.startswith(("CVE_", "CWE_")):
                continue
            if "_" not in token and not any(ch.isupper() for ch in token[1:]):
                continue
            if token not in functions:
                functions.append(token)
        return functions[:6]

    def _infer_patterns_from_patch(
        self,
        patch_analysis: Dict[str, Any],
        patch_intent: Dict[str, Any],
        type_widenings: Sequence[Dict[str, Any]],
        additions: Sequence[str],
        deletions: Sequence[str],
    ) -> List[str]:
        inferred: List[str] = []
        subject = str(patch_intent.get("subject", "") or "").lower()
        summary = str(patch_intent.get("summary", "") or "").lower()
        text = " ".join([subject, summary] + [str(line).lower() for line in additions] + [str(line).lower() for line in deletions])
        if ("integer overflow" in text or "overflow fix" in text or "arithmetic" in text) and type_widenings:
            inferred.append("integer_overflow")
        elif type_widenings and any(token in text for token in ("overflow", "widen", "counter", "accumulator")):
            inferred.append("integer_overflow")
        elif any(self._looks_like_overflow_guard(str(line).lower()) for line in additions):
            inferred.append("integer_overflow")

        strategy = patch_analysis.get("detection_strategy", {}) or {}
        primary = str(strategy.get("primary_pattern", "") or "").strip()
        if primary and primary not in inferred:
            inferred.append(primary)
        return inferred

    def _looks_like_overflow_guard(self, lowered_line: str) -> bool:
        text = str(lowered_line or "").strip()
        if not text:
            return False
        if any(limit in text for limit in ("size_max", "int_max", "uint_max", "long_max", "ssize_max")):
            return True
        return bool(
            "/" in text
            and any(op in text for op in (">", ">=", "<", "<="))
            and any(token in text for token in ("count", "size", "len", "bytes", "capacity", "elem"))
        )


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
                EvidenceType.SEMANTIC_SLICE.value,
                reason="Cross-file patch suggests a verifier-backed semantic slice is needed, not just a project summary.",
                priority=86,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.SEMANTIC_SLICE.value
                ),
                confidence=0.83,
                mechanism_refs=["strategy"],
            )
            self._require(
                requirements,
                EvidenceType.CALL_CHAIN.value,
                reason="Cross-file patch needs interprocedural call edges, not only local edited-line context.",
                priority=82,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.CALL_CHAIN.value
                ),
                confidence=0.78,
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

        if pattern_types & {"buffer_overflow", "null_dereference"}:
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

        if "integer_overflow" in pattern_types:
            hypotheses.append("The fix widens arithmetic carriers or restores a wider numeric domain before a size-related sink.")
            self._require(
                requirements,
                EvidenceType.SEMANTIC_SLICE.value,
                reason="Arithmetic-overflow fixes need the concrete accumulator/sink slice, not a patch headline.",
                priority=90,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.SEMANTIC_SLICE.value
                ),
                confidence=0.9,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.STATE_TRANSITION.value,
                reason="Need local numeric-domain transitions such as int32 accumulator to i64 accumulator before the sink.",
                priority=84,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.STATE_TRANSITION.value
                ),
                confidence=0.82,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.DATAFLOW_CANDIDATE.value,
                reason="Need candidate flow from narrow counters/length carriers into the downstream allocation or formatting sink.",
                priority=82,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.DATAFLOW_CANDIDATE.value
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
            # API_CONTRACT 已剔除，同步信息可从 SEMANTIC_SLICE.api_terms 获取
            self._require(
                requirements,
                EvidenceType.SEMANTIC_SLICE.value,
                reason="Race-condition fixes need semantic slice with synchronization API terms.",
                priority=82,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.SEMANTIC_SLICE.value
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
            # API_CONTRACT 已剔除，source/sink 信息可从 SEMANTIC_SLICE.api_terms 获取
            self._require(
                requirements,
                EvidenceType.SEMANTIC_SLICE.value,
                reason="Patch semantics likely involve source/sink or sanitizer APIs.",
                priority=86,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.SEMANTIC_SLICE.value
                ),
                confidence=0.8,
                mechanism_refs=["pattern_0"],
            )
            self._require(
                requirements,
                EvidenceType.DATAFLOW_CANDIDATE.value,
                reason="Taint tracking requires dataflow evidence.",
                priority=84,
                preferred_analyzers=self._find_supporting_analyzers(
                    analyzer_catalog, EvidenceType.DATAFLOW_CANDIDATE.value
                ),
                confidence=0.78,
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

        recommended_analyzers = self._rank_analyzers(analyzer_catalog, list(requirements.values()))
        coverage_gaps = self._detect_coverage_gaps(list(requirements.values()), selected, analyzer_catalog)
        if coverage_gaps:
            planner_notes.append("Selected analyzers do not cover every planned evidence primitive.")
            if "selected_coverage_gap" not in escalation_triggers:
                escalation_triggers.append("selected_coverage_gap")

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
        type_widening = False
        intent_tokens: List[str] = []
        for fact in patch_facts:
            if fact.fact_type == "removed_risky_operations":
                removed_ops.extend(str(item).strip().lower() for item in (fact.attributes.get("operations", []) or []))
            elif fact.fact_type == "added_guards":
                added_guards.extend(str(item).strip().lower() for item in (fact.attributes.get("guards", []) or []))
            elif fact.fact_type == "added_api_calls":
                added_apis.extend(str(item).strip().lower() for item in (fact.attributes.get("apis", []) or []))
            elif fact.fact_type == "type_widening":
                type_widening = True
            elif fact.fact_type == "patch_intent":
                text = " ".join(
                    str(fact.attributes.get(key, "") or "")
                    for key in ("subject", "summary")
                ).lower()
                intent_tokens.extend(re.findall(r"[a-z0-9_+-]+", text))

        removed_text = "\n".join(removed_ops)
        guard_text = "\n".join(added_guards)
        api_text = " ".join(added_apis)
        intent_text = " ".join(intent_tokens)

        removed_buffer_ops = any(token in removed_text for token in ("strcpy", "strcat", "sprintf", "memcpy", "memmove"))
        added_bounds_barrier = any(token in guard_text for token in ("sizeof", "capacity", "out_size", "len", "bytes", "written"))
        added_safe_api = any(token in api_text for token in ("snprintf", "strncpy", "strncat", "memcpy", "memmove"))
        if removed_buffer_ops and (added_bounds_barrier or added_safe_api):
            return "buffer_overflow"

        removed_null_sink = any(token in removed_text for token in ("->", "*", "["))
        if removed_null_sink and any(token in guard_text for token in ("null", "!ptr", "!record", "!user")):
            return "null_dereference"

        if type_widening and any(token in intent_text for token in ("integer", "overflow", "counter", "accumulator")):
            return "integer_overflow"

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
        )
