"""
证据查询工具 - 供 Refine Decide 阶段模型主动选择证据类型
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.evidence_schema import EvidenceRecord, EvidenceBundle


# 可选证据类型清单（供模型参考）
AVAILABLE_EVIDENCE_TYPES = {
    "patch_fact": {
        "description": "补丁事实摘要",
        "usage": "需要理解补丁修复的漏洞模式、涉及的函数和文件",
    },
    "semantic_slice": {
        "description": "语义切片（代码片段）",
        "usage": "需要补丁涉及的上下文代码文件对应代码切片信息",
    },
    "dataflow_candidate": {
        "description": "数据流候选",
        "usage": "需要理解数据如何在变量/API间流动",
    },
    "call_chain": {
        "description": "调用链",
        "usage": "需要理解函数调用关系、callee/caller",
    },
    "path_guard": {
        "description": "路径守卫条件",
        "usage": "需要理解条件检查、边界守卫",
    },
    "allocation_lifecycle": {
        "description": "分配生命周期",
        "usage": "内存漏洞场景（use_after_free, double_free）",
    },
    "state_transition": {
        "description": "状态转换",
        "usage": "状态机、锁状态、引用计数场景",
    },
    "directory_tree": {
        "description": "目录层级信息",
        "usage": "需要了解项目结构、文件位置、目录层级",
    },
}


class EvidenceQueryTools:
    """证据查询工具集 - 模型主动选择证据类型"""

    def __init__(self, bundle: EvidenceBundle, project_root: Optional[Path] = None):
        self.bundle = bundle
        self.project_root = project_root
        self._by_type: Dict[str, List[EvidenceRecord]] = {}
        self._build_indices()

    def _build_indices(self) -> None:
        """构建证据类型索引"""
        for record in self.bundle.records:
            self._by_type.setdefault(record.type, []).append(record)

    # ===== 证据类型清单 =====

    def list_available_evidence_types(self) -> Dict[str, Dict[str, str]]:
        """列出可选证据类型清单供模型选择"""
        return AVAILABLE_EVIDENCE_TYPES

    def get_evidence_by_types(self, evidence_types: List[str]) -> Dict[str, Any]:
        """
        根据模型请求的证据类型批量获取证据
        模型在 request_evidence action 中指定需要的证据类型列表
        """
        result: Dict[str, Any] = {}
        for ev_type in evidence_types:
            if ev_type == "patch_fact":
                result["patch_fact"] = self.get_patch_facts()
            elif ev_type == "semantic_slice":
                result["semantic_slice"] = self.get_semantic_slices()
            elif ev_type == "dataflow_candidate":
                result["dataflow_candidate"] = self.get_dataflow_candidates()
            elif ev_type == "call_chain":
                result["call_chain"] = self.get_call_edges()
            elif ev_type == "path_guard":
                result["path_guard"] = self.get_guards()
            elif ev_type == "allocation_lifecycle":
                result["allocation_lifecycle"] = self.get_allocation_lifecycle()
            elif ev_type == "state_transition":
                result["state_transition"] = self.get_state_transitions()
            elif ev_type == "directory_tree":
                result["directory_tree"] = self.get_directory_tree()
        return result

    # ===== 各证据类型获取方法 =====

    def get_patch_facts(self) -> Dict[str, Any]:
        """获取补丁事实摘要。"""
        records = self._by_type.get("patch_fact", [])
        facts: List[Dict[str, Any]] = []
        for r in records:
            payload = r.semantic_payload or {}
            facts.append({
                "fact_type": payload.get("fact_type", ""),
                "label": payload.get("label", ""),
                "attributes": payload.get("attributes", {}),
            })

        if not facts:
            return {"available": False, "message": "当前无 patch_fact 证据"}

        type_widenings = [
            fact.get("attributes", {})
            for fact in facts
            if fact.get("fact_type") == "type_widening"
        ]
        fix_patterns = []
        for fact in facts:
            if fact.get("fact_type") != "fix_patterns":
                continue
            for item in (fact.get("attributes", {}) or {}).get("patterns", []) or []:
                token = str(item).strip()
                if token and token not in fix_patterns:
                    fix_patterns.append(token)

        return {
            "available": True,
            "summary": self._patch_fact_summary(facts),
            "facts": facts,
            "primary_pattern": self._extract_primary_pattern(facts),
            "affected_functions": self._extract_affected_functions(facts),
            "type_widenings": type_widenings[:4],
            "fix_patterns": fix_patterns[:8],
        }

    def get_semantic_slices(self) -> Dict[str, Any]:
        """获取语义切片。"""
        records = self._by_type.get("semantic_slice", [])
        slices = self._merge_semantic_slices(records)
        if not slices:
            return {"available": False, "message": "当前无 semantic_slice 证据"}
        return {
            "available": True,
            "count": len(slices),
            "items": slices[:6],
        }

    def get_dataflow_candidates(self) -> Dict[str, Any]:
        """获取数据流候选。"""
        records = self._by_type.get("dataflow_candidate", [])
        candidates: List[Dict[str, Any]] = []
        for r in records:
            payload = r.semantic_payload or {}
            candidates.append({
                "source": payload.get("source", ""),
                "sink": payload.get("sink", ""),
                "path": payload.get("path", []),
                "summary": payload.get("summary", ""),
                "file": r.scope.file,
                "function": r.scope.function,
                "state_transitions": payload.get("state_transitions", []),
                "source_excerpt": str(payload.get("source_excerpt", "") or ""),
            })
        if not candidates:
            candidates = self._fallback_dataflow_candidates()
        candidates = self._merge_dataflow_candidates(candidates)
        if not candidates:
            return {"available": False, "message": "当前无 dataflow_candidate 证据"}
        return {
            "available": True,
            "count": len(candidates),
            "items": candidates[:8],
        }

    def get_call_edges(self) -> Dict[str, Any]:
        """获取调用链边。"""
        edges: List[str] = []
        summaries: List[str] = []
        for r in self._by_type.get("call_chain", []):
            if r.evidence_slice:
                edges.extend(
                    edge
                    for edge in (r.evidence_slice.call_edges or [])
                    if self._is_call_edge(edge)
                )
                if r.evidence_slice.summary:
                    summaries.append(str(r.evidence_slice.summary))
            payload = r.semantic_payload or {}
            edges.extend(
                edge
                for edge in (str(item).strip() for item in (payload.get("call_edges", []) or []) if str(item).strip())
                if self._is_call_edge(edge)
            )
            summary = payload.get("summary", "")
            if isinstance(summary, list):
                summaries.extend(str(item).strip() for item in summary if str(item).strip())
            elif str(summary).strip():
                summaries.append(str(summary).strip())
        deduped = self._dedupe(edges)[:15]
        if not deduped:
            return {"available": False, "message": "当前无 call_chain 证据"}
        return {
            "available": True,
            "count": len(deduped),
            "edges": deduped,
            "call_targets": self._extract_call_targets(),
            "summaries": self._dedupe(summaries)[:8],
        }

    def get_guards(self) -> Dict[str, Any]:
        """获取守卫条件。"""
        guards: List[Dict[str, Any]] = []
        for r in self._by_type.get("path_guard", []):
            payload = r.semantic_payload or {}
            guard_expr = str(payload.get("guard_expr", "") or "").strip()
            guard_list = [guard_expr] if guard_expr else [
                str(item).strip()
                for item in ((r.evidence_slice.guards if r.evidence_slice else []) or [])
                if str(item).strip()
            ]
            for guard in guard_list[:4]:
                guards.append({
                    "expression": guard,
                    "summary": str(payload.get("summary", "") or ""),
                    "state_before": list(payload.get("state_before", []) or [])[:6],
                    "state_after": list(payload.get("state_after", []) or [])[:6],
                    "tracked_symbols": list(payload.get("tracked_symbols", []) or [])[:6],
                    "file": r.scope.file,
                    "function": r.scope.function,
                })
        if not guards:
            return {"available": False, "message": "当前无 path_guard 证据"}
        return {
            "available": True,
            "items": guards[:10],
        }

    def get_allocation_lifecycle(self) -> Dict[str, Any]:
        """获取分配生命周期（内存漏洞场景）。"""
        records = self._by_type.get("allocation_lifecycle", [])
        lifecycles: List[Dict[str, Any]] = []
        for r in records:
            payload = r.semantic_payload or {}
            lifecycles.append({
                "path": payload.get("path", []),
                "summary": payload.get("summary", ""),
                "operations": list(payload.get("operations", []) or [])[:8],
                "acquisition_ops": list(payload.get("acquisition_ops", []) or [])[:6],
                "release_ops": list(payload.get("release_ops", []) or [])[:6],
                "transition_ops": list(payload.get("transition_ops", []) or [])[:6],
                "state_before": list(payload.get("state_before", []) or [])[:6],
                "state_after": list(payload.get("state_after", []) or [])[:6],
                "file": r.scope.file,
                "function": r.scope.function,
            })
        if not lifecycles:
            return {"available": False, "message": "当前无 allocation_lifecycle 证据"}
        return {
            "available": True,
            "items": lifecycles[:8],
        }

    def get_state_transitions(self) -> Dict[str, Any]:
        """获取状态转换。"""
        transitions: List[Dict[str, Any]] = []
        for r in self._by_type.get("state_transition", []):
            payload = r.semantic_payload or {}
            transitions.append({
                "summary": str(payload.get("summary", "") or ""),
                "state_before": list(payload.get("state_before", []) or [])[:6],
                "state_after": list(payload.get("state_after", []) or [])[:6],
                "tracked_symbols": list(payload.get("tracked_symbols", []) or [])[:6],
                "call_targets": list(payload.get("call_targets", []) or [])[:6],
                "file": r.scope.file,
                "function": r.scope.function,
            })
        if not transitions:
            return {"available": False, "message": "当前无 state_transition 证据"}
        return {
            "available": True,
            "items": transitions[:12],
        }

    def get_directory_tree(self) -> Dict[str, Any]:
        """
        获取目录层级信息 - 项目结构、文件位置、目录层级
        支持模型了解补丁涉及文件的目录上下文
        """
        if not self.project_root:
            return {"available": False, "message": "项目根目录未设置"}

        # 从证据记录中提取涉及的文件
        involved_files: set = set()
        for r in self.bundle.records:
            if r.scope.file:
                involved_files.add(r.scope.file)

        if not involved_files:
            return {"available": False, "message": "当前无可定位的源码文件"}

        tree = self._build_directory_tree(self.project_root, involved_files, max_depth=4)

        return {
            "available": True,
            "project_root": str(self.project_root),
            "involved_files": sorted(list(involved_files))[:20],
            "tree": tree,
        }

    # ===== 辅助方法 =====

    def _extract_slice(self, record: EvidenceRecord) -> Dict[str, Any]:
        """提取语义切片详情。"""
        sl = record.evidence_slice
        scope = record.scope
        payload = record.semantic_payload or {}
        return {
            "id": record.evidence_id,
            "file": scope.file,
            "function": scope.function,
            "summary": sl.summary if sl else "",
            "statements": sl.statements[:8] if sl else [],
            "guards": sl.guards[:4] if sl else [],
            "call_edges": sl.call_edges[:6] if sl else [],
            "api_terms": sl.api_terms[:8] if sl else [],
            "state_transitions": sl.state_transitions[:6] if sl else [],
            "coverage_status": str(payload.get("coverage_status", "") or (sl.coverage_status if sl else "")),
            "tracked_symbols": (
                list(payload.get("widened_variables", []) or [])[:8]
                or list(payload.get("tracked_symbols", []) or [])[:8]
                or (sl.related_symbols[:8] if sl else [])
            ),
            "source_excerpt": self._payload_excerpt(payload) or self._get_source_excerpt(scope.file, scope.function),
        }

    def _merge_semantic_slices(self, records: List[EvidenceRecord]) -> List[Dict[str, Any]]:
        grouped: Dict[tuple[str, str], List[Dict[str, Any]]] = {}
        ordered_keys: List[tuple[str, str]] = []
        for record in records:
            item = self._extract_slice(record)
            key = (str(item.get("file", "") or ""), str(item.get("function", "") or ""))
            if key not in grouped:
                grouped[key] = []
                ordered_keys.append(key)
            grouped[key].append(item)

        merged: List[Dict[str, Any]] = []
        for key in ordered_keys:
            items = grouped.get(key, [])
            if not items:
                continue
            primary = max(items, key=self._semantic_slice_score)
            function_name = str(primary.get("function", "") or "")
            support_summaries = self._dedupe([
                str(item.get("summary", "") or "")
                for item in items
                if str(item.get("summary", "") or "").strip()
                and str(item.get("summary", "") or "").strip() != str(primary.get("summary", "") or "").strip()
            ])[:3]
            merged.append({
                **primary,
                "call_edges": self._dedupe([
                    edge
                    for item in items
                    for edge in (item.get("call_edges", []) or [])
                    if str(edge).strip() and self._call_edge_matches_function(str(edge), function_name)
                ])[:6],
                "api_terms": self._dedupe([
                    token
                    for item in items
                    for token in (item.get("api_terms", []) or [])
                    if str(token).strip()
                ])[:8],
                "state_transitions": self._dedupe([
                    token
                    for item in items
                    for token in (item.get("state_transitions", []) or [])
                    if str(token).strip()
                ])[:6],
                "tracked_symbols": self._dedupe([
                    token
                    for item in items
                    for token in (item.get("tracked_symbols", []) or [])
                    if str(token).strip()
                ])[:8],
                "guards": self._dedupe([
                    token
                    for item in items
                    for token in (item.get("guards", []) or [])
                    if str(token).strip()
                ])[:4],
                "supporting_summaries": support_summaries,
            })
        return merged[:6]

    def _merge_dataflow_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        grouped: Dict[tuple[str, str], List[Dict[str, Any]]] = {}
        ordered_keys: List[tuple[str, str]] = []
        for item in candidates:
            key = (str(item.get("file", "") or ""), str(item.get("function", "") or ""))
            if key not in grouped:
                grouped[key] = []
                ordered_keys.append(key)
            grouped[key].append(item)

        merged: List[Dict[str, Any]] = []
        for key in ordered_keys:
            items = grouped.get(key, [])
            if not items:
                continue
            primary = max(items, key=self._dataflow_candidate_score)
            merged.append({
                **primary,
                "path": self._dedupe([
                    token
                    for item in items
                    for token in (item.get("path", []) or [])
                    if str(token).strip()
                ])[:6],
                "state_transitions": self._dedupe([
                    token
                    for item in items
                    for token in (item.get("state_transitions", []) or [])
                    if str(token).strip()
                ])[:4],
            })
        return merged[:8]

    def _semantic_slice_score(self, item: Dict[str, Any]) -> int:
        coverage = str(item.get("coverage_status", "") or "")
        score = 0
        if coverage == "full":
            score += 5
        elif coverage == "partial":
            score += 3
        score += len(item.get("guards", []) or []) * 3
        score += len(item.get("statements", []) or [])
        score += len(item.get("state_transitions", []) or [])
        score += len(item.get("api_terms", []) or [])
        score += len(item.get("call_edges", []) or [])
        summary = str(item.get("summary", "") or "")
        if summary:
            score += min(len(summary) // 40, 4)
        return score

    def _dataflow_candidate_score(self, item: Dict[str, Any]) -> int:
        score = 0
        score += len(item.get("path", []) or []) * 2
        score += len(item.get("state_transitions", []) or [])
        if str(item.get("sink", "") or "").strip():
            score += 3
        if str(item.get("summary", "") or "").strip():
            score += 2
        if str(item.get("source_excerpt", "") or "").strip():
            score += 1
        return score

    def _get_source_excerpt(self, file_path: str, function_name: str) -> str:
        """获取源码片段。"""
        if not file_path or not self.project_root:
            return ""
        try:
            full_path = self.project_root / file_path
            if not full_path.exists():
                return ""
            lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if function_name:
                for index, line in enumerate(lines):
                    if function_name in line and "(" in line:
                        start = max(0, index - 8)
                        end = min(len(lines), index + 28)
                        excerpt = "\n".join(
                            f"{line_no + 1}: {text}"
                            for line_no, text in enumerate(lines[start:end], start=start)
                        )
                        return excerpt[:2200]
            excerpt = "\n".join(f"{i+1}: {line}" for i, line in enumerate(lines[:40]))
            return excerpt[:2000]
        except Exception:
            return ""

    def _build_directory_tree(
        self,
        root: Path,
        involved_files: set,
        max_depth: int = 4,
    ) -> Dict[str, Any]:
        """构建仅覆盖涉及文件路径的目录树。"""
        tree: Dict[str, Any] = {"name": root.name, "type": "directory", "children": []}
        children_index: Dict[tuple[str, ...], Dict[str, Any]] = {(): tree}

        for raw_path in sorted(involved_files):
            relative = self._normalize_involved_path(root, raw_path)
            parts = [part for part in Path(relative).parts if part not in {"", "."}]
            if not parts:
                continue
            current_key: tuple[str, ...] = ()
            current_node = tree
            for part in parts[:-1]:
                if part.startswith(".") or part in {"__pycache__", "node_modules", ".git", "_codeql_detected_source_root"}:
                    current_node = tree
                    current_key = ()
                    break
                next_key = (*current_key, part)
                node = children_index.get(next_key)
                if node is None:
                    node = {"name": part, "type": "directory", "children": []}
                    current_node.setdefault("children", []).append(node)
                    children_index[next_key] = node
                current_node = node
                current_key = next_key
            else:
                leaf = parts[-1]
                if not leaf.startswith("."):
                    siblings = current_node.setdefault("children", [])
                    if not any(item.get("type") == "file" and item.get("name") == leaf for item in siblings):
                        siblings.append({"name": leaf, "type": "file", "involved": True})
        return tree

    def _extract_call_targets(self) -> List[str]:
        """提取调用目标"""
        targets: List[str] = []
        for r in self._by_type.get("call_chain", []):
            if r.evidence_slice:
                for edge in (r.evidence_slice.call_edges or []):
                    if self._is_call_edge(edge):
                        target = edge.split("->")[1].strip()
                        targets.append(target)
            payload = r.semantic_payload or {}
            for edge in (payload.get("call_edges", []) or []):
                token = str(edge).strip()
                if self._is_call_edge(token):
                    targets.append(token.split("->", 1)[1].strip())
        return self._dedupe(targets)[:10]

    def _extract_primary_pattern(self, facts: List[Dict[str, Any]]) -> str:
        """提取主要漏洞模式。"""
        for fact in facts:
            if fact.get("fact_type") == "vulnerability_patterns":
                patterns = fact.get("attributes", {}).get("patterns", [])
                if patterns:
                    return patterns[0]
        return "unknown"

    def _extract_affected_functions(self, facts: List[Dict[str, Any]]) -> List[str]:
        """提取受影响的函数。"""
        for fact in facts:
            if fact.get("fact_type") == "affected_functions":
                return fact.get("attributes", {}).get("functions", [])
        for fact in facts:
            functions = fact.get("attributes", {}).get("functions", [])
            if functions:
                return functions
        return []

    def _patch_fact_summary(self, facts: List[Dict[str, Any]]) -> str:
        primary_pattern = self._extract_primary_pattern(facts)
        functions = self._extract_affected_functions(facts)
        widenings = [
            fact.get("attributes", {})
            for fact in facts
            if fact.get("fact_type") == "type_widening"
        ]
        summary_parts: List[str] = []
        if primary_pattern and primary_pattern != "unknown":
            summary_parts.append(f"pattern={primary_pattern}")
        if functions:
            summary_parts.append(f"functions={', '.join(map(str, functions[:4]))}")
        if widenings:
            first = widenings[0]
            vars_text = ", ".join(map(str, (first.get("variables", []) or [])[:4]))
            summary_parts.append(
                f"type_widening={first.get('old_type', '')}->{first.get('new_type', '')}({vars_text})"
            )
        return " | ".join(summary_parts) if summary_parts else "补丁事实已收集"

    def _payload_excerpt(self, payload: Dict[str, Any]) -> str:
        excerpt = str(payload.get("source_excerpt", "") or "").strip()
        if excerpt:
            return excerpt[:2200]
        return ""

    def _fallback_dataflow_candidates(self) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        for record in self._by_type.get("semantic_slice", []):
            payload = record.semantic_payload or {}
            tracked = [
                str(item).strip()
                for item in (
                    payload.get("widened_variables", [])
                    or payload.get("tracked_symbols", [])
                    or []
                )
                if str(item).strip()
            ]
            sink_calls = [
                str(item).strip()
                for item in (payload.get("sink_calls", []) or [])
                if str(item).strip()
            ]
            path = [
                str(item).strip()
                for item in (
                    payload.get("arithmetic_operations", [])
                    or payload.get("state_transitions", [])
                    or []
                )
                if str(item).strip()
            ]
            transitions = [
                str(item).strip()
                for item in (
                    payload.get("state_transitions", [])
                    or payload.get("state_after", [])
                    or ((record.evidence_slice.state_transitions if record.evidence_slice else []) or [])
                )
                if str(item).strip()
            ]
            if not tracked and not sink_calls and not path:
                continue
            candidates.append({
                "source": ", ".join(tracked[:4]),
                "sink": ", ".join(sink_calls[:2]),
                "path": path[:6],
                "summary": str(
                    payload.get("summary", "")
                    or (record.evidence_slice.summary if record.evidence_slice else "")
                ),
                "file": record.scope.file,
                "function": record.scope.function,
                "state_transitions": transitions[:4],
                "source_excerpt": self._payload_excerpt(payload),
            })
        return candidates[:8]

    def _relative_to_project(self, path: Path) -> str:
        if not self.project_root:
            return str(path)
        try:
            return str(path.resolve().relative_to(self.project_root.resolve()))
        except Exception:
            return str(path)

    def _normalize_involved_path(self, root: Path, raw_path: str) -> str:
        path = Path(str(raw_path or "").strip())
        if not path.is_absolute():
            return str(path)
        try:
            return str(path.resolve().relative_to(root.resolve()))
        except Exception:
            return path.name

    def _is_call_edge(self, edge: str) -> bool:
        token = str(edge or "").strip()
        if "->" not in token:
            return False
        caller, callee = [part.strip() for part in token.split("->", 1)]
        if not caller or not callee:
            return False
        if any(marker in caller for marker in ("(", ")", ":", ",", ";")):
            return False
        if any(marker in callee for marker in ("(", ")", ":", ",", ";")):
            return False
        return bool(
            re.match(r"^[A-Za-z_][\w]*$", caller)
            and re.match(r"^[A-Za-z_][\w]*$", callee)
        )

    def _call_edge_matches_function(self, edge: str, function_name: str) -> bool:
        token = str(edge or "").strip()
        if not self._is_call_edge(token):
            return False
        if not function_name:
            return True
        caller = token.split("->", 1)[0].strip()
        return caller == function_name

    def _dedupe(self, items: List[str]) -> List[str]:
        """去重。"""
        seen: set = set()
        result: List[str] = []
        for item in items:
            token = str(item).strip()
            if token and token not in seen:
                seen.add(token)
                result.append(token)
        return result
