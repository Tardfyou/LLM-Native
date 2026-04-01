"""
PATCHWEAVER vulnerability mechanism graph.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .evidence_types import MechanismNodeKind, PatchFact


@dataclass(frozen=True)
class MechanismNode:
    """A node in the vulnerability mechanism graph."""

    node_id: str
    kind: str
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind,
            "label": self.label,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class MechanismEdge:
    """A relation in the vulnerability mechanism graph."""

    source: str
    target: str
    relation: str
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class VulnerabilityMechanismGraph:
    """Patch-scoped graph used by the planner."""

    summary: str
    primary_patterns: List[str] = field(default_factory=list)
    nodes: List[MechanismNode] = field(default_factory=list)
    edges: List[MechanismEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "primary_patterns": list(self.primary_patterns),
            "nodes": [item.to_dict() for item in self.nodes],
            "edges": [item.to_dict() for item in self.edges],
        }


class MechanismGraphBuilder:
    """Build a lightweight VMG from patch metadata."""

    def build(
        self,
        patch_facts: List[PatchFact],
        patch_analysis: Dict[str, Any],
    ) -> VulnerabilityMechanismGraph:
        nodes: List[MechanismNode] = []
        edges: List[MechanismEdge] = []
        seen_functions = set()
        seen_guards = set()
        seen_fixes = set()
        seen_metadata = set()

        patch_node = MechanismNode(
            node_id="patch",
            kind=MechanismNodeKind.PATCH.value,
            label="Security patch",
            attributes={
                "changed_files": patch_analysis.get("files_changed", []),
            },
        )
        nodes.append(patch_node)

        file_details = patch_analysis.get("file_details", []) or []
        for index, item in enumerate(file_details):
            file_node_id = f"file_{index}"
            nodes.append(
                MechanismNode(
                    node_id=file_node_id,
                    kind=MechanismNodeKind.FILE.value,
                    label=item.get("path", f"file_{index}"),
                    attributes=item,
                )
            )
            edges.append(MechanismEdge("patch", file_node_id, "touches", 0.95))

        patterns = patch_analysis.get("vulnerability_patterns", []) or []
        for index, pattern in enumerate(patterns):
            pattern_type = pattern.get("type", "unknown")
            pattern_node_id = f"pattern_{index}"
            nodes.append(
                MechanismNode(
                    node_id=pattern_node_id,
                    kind=MechanismNodeKind.PATTERN.value,
                    label=pattern_type,
                    attributes=pattern,
                )
            )
            edges.append(MechanismEdge("patch", pattern_node_id, "indicates", 0.9))

            for func_name in pattern.get("affected_functions", []) or []:
                if not func_name or func_name in seen_functions:
                    continue
                seen_functions.add(func_name)
                func_node_id = f"func_{len(seen_functions)}"
                nodes.append(
                    MechanismNode(
                        node_id=func_node_id,
                        kind=MechanismNodeKind.FUNCTION.value,
                        label=func_name,
                        attributes={"function": func_name},
                    )
                )
                edges.append(MechanismEdge(pattern_node_id, func_node_id, "affects", 0.75))

            for guard in pattern.get("trigger_conditions", []) or []:
                if not guard or guard in seen_guards:
                    continue
                seen_guards.add(guard)
                guard_node_id = f"guard_{len(seen_guards)}"
                nodes.append(
                    MechanismNode(
                        node_id=guard_node_id,
                        kind=MechanismNodeKind.GUARD.value,
                        label=guard,
                        attributes={"condition": guard},
                    )
                )
                edges.append(MechanismEdge(pattern_node_id, guard_node_id, "requires", 0.7))

        cross_file_deps = patch_analysis.get("cross_file_dependencies", []) or []
        for index, dep in enumerate(cross_file_deps):
            dep_node_id = f"dep_{index}"
            nodes.append(
                MechanismNode(
                    node_id=dep_node_id,
                    kind=MechanismNodeKind.DEPENDENCY.value,
                    label=f"{dep.get('from', '')} -> {dep.get('to', '')}",
                    attributes=dep,
                )
            )
            edges.append(MechanismEdge("patch", dep_node_id, "spans", 0.8))

        strategy = patch_analysis.get("detection_strategy", {}) or {}
        if strategy:
            nodes.append(
                MechanismNode(
                    node_id="strategy",
                    kind=MechanismNodeKind.STRATEGY.value,
                    label=strategy.get("primary_pattern", "strategy"),
                    attributes=strategy,
                )
            )
            edges.append(MechanismEdge("patch", "strategy", "guides", 0.85))

        for fact in patch_facts:
            if fact.fact_type == "affected_functions":
                for func_name in fact.attributes.get("functions", []) or []:
                    token = str(func_name).strip()
                    if not token or token in seen_functions:
                        continue
                    seen_functions.add(token)
                    func_node_id = f"func_{len(seen_functions)}"
                    nodes.append(
                        MechanismNode(
                            node_id=func_node_id,
                            kind=MechanismNodeKind.FUNCTION.value,
                            label=token,
                            attributes={"function": token, "source": "patch_fact"},
                        )
                    )
                    edges.append(MechanismEdge("patch", func_node_id, "focuses_on", 0.82))

            elif fact.fact_type == "added_guards":
                for guard in fact.attributes.get("guards", []) or []:
                    token = str(guard).strip()
                    if not token or token in seen_guards:
                        continue
                    seen_guards.add(token)
                    guard_node_id = f"guard_{len(seen_guards)}"
                    nodes.append(
                        MechanismNode(
                            node_id=guard_node_id,
                            kind=MechanismNodeKind.GUARD.value,
                            label=token,
                            attributes={"condition": token, "source": "patch_fact"},
                        )
                    )
                    edges.append(MechanismEdge("patch", guard_node_id, "adds_guard", 0.84))

            elif fact.fact_type in {"fix_patterns", "added_api_calls"}:
                key = "patterns" if fact.fact_type == "fix_patterns" else "apis"
                for item in fact.attributes.get(key, []) or []:
                    token = str(item).strip()
                    if not token or token in seen_fixes:
                        continue
                    seen_fixes.add(token)
                    fix_node_id = f"fix_{len(seen_fixes)}"
                    nodes.append(
                        MechanismNode(
                            node_id=fix_node_id,
                            kind=MechanismNodeKind.FIX.value,
                            label=token,
                            attributes={"kind": fact.fact_type, "value": token},
                        )
                    )
                    edges.append(MechanismEdge("patch", fix_node_id, "introduces", 0.8))

            elif fact.fact_type == "patch_intent":
                summary = str(fact.attributes.get("summary", "") or "").strip()
                subject = str(fact.attributes.get("subject", "") or "").strip()
                label = subject or summary
                if label and label not in seen_metadata:
                    seen_metadata.add(label)
                    nodes.append(
                        MechanismNode(
                            node_id="intent_0",
                            kind=MechanismNodeKind.INTENT.value,
                            label=label,
                            attributes=fact.attributes,
                        )
                    )
                    edges.append(MechanismEdge("patch", "intent_0", "describes", 0.78))

            elif fact.fact_type == "external_references":
                for cve in fact.attributes.get("cves", []) or []:
                    token = str(cve).strip().upper()
                    if not token or token in seen_metadata:
                        continue
                    seen_metadata.add(token)
                    node_id = f"cve_{len([item for item in seen_metadata if item.startswith('CVE-')])}"
                    nodes.append(
                        MechanismNode(
                            node_id=node_id,
                            kind=MechanismNodeKind.CVE.value,
                            label=token,
                            attributes={"reference": token},
                        )
                    )
                    edges.append(MechanismEdge("patch", node_id, "references", 0.82))
                for cwe in fact.attributes.get("cwes", []) or []:
                    token = str(cwe).strip().upper()
                    if not token or token in seen_metadata:
                        continue
                    seen_metadata.add(token)
                    node_id = f"cwe_{len([item for item in seen_metadata if item.startswith('CWE-')])}"
                    nodes.append(
                        MechanismNode(
                            node_id=node_id,
                            kind=MechanismNodeKind.CWE.value,
                            label=token,
                            attributes={"reference": token},
                        )
                    )
                    edges.append(MechanismEdge("patch", node_id, "maps_to", 0.8))
                issues = [str(item).strip() for item in (fact.attributes.get("issues", []) or []) if str(item).strip()]
                if issues:
                    label = ", ".join(issues[:3])
                    if label not in seen_metadata:
                        seen_metadata.add(label)
                        nodes.append(
                            MechanismNode(
                                node_id="commit_0",
                                kind=MechanismNodeKind.COMMIT.value,
                                label=label,
                                attributes={"issues": issues[:6]},
                            )
                        )
                        edges.append(MechanismEdge("patch", "commit_0", "tracked_by", 0.72))

        summary = self._summarize(patch_facts, patch_analysis)
        primary_patterns = [
            item.get("type", "unknown")
            for item in patterns
            if item.get("type")
        ]

        return VulnerabilityMechanismGraph(
            summary=summary,
            primary_patterns=primary_patterns,
            nodes=nodes,
            edges=edges,
        )

    def _summarize(
        self,
        patch_facts: List[PatchFact],
        patch_analysis: Dict[str, Any],
    ) -> str:
        primary = (patch_analysis.get("detection_strategy", {}) or {}).get("primary_pattern", "unknown")
        changed_files = len(patch_analysis.get("files_changed", []) or [])
        added_guards = 0
        removed_risky_ops = 0
        fix_patterns = 0
        metadata_refs = 0
        for fact in patch_facts:
            if fact.fact_type == "added_guards":
                added_guards = len(fact.attributes.get("guards", []) or [])
            elif fact.fact_type == "removed_risky_operations":
                removed_risky_ops = len(fact.attributes.get("operations", []) or [])
            elif fact.fact_type == "fix_patterns":
                fix_patterns = len(fact.attributes.get("patterns", []) or [])
            elif fact.fact_type == "external_references":
                metadata_refs += len(fact.attributes.get("cves", []) or [])
                metadata_refs += len(fact.attributes.get("cwes", []) or [])
                metadata_refs += len(fact.attributes.get("issues", []) or [])

        return (
            f"Patch suggests {primary} semantics across {changed_files} file(s); "
            f"added guards={added_guards}, removed risky operations={removed_risky_ops}, "
            f"fix patterns={fix_patterns}, metadata refs={metadata_refs}."
        )
