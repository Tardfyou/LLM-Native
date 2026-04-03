# Refine 阶段证据系统重构方案

> 版本: 2.0
> 日期: 2026-04-02
> 范围: 仅影响 Refine 阶段，Bootstrap 完全隔离

---

## 1. 改动范围

### 1.1 不改动的部分

| 组件 | 说明 |
|------|------|
| **Bootstrap 阶段** | 完全不动，保持现有逻辑 |
| **结构化候选生成** | 保持 `build_structural_candidate` 不变 |
| **Generate 阶段** | 本次不涉及 |
| **证据采集层** | 保留，但剔除低价值类型 |

### 1.2 改动的部分

| 组件 | 改动内容 |
|------|----------|
| **证据类型** | 剔除 `METADATA_HINT`、`DIAGNOSTIC` 等低价值类型 |
| **Refine Validate 阶段** | 调整验证顺序 |
| **Refine Decide 阶段** | 引入证据查询工具 + 策略建议 |
| **Prompt 模板** | 语法错误时指示最小修复 |

---

## 2. 证据系统精简

### 2.1 保留的证据类型 (7种)

```python
class EvidenceType(str, Enum):
    # 高价值 - 核心语义
    PATCH_FACT = "patch_fact"                    # 补丁事实
    SEMANTIC_SLICE = "semantic_slice"            # 语义切片
    DATAFLOW_CANDIDATE = "dataflow_candidate"    # 数据流候选
    CALL_CHAIN = "call_chain"                    # 调用链
    
    # 高价值 - 状态与生命周期
    ALLOCATION_LIFECYCLE = "allocation_lifecycle"  # 分配生命周期
    STATE_TRANSITION = "state_transition"          # 状态转换
    PATH_GUARD = "path_guard"                      # 路径守卫
    
    # 中价值 - 必要
    CONTEXT_SUMMARY = "context_summary"          # 上下文摘要
    VALIDATION_OUTCOME = "validation_outcome"    # 验证结果
```

### 2.2 剔除的证据类型 (4种)

| 类型 | 剔除原因 |
|------|----------|
| `METADATA_HINT` | 价值低，信息可从其他渠道获取 |
| `DIAGNOSTIC` | 与 `VALIDATION_OUTCOME` 重复 |
| `API_CONTRACT` | 信息可从 `SEMANTIC_SLICE.api_terms` 获取 |
| `CONTEXT_SUMMARY` (部分) | 简化，只保留项目级摘要 |

### 2.3 EvidencePlanner 精简

```python
# v2/src/core/evidence_planner.py

class EvidencePlanner:
    """精简后的证据规划器"""

    def plan(self, ...):
        requirements = {}
        
        # 必需证据
        self._require(requirements, EvidenceType.PATCH_FACT, priority=100)
        self._require(requirements, EvidenceType.SEMANTIC_SLICE, priority=90)
        
        # 根据模式按需添加
        if strategy.get("data_flow_tracking"):
            self._require(requirements, EvidenceType.DATAFLOW_CANDIDATE, priority=85)
            self._require(requirements, EvidenceType.CALL_CHAIN, priority=75)
        
        if pattern_types & {"use_after_free", "double_free"}:
            self._require(requirements, EvidenceType.ALLOCATION_LIFECYCLE, priority=88)
            self._require(requirements, EvidenceType.STATE_TRANSITION, priority=82)
        
        if pattern_types & {"buffer_overflow", "null_dereference"}:
            self._require(requirements, EvidenceType.PATH_GUARD, priority=85)
        
        # 不再添加 METADATA_HINT、DIAGNOSTIC 等
        ...
```

---

## 3. Refine 单轮工作流调整

### 3.1 当前工作流

```
CSA:  bootstrap → decide ⇄ apply_patch → validate (LSP → compile → review) → finish
CodeQL: bootstrap → decide ⇄ apply_patch → validate (analyse → review) → finish
```

### 3.2 调整后工作流

```
CSA:    bootstrap → decide ⇄ apply_patch → validate (LSP → review → compile) → finish
CodeQL: bootstrap → decide ⇄ apply_patch → validate (review → analyse) → finish
```

### 3.3 多轮精炼迭代（大轮概念）

**核心设计**：一轮完整精炼通过后，可进入下一轮继续增强，每轮基于前一轮产出代码继续操作。

```
Round 1: bootstrap → decide → apply_patch → validate(通过) →
            ↓
        轮次判断（配置控制）
            ↓
Round 2: 加载Round1代码 → decide（含退化判断）→ apply_patch → validate →
            ↓
        继续或终止
```

**关键机制**：

| 机制 | 说明 |
|------|------|
| **轮次配置** | `config.refine.max_rounds: 1`（默认只跑1轮） |
| **代码继承** | 每轮开始时加载前一轮产出的代码 |
| **退化判断** | 模型在prompt中自行判断结构和语义是否退化 |
| **语义评估** | 模型自行判断当前语义能力是否已足够好 |

### 3.4 轮次控制实现

```python
# v2/src/refine/agent.py

class LangChainRefinementAgent:
    def __init__(self, config: Optional[Dict[str, Any]] = None, ...):
        self.config = config or {}
        # 大轮迭代次数（默认1轮）
        refine_config = self.config.get("refine", {}) or {}
        self.max_rounds = max(1, min(int(refine_config.get("max_rounds", 1) or 1), 3))

    def run(self, request: RefinementRequest) -> RefinementResult:
        """支持多轮精炼"""
        round_num = 0
        current_request = request
        previous_code = ""
        previous_review_metadata = {}

        while round_num < self.max_rounds:
            round_num += 1
            self._emit_progress("round_started", round=round_num, max_rounds=self.max_rounds)

            # 执行一轮精炼
            result = self._run_single_round(
                request=current_request,
                round_num=round_num,
                previous_code=previous_code,
                previous_review_metadata=previous_review_metadata,
            )

            if not result.success:
                return result

            # 保存本轮产出，供下一轮使用
            previous_code = result.checker_code
            previous_review_metadata = result.metadata.get("last_review", {})

            # 准备下一轮请求
            if round_num < self.max_rounds:
                current_request = RefinementRequest(
                    target_path=request.target_path,
                    patch_path=request.patch_path,
                    analyzer=request.analyzer,
                    initial_code=previous_code,  # 本轮产出作为下一轮起点
                    max_iterations=request.max_iterations,
                    extra_context={
                        "previous_round": round_num,
                        "previous_review_metadata": previous_review_metadata,
                    },
                )

        return result
```

### 3.5 Decide Prompt 多轮适配

```markdown
# v2/prompts/refine/decide.md

你正在执行精炼工作流，当前是第 {{ROUND_NUM}} 轮精炼（共 {{MAX_ROUNDS}} 轮）。

{{TASK_PROMPT}}

## 前一轮信息

{{PREVIOUS_ROUND_CONTEXT}}

## 当前工作副本

```text
{{ARTIFACT_TEXT}}
```

## 补丁原文件

```diff
{{PATCH_TEXT}}
```

## 约束规则

**退化禁止（强制约束）**：
- 本轮修改**不得**导致代码结构退化（可读性下降、模块化变差、函数拆分混乱）
- 本轮修改**不得**导致语义能力退化（数据流追踪、状态检查、守卫覆盖能力减弱）
- 如果前一轮语义能力已足够好，本轮**只能**做结构优化，禁止削弱语义

**语义足够判断**：
- 如果当前代码已捕获补丁体现的核心漏洞机制（如完整的数据流路径、正确的守卫条件），视为语义足够
- 语义足够时，本轮只需优化结构（改善可读性、减少冗余）
- 语义不足时，继续增强语义检测能力

**增量修改**：
- 基于当前工作副本做最小修改
- 禁止整文件重写
- 禁止删除已有的有效语义检查逻辑

## CoT思考引导

**Step 1: 评估前一轮状态**
- 前一轮代码的结构质量如何？
- 前一轮的语义能力是否已捕获补丁核心机制？

**Step 2: 判断本轮目标**
- 如果语义足够 → 结构优化（改善可读性、模块化）
- 如果语义不足 → 语义增强（添加数据流、状态检查、守卫）
- 如果发现退化 → 必须修复退化问题

**Step 3: 检查修改约束**
- 本轮修改是否会删除已有语义检查？→ 禁止
- 本轮修改是否会导致结构混乱？→ 禁止

**Step 4: 产出修复**
- 增量修改，最小改动原则

## 输出格式

```json
{
  "cot_analysis": {
    "previous_semantics": "足够 / 不足",
    "regression_risk": "无风险 / 有退化风险需避免",
    "strategy": "结构优化 / 语义增强 / 保持现状"
  },
  "action": "apply_patch | finish",
  "summary": "一句话说明本轮意图",
  "patch": "unified diff",
  "resulting_content": "修复后完整文本"
}
```

注意：如果评估后发现当前代码已足够好且无需任何改进，直接输出 `finish`。
```

### 3.6 配置文件示例

```yaml
# v2/config/config.yaml

refine:
  # 大轮迭代次数（1-3轮，默认1轮）
  max_rounds: 1

  # 单轮内部小循环次数（现有配置）
  max_iterations: 20
```

```python
# v2/src/refine/agent.py

def validate(state: RefinementWorkflowState) -> RefinementWorkflowState:
    notes = list(state.get("context_notes", []) or [])

    if request.analyzer == "csa":
        # CSA: LSP → Review → Compile
        # Step 1: LSP 快速检查
        lsp = toolkit.lsp_validate_artifact(check_level="quick")
        notes.append(self._make_note("lsp_validate_artifact", lsp, limit=2000))
        if self._is_error_text(lsp):
            return {
                "context_notes": notes,
                "route": "decide",
                "failure_type": "syntax_error",  # 新增：标记失败类型
            }

        # Step 2: 结构审查 (移到 compile 之前)
        if self.artifact_review_required:
            review_result = toolkit.review_artifact()
            notes.append(self._make_note("review_artifact", review_result, limit=2200))
            if self._is_error_text(review_result):
                return {
                    "context_notes": notes,
                    "route": "decide",
                    "failure_type": "review_failure",  # 新增
                }

        # Step 3: 最终编译
        compile_result = toolkit.compile_artifact()
        notes.append(self._make_note("compile_artifact", compile_result, limit=2200))
        if self._is_error_text(compile_result):
            return {
                "context_notes": notes,
                "route": "decide",
                "failure_type": "compile_failure",  # 新增
            }

    else:
        # CodeQL: Review → Analyse
        # Step 1: 结构审查 (移到 analyse 之前)
        if self.artifact_review_required:
            review_result = toolkit.review_artifact()
            notes.append(self._make_note("review_artifact", review_result, limit=2200))
            if self._is_error_text(review_result):
                return {
                    "context_notes": notes,
                    "route": "decide",
                    "failure_type": "review_failure",
                }

        # Step 2: 执行查询
        analyze_result = toolkit.analyze_artifact()
        notes.append(self._make_note("analyze_artifact", analyze_result, limit=2200))
        if self._is_error_text(analyze_result):
            return {
                "context_notes": notes,
                "route": "decide",
                "failure_type": "analyze_failure",
            }

    return {
        "context_notes": notes,
        "route": "finish",
        "final_message": "当前候选已通过验证。",
    }
```

### 3.4 验证顺序调整原因

| 分析器 | 调整 | 原因 |
|--------|------|------|
| CSA | compile 移到最后 | 编译成本高，先确保 LSP 和 review 通过 |
| CodeQL | analyse 移到最后 | 执行查询成本高，先确保 review 通过 |

---

## 4. 证据查询工具 (仅用于 Decide 阶段)

### 4.1 EvidenceQueryTools

位置: `v2/src/evidence/evidence_tools.py`

**设计原则**：工具提供证据查询能力，模型根据CoT分析结果**主动选择**需要哪些证据类型，不做强制检查。

```python
"""
证据查询工具 - 供 Refine Decide 阶段模型主动选择证据类型
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from .evidence_schema import EvidenceRecord, EvidenceBundle


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

    def _build_indices(self):
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
        result = {}
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
        """获取补丁事实摘要"""
        records = self._by_type.get("patch_fact", [])
        facts = []
        for r in records:
            payload = r.semantic_payload or {}
            facts.append({
                "fact_type": payload.get("fact_type", ""),
                "label": payload.get("label", ""),
                "attributes": payload.get("attributes", {}),
            })

        if not facts:
            return {"available": False, "message": "当前无 patch_fact 证据"}

        return {
            "available": True,
            "facts": facts,
            "primary_pattern": self._extract_primary_pattern(facts),
            "affected_functions": self._extract_affected_functions(facts),
        }

    def get_semantic_slices(self) -> List[Dict[str, Any]]:
        """
        获取语义切片 - 补丁涉及的上下文代码文件对应代码切片信息
        包含：源码片段、函数上下文、调用目标、守卫条件等
        """
        records = self._by_type.get("semantic_slice", [])
        slices = []
        for r in records:
            slice_data = self._extract_slice(r)
            slices.append(slice_data)
        return slices

    def get_dataflow_candidates(self) -> List[Dict[str, Any]]:
        """获取数据流候选"""
        records = self._by_type.get("dataflow_candidate", [])
        candidates = []
        for r in records:
            payload = r.semantic_payload or {}
            candidates.append({
                "source": payload.get("source", ""),
                "sink": payload.get("sink", ""),
                "path": payload.get("path", []),
            })
        return candidates[:10]

    def get_call_edges(self) -> Dict[str, Any]:
        """获取调用链边"""
        edges = []
        for r in self.bundle.records:
            if r.evidence_slice:
                edges.extend(r.evidence_slice.call_edges or [])
        return {
            "edges": self._dedupe(edges)[:15],
            "call_targets": self._extract_call_targets(),
        }

    def get_guards(self) -> List[Dict[str, Any]]:
        """获取守卫条件"""
        guards = []
        for r in self.bundle.records:
            if r.evidence_slice:
                guard_list = r.evidence_slice.guards or []
                for guard in guard_list:
                    guards.append({
                        "expression": guard,
                        "file": r.scope.file,
                        "function": r.scope.function,
                    })
        return guards[:10]

    def get_allocation_lifecycle(self) -> List[Dict[str, Any]]:
        """获取分配生命周期（内存漏洞场景）"""
        records = self._by_type.get("allocation_lifecycle", [])
        lifecycles = []
        for r in records:
            payload = r.semantic_payload or {}
            lifecycles.append({
                "allocation_site": payload.get("allocation_site", ""),
                "deallocation_site": payload.get("deallocation_site", ""),
                "variable": payload.get("variable", ""),
                "path": payload.get("path", []),
            })
        return lifecycles[:8]

    def get_state_transitions(self) -> List[Dict[str, Any]]:
        """获取状态转换"""
        transitions = []
        for r in self.bundle.records:
            if r.evidence_slice:
                st_list = r.evidence_slice.state_transitions or []
                for st in st_list:
                    transitions.append({
                        "transition": st,
                        "file": r.scope.file,
                        "function": r.scope.function,
                    })
        return transitions[:10]

    def get_directory_tree(self) -> Dict[str, Any]:
        """
        获取目录层级信息 - 项目结构、文件位置、目录层级
        支持模型了解补丁涉及文件的目录上下文
        """
        if not self.project_root:
            return {"available": False, "message": "项目根目录未设置"}

        # 从证据记录中提取涉及的文件
        involved_files = set()
        for r in self.bundle.records:
            if r.scope.file:
                involved_files.add(r.scope.file)

        # 构建目录树
        tree = self._build_directory_tree(self.project_root, involved_files, max_depth=4)

        return {
            "available": True,
            "project_root": str(self.project_root),
            "involved_files": list(involved_files)[:20],
            "tree": tree,
        }

    # ===== 辅助方法 =====

    def _extract_slice(self, record: EvidenceRecord) -> Dict[str, Any]:
        """提取语义切片详情"""
        sl = record.evidence_slice
        scope = record.scope
        return {
            "id": record.evidence_id,
            "file": scope.file,
            "function": scope.function,
            "summary": sl.summary if sl else "",
            "statements": sl.statements[:8] if sl else [],
            "guards": sl.guards[:4] if sl else [],
            "call_edges": sl.call_edges[:6] if sl else [],
            "api_terms": sl.api_terms[:8] if sl else [],
            "source_excerpt": self._get_source_excerpt(scope.file, scope.function),
        }

    def _get_source_excerpt(self, file_path: str, function_name: str) -> str:
        """获取源码片段"""
        if not file_path or not self.project_root:
            return ""
        try:
            full_path = self.project_root / file_path
            if not full_path.exists():
                return ""
            lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            # 简化：返回文件前30行作为上下文
            excerpt = "\n".join(f"{i+1}: {line}" for i, line in enumerate(lines[:30]))
            return excerpt[:2000]
        except Exception:
            return ""

    def _build_directory_tree(
        self,
        root: Path,
        involved_files: set,
        max_depth: int = 4,
    ) -> Dict[str, Any]:
        """构建目录树，高亮涉及的文件"""
        tree = {"name": root.name, "type": "directory", "children": []}
        involved_basenames = {Path(f).name for f in involved_files}

        try:
            items = sorted(root.iterdir(), key=lambda x: (not x.is_dir(), x.name))
        except Exception:
            return tree

        for item in items[:30]:  # 限制数量
            if item.name.startswith(".") or item.name in {"__pycache__", "node_modules", ".git"}:
                continue

            if item.is_dir():
                if max_depth > 0:
                    child_tree = self._build_directory_tree(item, involved_files, max_depth - 1)
                    tree["children"].append(child_tree)
            else:
                is_involved = item.name in involved_basenames or str(item.relative_to(root)) in involved_files
                tree["children"].append({
                    "name": item.name,
                    "type": "file",
                    "involved": is_involved,
                })

        return tree

    def _extract_call_targets(self) -> List[str]:
        """提取调用目标"""
        targets = []
        for r in self.bundle.records:
            if r.evidence_slice:
                for edge in (r.evidence_slice.call_edges or []):
                    if "->" in edge:
                        target = edge.split("->")[1].strip()
                        targets.append(target)
        return self._dedupe(targets)[:10]

    def _extract_primary_pattern(self, facts: List[Dict[str, Any]]) -> str:
        for fact in facts:
            if fact.get("fact_type") == "vulnerability_patterns":
                patterns = fact.get("attributes", {}).get("patterns", [])
                if patterns:
                    return patterns[0]
        return "unknown"

    def _extract_affected_functions(self, facts: List[Dict[str, Any]]) -> List[str]:
        for fact in facts:
            if fact.get("fact_type") == "affected_functions":
                return fact.get("attributes", {}).get("functions", [])
        return []

    def _dedupe(self, items: List[str]) -> List[str]:
        seen = set()
        result = []
        for item in items:
            token = str(item).strip()
            if token and token not in seen:
                seen.add(token)
                result.append(token)
        return result
```

### 4.2 Decide 阶段流程

**核心流程**：Bootstrap注入上下文 → 模型CoT思考 → 判断是否需要证据 → 选择证据类型或产出修复

```python
# v2/src/refine/agent.py

def decide(state: RefinementWorkflowState) -> RefinementWorkflowState:
    """
    Decide 阶段职责：
    1. 提供原始代码和补丁原文件作为上下文（必需，由bootstrap注入prompt）
    2. CoT引导模型思考当前检测实现的不足
    3. 模型主动判断是否需要补充证据，从清单中选择证据类型
    4. 产出修复方案或请求证据补充
    """
    model_turns = int(state.get("model_turns", 0) or 0) + 1
    if model_turns > request.max_iterations:
        return {"route": "finish", "error_message": "达到最大轮次"}

    # 获取上下文（bootstrap已注入）
    artifact_text = state.get("artifact_text", "")    # 原始代码
    patch_text = state.get("patch_text", "")          # 补丁原文件
    failure_type = state.get("failure_type", "")
    context_notes = list(state.get("context_notes", []) or [])
    previously_collected_evidence = state.get("collected_evidence", {})

    # 证据工具（提供证据类型清单和获取方法）
    from ..evidence.evidence_tools import EvidenceQueryTools
    evidence_tools = EvidenceQueryTools(evidence_bundle, project_root)

    # 构建决策prompt（包含证据类型清单）
    prompt = self._render_decision_prompt(
        task_prompt=task_prompt,
        artifact_text=artifact_text,
        patch_text=patch_text,
        context_notes=context_notes,
        iteration=model_turns,
        available_evidence_types=evidence_tools.list_available_evidence_types(),
        previously_collected_evidence=previously_collected_evidence,
    )

    # LLM 决策（含CoT思考过程）
    response = self._invoke_decision_model(messages)
    decision = self._parse_decision(response)

    # 处理 request_evidence action
    if decision.get("action") == "request_evidence":
        evidence_types = decision.get("evidence_types", [])
        collected = evidence_tools.get_evidence_by_types(evidence_types)
        return {
            "collected_evidence": collected,
            "model_turns": model_turns,
            "route": "decide",  # 收集证据后重新进入 decide
        }

    return {
        "decision": decision,
        "model_turns": model_turns,
        "route": self._route_from_decision(decision),
    }
```

**关键点**：
- `artifact_text` 和 `patch_text` 是**必需上下文**，直接注入prompt
- 模型通过CoT分析后，**主动判断**是否需要补充证据
- 模型从证据类型清单中**自主选择**需要的证据类型
- 证据收集后重新进入 decide，模型获得补充上下文继续分析

### 4.3 Bootstrap 失败与上下文注入

**Bootstrap 行为分析**：

```python
# v2/src/refine/agent.py bootstrap 函数

def bootstrap(state: RefinementWorkflowState) -> RefinementWorkflowState:
    # 读取原始代码（必需上下文）
    artifact_text = toolkit.read_artifact()
    if self._is_error_text(artifact_text):
        return {
            "route": "finish",  # 无法读取工件，直接终止
            "error_message": artifact_text.removeprefix("ERROR: ").strip(),
        }

    # 读取补丁原文件（必需上下文）
    patch_text = toolkit.read_patch()
    if self._is_error_text(patch_text):
        return {
            "route": "finish",  # 无法读取补丁，直接终止
            "error_message": patch_text.removeprefix("ERROR: ").strip(),
        }

    # 尝试结构化候选（可选）
    structural_candidate = self._try_structural_candidate(...)

    # 成功注入上下文，进入 decide
    return {
        "artifact_text": artifact_text,   # ← 必需：注入prompt
        "patch_text": patch_text,         # ← 必需：注入prompt
        "route": "decide",                # ← 进入LLM精炼
    }
```

| 场景 | artifact_text | patch_text | route | 模型行为 |
|-----|---------------|------------|-------|---------|
| 两者都成功读取 | 有内容 | 有内容 | `decide` | 进入LLM精炼，基于上下文CoT分析 |
| read_artifact失败 | 空 | - | `finish` | 直接终止（无工件可修） |
| read_patch失败 | 有内容 | 空 | `finish` | 直接终止（无补丁参考） |
| structural_candidate失败 | 有内容 | 有内容 | `decide` | 正常进入LLM精炼 |

**结论**：
- 原始代码和补丁原文件是**必需上下文**，读取失败会终止流程
- 这两个上下文直接注入到Decide prompt，供模型CoT分析使用
- 模型基于上下文分析不足后，**主动选择**收集额外证据

---

## 5. Prompt 模板更新

### 5.1 Decide Prompt 模板

位置: `v2/prompts/refine/decide.md`

```markdown
你正在执行一个受控的 detector/query 精炼工作流。

**目标文件类型**：
- CSA：Clang-18 插件式 checker 源文件（.cpp），编译为 .so 动态插件
- CodeQL：.ql 查询文件，用于 CodeQL 数据库分析

{{TASK_PROMPT}}

当前轮次: {{ITERATION}} / {{MAX_ITERATIONS}}

系统会在你提交 `apply_patch` 后自动执行本地验证与结构审查。
不要请求编译、LSP、CodeQL 分析或 review；这些由工作流自动完成。

当前工作副本全文：
```text
{{ARTIFACT_TEXT}}
```

补丁全文：
```diff
{{PATCH_TEXT}}
```

附加上下文：
{{CONTEXT_NOTES}}

---

## 可选证据类型清单

当你觉得需要补充上下文信息时，可以从以下证据类型中选择需要获取的项：

| 证据类型 | 说明 | 适用场景 |
|---------|------|---------|
| `patch_fact` | 补丁事实摘要 | 需要理解补丁修复的漏洞模式、涉及的函数和文件 |
| `semantic_slice` | 语义切片（代码片段） | 需要补丁涉及的上下文代码文件对应代码切片信息 |
| `dataflow_candidate` | 数据流候选 | 需要理解数据如何在变量/API间流动 |
| `call_chain` | 调用链 | 需要理解函数调用关系、callee/caller |
| `path_guard` | 路径守卫条件 | 需要理解条件检查、边界守卫 |
| `allocation_lifecycle` | 分配生命周期 | 内存漏洞场景（use_after_free, double_free） |
| `state_transition` | 状态转换 | 状态机、锁状态、引用计数场景 |
| `directory_tree` | 目录层级信息 | 需要了解项目结构、文件位置、目录层级 |

**使用方式**：
- 在 `cot_analysis.evidence_needed` 中列出需要的证据类型
- 系统会在下一轮提供对应证据内容
- 不需要重复请求已提供的证据类型

---

## 目标文件结构约束

### CSA Checker (Clang-18 插件式)

必备头文件：
```cpp
#include "clang/AST/Expr.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <memory>
```

必备导出（插件注册）：
```cpp
extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<YourChecker>("custom.YourChecker", "Description", "");
}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_VERSION_STRING;
```

Clang-18 API 约束（禁止使用不存在的 API）：
- ❌ `Stmt::getParent()` / `Stmt::getParentStmt()` - 不存在
- ❌ `Expr::getParent()` - 不存在
- ❌ `StringRef::lower().str()` - `lower()` 已返回 `std::string`
- ✅ `StringRef::starts_with()` (不是 `startswith`)
- ✅ `State->get<MapName>(key)` 返回 `const Value*` 指针，不是 `std::optional`
- ✅ 获取函数名：`Call.getCalleeIdentifier()->getName()`
- ✅ 获取参数：`Call.getArgSVal(index)` 或 `Call.getArgExpr(index)`
- ✅ 获取内存区域：`SVal::getAsRegion()`
- ✅ 生成报告节点：`C.generateNonFatalErrorNode()` 或 `C.generateErrorNode()`

不要虚构 CSA API，不要使用未列出的方法签名。

### CodeQL Query (.ql)

约束：
- 量词变量必须在同一 `exists()` 参数列表中声明
- 不要引用外层兄弟量词里的局部变量
- 沿用骨架里的 exact CodeQL API 名称和类型名
- 不要臆造不存在的 CodeQL API、类型、成员方法

禁止改写：
- `SizeofExprOperator` → `sizeof(...)` ❌
- `GuardCondition.ensuresLt` → `ComparisonOperation` ❌
- `getTarget()` → 其他伪 API ❌
- `bbDominates` → 自定义支配关系 ❌

---

## 决策规则

**修改原则**：
- 只输出 unified diff（增量修改），禁止整文件重写
- 首轮只修改与补丁机制直接相关的函数体，不改文件头/include/注册代码

**CSA 特殊约束**：
- 不要引入无法确认签名的 API；不要臆造 `ProgramState`/`CheckerContext`/`SVal` 辅助方法
- 如果 patch 用显式长度检查加 bounded API 替换 risky API，围绕 removed risky API 与新增 guard/barrier 做精炼
- 如果 review 指出 helper 是 callee-only direct report，优先删除该 dispatch/helper
- 不要重复声明同名局部变量；不要提交带 `for now`/`placeholder` 等占位说明的补丁

**语义增强判断**：
- 如果当前实现仍主要依赖 API 名称、`strlen/strnlen`、变量名启发式，这还不算完成
- 要么推进到真实的 destination capacity / guard / region / state 语义，要么停止并保留基线

**失败修复策略**：
- 先从附加上下文定位最后一个失败工具的报错
- LSP/compile/parse 失败时，只修 API/参数/类型/量词作用域/include，不扩大语义改动
- patch 应用失败时，缩小 hunk 范围并严格对齐当前工作副本

**终止条件**：
- 通过质量门且无更强语义改进方案 → 输出 `finish`
- 不提交只改注释/排版/变量名的等价补丁

---

## CoT思考引导

**Step 1: 分析当前状态**
- 当前实现是否已捕获补丁核心漏洞机制？
- 是否缺少关键上下文信息（代码切片、调用链、守卫条件等）？

**Step 2: 判断下一步行动**
- 如果缺少上下文 → 选择需要的证据类型，输出 `request_evidence`
- 如果上下文足够且有修复方案 → 输出 `apply_patch`
- 如果已通过质量门且无需改进 → 输出 `finish`

**Step 3: 检查修改约束（apply_patch时）**
- 只输出 unified diff（增量修改），禁止整文件重写
- 首轮只修改与补丁机制直接相关的函数体

---

只输出一个 JSON 对象，不要添加解释，不要使用 Markdown 代码块。

JSON schema:
{
  "cot_analysis": {
    "current_semantics": "足够 / 不足",
    "missing_context": "描述缺少的上下文信息",
    "evidence_needed": ["证据类型列表，如 patch_fact, semantic_slice, call_chain 等"],
    "strategy": "语义增强 / 结构优化 / 保持现状"
  },
  "action": "request_evidence" | "apply_patch" | "finish",
  "summary": "一句话说明本轮意图",
  "evidence_types": "当 action 为 request_evidence 时填写需要的证据类型数组；否则为空数组",
  "patch": "当 action 为 apply_patch 时填写 unified diff；否则为空字符串",
  "resulting_content": "可选。当 patch 应用失败且需要 fallback 时填写完整文本；其他情况留空字符串"
}
```

**关键设计决策**：

| 问题 | 解决方案 |
|------|----------|
| 为什么同时要求 patch 和 resulting_content？ | `patch` 是主要的增量修改方式；`resulting_content` 仅作为 fallback，当 patch 应用失败且改动量≤65%时合成新 patch |
| resulting_content 何时使用？ | 仅当 patch 应用失败时作为恢复手段，平时留空 |
| 为什么要明确目标文件类型？ | CSA 和 CodeQL 有完全不同的语法和 API 约束，必须在 prompt 中明确 |
| CSA 为什么要强调 Clang-18？ | 旧版 API（如 `startswith`、`Stmt::getParent`）在 Clang-18 中不存在或签名变化 |

---

### 5.2 证据上下文窗口参数

以下参数控制证据采集时的上下文窗口大小：

| 参数 | 文件位置 | 原值 | 新值 | 说明 |
|------|----------|------|------|------|
| `radius` | `evidence/collectors/artifact_extractor.py:120,610` | 8 | **12** | 源码窗口半径（anchor_line 前后各 N 行） |
| `target_files` | `evidence/collectors/csa_path.py:323` | [:6] | **[:8]** | 采集的目标文件上限 |
| `target_files` | `evidence/collectors/codeql_flow.py:179` | [:6] | **[:8]** | CodeQL 采集的目标文件上限 |
| `call_boundary` | `evidence/collectors/csa_path.py:370` | [:4] | **[:6]** | 放入 evidence_slice 的文件数 |
| `call_boundary` | `evidence/collectors/codeql_flow.py:200` | [:4] | **[:6]** | CodeQL slice 的 call_boundary |

**效果**：
- 源码窗口从 **17 行** 扩展到 **25 行**（前后各 12 行）
- target_files 从 **6 个** 增加到 **8 个**
- call_boundary 从 **4 个** 增加到 **6 个**

### 5.2 CoT解析与证据收集

```python
def _parse_and_collect_evidence(self, decision: Dict[str, Any]) -> Dict[str, Any]:
    """解析CoT决策，执行证据收集"""
    cot = decision.get("cot_analysis", {})
    evidence_strategy = cot.get("evidence_strategy", [])

    # 模型主动选择的证据收集
    collected = {}
    for tool_name in evidence_strategy:
        if tool_name == "get_patch_facts":
            collected["patch_facts"] = self.evidence_tools.get_patch_facts()
        elif tool_name == "get_semantic_slices":
            collected["slices"] = self.evidence_tools.get_semantic_slices()
        elif tool_name == "get_guards":
            collected["guards"] = self.evidence_tools.get_guards()
        # ... 其他工具

    return {
        "collected_evidence": collected,
        "cot_analysis": cot,
    }
```

### 5.2 诊断指导渲染

```python
def _render_diagnosis_guidance(self, diagnosis: Dict[str, Any]) -> str:
    """渲染诊断指导"""
    lines = []
    
    strategy = diagnosis.get("strategy", "general")
    priority = diagnosis.get("priority", "medium")
    guidance = diagnosis.get("guidance", [])

    lines.append(f"### 策略: {strategy} (优先级: {priority})")
    lines.append("")
    for g in guidance:
        lines.append(g)
    
    return "\n".join(lines)
```

### 5.3 语法错误最小修复指导

当 `failure_type == "syntax_error"` 时，生成以下指导：

```markdown
### 策略: fix_syntax (优先级: high)

【语法错误修复 - 最小修改原则】
- 只修改报错的具体行，不要改动其他代码
- 不要重构、不要优化、不要添加新功能
- 需要修复的位置: 行 42, 行 56
- 修复后立即验证，不要批量修改多处
- 如果不确定修复方案，先查看错误行的上下文

【语法错误示例】
错误行: 42:15: error: expected ';' after expression
修复: 在该行末尾添加分号，不要改动其他内容

【禁止事项】
- ❌ 不要重写整个函数
- ❌ 不要修改变量命名
- ❌ 不要添加注释或文档
- ❌ 不要优化代码结构
```

---

## 6. 完整工作流图

```
┌─────────────────────────────────────────────────────────────────────┐
│ Bootstrap (不修改)                                                   │
│   ├── 读取工件和补丁                                                 │
│   ├── 尝试结构化候选 (可选)                                          │
│   │   └── 验证候选 → 直接 validate                                   │
│   └── 进入 decide                                                    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Decide 循环 (证据系统改进)                                           │
│   ├── EvidenceQueryTools.diagnose_failure()                         │
│   ├── 根据失败类型生成针对性指导                                     │
│   │   ├── syntax_error → 最小修复指导                               │
│   │   ├── review_failure → 结构修复指导                             │
│   │   └── compile/analyze_failure → 语义修复指导                    │
│   ├── LLM 决策                                                      │
│   └── 执行动作 (apply_patch / read_reference / search_knowledge)    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Validate (顺序调整)                                                  │
│                                                                     │
│   CSA:  LSP → Review → Compile                                      │
│   CodeQL: Review → Analyse                                          │
│                                                                     │
│   失败时返回 failure_type 供 Decide 使用                            │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                               Finish
```

---

## 7. 文件变更清单

### 7.1 新增文件

```
v2/src/evidence/evidence_tools.py          # 证据查询工具
```

### 7.2 修改文件

```
v2/src/core/evidence_types.py              # 精简证据类型枚举
v2/src/core/evidence_planner.py            # 精简证据规划逻辑
v2/src/refine/agent.py                     # validate 顺序 + decide 使用证据工具
v2/prompts/refine/agent/decide.md          # 更新 prompt 模板
```

### 7.3 不修改文件

```
v2/src/refine/agent.py (bootstrap 函数)   # 完全不动
v2/src/refine/csa_structural.py            # 不动
v2/src/refine/codeql_structural.py         # 不动
v2/src/generate/*                          # 本次不涉及
```

---

## 8. 测试用例

### 8.1 验证顺序测试

```python
def test_csa_validate_order():
    """CSA 验证顺序: LSP → Review → Compile"""
    agent = LangChainRefinementAgent(...)
    # Mock: LSP 失败
    with mock.patch("toolkit.lsp_validate_artifact", return_value="ERROR: ..."):
        result = agent._build_workflow(...).validate(state)
        assert result["route"] == "decide"
        assert result["failure_type"] == "syntax_error"

    # Mock: LSP 通过，Review 失败
    with mock.patch("toolkit.lsp_validate_artifact", return_value="OK"):
        with mock.patch("toolkit.review_artifact", return_value="ERROR: ..."):
            result = agent._build_workflow(...).validate(state)
            assert result["route"] == "decide"
            assert result["failure_type"] == "review_failure"

    # Mock: LSP 和 Review 通过，Compile 失败
    with mock.patch("toolkit.lsp_validate_artifact", return_value="OK"):
        with mock.patch("toolkit.review_artifact", return_value="OK"):
            with mock.patch("toolkit.compile_artifact", return_value="ERROR: ..."):
                result = agent._build_workflow(...).validate(state)
                assert result["route"] == "decide"
                assert result["failure_type"] == "compile_failure"


def test_codeql_validate_order():
    """CodeQL 验证顺序: Review → Analyse"""
    agent = LangChainRefinementAgent(...)
    # Mock: Review 失败
    with mock.patch("toolkit.review_artifact", return_value="ERROR: ..."):
        result = agent._build_workflow(...).validate(state)
        assert result["route"] == "decide"
        assert result["failure_type"] == "review_failure"


def test_syntax_error_guidance():
    """语法错误生成最小修复指导"""
    tools = EvidenceQueryTools(bundle)
    diagnosis = tools.diagnose_failure("syntax_error", [
        "42:15: error: expected ';'",
        "56:8: error: undeclared identifier",
    ])

    assert diagnosis["strategy"] == "fix_syntax"
    assert "最小修改" in str(diagnosis["guidance"])
    assert "行 42" in str(diagnosis["guidance"])
```

### 8.2 CoT分析与多轮精炼测试

```python
def test_cot_analysis_flow():
    """测试CoT分析流程"""
    decision = {
        "cot_analysis": {
            "previous_semantics": "不足",
            "regression_risk": "无风险",
            "strategy": "语义增强",
        },
        "action": "apply_patch",
    }

    agent = LangChainRefinementAgent(...)
    result = agent._parse_and_collect_evidence(decision)

    assert result["cot_analysis"]["strategy"] == "语义增强"


def test_model_decides_structure_only():
    """模型判断语义足够，只做结构优化"""
    decision = {
        "cot_analysis": {
            "previous_semantics": "足够",
            "regression_risk": "无风险",
            "strategy": "结构优化",
        },
        "action": "apply_patch",
        "patch": "...",  # 只改结构，不改语义
    }

    # 模型自行判断语义足够，本轮只优化结构
    assert decision["cot_analysis"]["strategy"] == "结构优化"


def test_model_detects_regression_risk():
    """模型检测到退化风险，避免退化修改"""
    decision = {
        "cot_analysis": {
            "previous_semantics": "足够",
            "regression_risk": "有退化风险需避免",
            "strategy": "保持现状",
        },
        "action": "finish",  # 模型选择不修改
    }

    # 模型判断有退化风险，选择保持现状
    assert decision["action"] == "finish"


def test_multi_round_refinement():
    """多轮精炼迭代"""
    config = {"refine": {"max_rounds": 2}}
    agent = LangChainRefinementAgent(config=config)

    request = RefinementRequest(
        target_path="/path/to/checker.cpp",
        patch_path="/path/to/patch.diff",
        analyzer="csa",
    )

    result = agent.run(request)

    # 验证跑了2轮
    assert result.metadata.get("rounds_completed") == 2


def test_round_code_inheritance():
    """每轮继承前一轮产出代码"""
    agent = LangChainRefinementAgent(config={"refine": {"max_rounds": 2}})

    # Round 1 产出
    round1_code = "int main() { /* enhanced */ }"
    round1_review = {"metadata": {"semantic_score": 0.7}}

    # Round 2 应基于 Round 1 代码继续
    request_round2 = RefinementRequest(
        initial_code=round1_code,  # 前一轮产出
        extra_context={"previous_review_metadata": round1_review},
    )

    # 验证 Round 2 prompt 包含前一轮信息
    prompt = agent._render_decision_prompt(
        ...,
        previous_round_context="Round 1: semantic_score=0.7",
    )
    assert "Round 1" in prompt


def test_max_rounds_config():
    """轮次配置生效"""
    # 配置只跑1轮
    config = {"refine": {"max_rounds": 1}}
    agent = LangChainRefinementAgent(config=config)
    assert agent.max_rounds == 1

    # 配置跑3轮
    config = {"refine": {"max_rounds": 3}}
    agent = LangChainRefinementAgent(config=config)
    assert agent.max_rounds == 3


def test_bootstrap_injects_context():
    """Bootstrap成功注入必需上下文"""
    agent = LangChainRefinementAgent(...)

    with mock.patch("toolkit.read_artifact", return_value="int main() {}"):
        with mock.patch("toolkit.read_patch", return_value="--- a/file.c\n+++ b/file.c"):
            result = agent.bootstrap({})

            assert result["route"] == "decide"
            assert result["artifact_text"] == "int main() {}"


def test_evidence_tools_available():
    """证据工具可供模型选择"""
    bundle = EvidenceBundle(records=[])
    tools = EvidenceQueryTools(bundle)

    available = tools.list_available_tools()
    assert "get_patch_facts" in str(available)
```

---

## 9. 实施步骤

```
Step 1: 精简证据类型
├── 修改 evidence_types.py
├── 修改 evidence_planner.py
└── 测试证据采集

Step 2: 调整 Validate 顺序
├── 修改 refine/agent.py validate 函数
├── 添加 failure_type 返回
└── 测试验证流程

Step 3: 实现证据查询工具
├── 新建 evidence_tools.py
├── 实现 get_patch_facts() - 可选工具
├── 实现 get_semantic_slices/guards/call_edges 等
├── 实现 list_available_tools() - 工具清单
└── 单元测试

Step 4: 设计CoT引导Prompt
├── 更新 decide.md prompt模板
│   ├── 约束规则：退化禁止、语义足够判断
│   ├── Step 1: 评估前一轮状态
│   ├── Step 2: 判断本轮目标
│   ├── Step 3: 检查修改约束
│   └── Step 4: 产出修复
├── 实现 _parse_and_collect_evidence() 解析CoT决策
└── 集成测试

Step 5: 实现多轮精炼迭代
├── 添加 max_rounds 配置（默认1轮）
├── 修改 run() 函数支持多轮循环
├── 每轮结束时保存代码和review结果
├── 下一轮加载前一轮产出作为起点
├── 在prompt中注入前一轮信息
└── 验证轮次控制

Step 6: 验证上下文注入
├── 确认 bootstrap 将 artifact_text/patch_text 注入 prompt
├── 确认读取失败时直接 finish
├── 运行现有测试
└── 验证修复循环不受影响
```

**核心流程验证**：

```
Round N:
    Bootstrap（加载前一轮代码，如有）
        ↓
    artifact_text + patch_text 注入 prompt
        ↓
    Decide: CoT分析
        ├── 退化判断（模型自行）
        ├── 语义评估（模型自行）
        ├── 选择策略（结构优化/语义增强）
        └── 产出修复
        ↓
    Apply_patch → Validate
        ↓
    [通过?] → 保存本轮产出 → 轮次判断 → [继续/终止]
```

---

## 变更历史

| 版本 | 日期 | 变更内容 |
|------|------|----------|
| 2.0 | 2026-04-02 | 重构：聚焦 refine，隔离 bootstrap，调整验证顺序 |
| 2.1 | 2026-04-03 | 修正：原始代码和补丁作为上下文注入，模型通过CoT主动选择证据收集 |
| 2.2 | 2026-04-03 | 新增：多轮精炼迭代（大轮概念），轮次配置化，退化约束和语义评估放提示词 |
| 2.3 | 2026-04-03 | 改进：decide.md 明确目标文件类型，添加 CSA/CodeQL 结构约束，简化 JSON schema（resulting_content 改为可选 fallback） |
| 2.4 | 2026-04-03 | 核心改进：证据系统改为提供可选证据类型清单，模型主动选择取证类型；移除文件操作/RAG检索引导；新增 directory_tree 证据类型支持目录层级信息；semantic_slice 支持代码切片信息；JSON schema 新增 request_evidence action |