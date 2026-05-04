"""
补丁分析工具 - 深度分析补丁文件

提供:
- PatchAnalysisTool: 分析补丁，提取漏洞模式
"""

import re
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path

from ..agent.tools import Tool, ToolResult
from ..prompts import PromptRepository
from ..utils.vulnerability_taxonomy import (
    normalize_vulnerability_type,
)
from ..llm.usage import normalize_usage


@dataclass
class FileChange:
    """文件变更"""
    old_path: str
    new_path: str
    is_rename: bool = False
    is_new: bool = False
    is_deleted: bool = False
    additions: List[str] = field(default_factory=list)
    deletions: List[str] = field(default_factory=list)
    hunks: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class VulnerabilityPattern:
    """漏洞模式"""
    pattern_type: str  # e.g., "buffer_overflow", "null_deref", "use_after_free"
    description: str
    trigger_conditions: List[str]
    fix_patterns: List[str]
    affected_functions: List[str]
    cross_file: bool = False


class PatchAnalysisTool(Tool):
    """补丁分析工具"""

    def __init__(
        self,
        llm_client=None,
        llm_config: Optional[Dict[str, Any]] = None,
        prompt_config: Optional[Dict[str, Any]] = None,
        enable_llm: bool = True,
    ):
        self._llm_client = llm_client
        self._llm_config = llm_config or {}
        self._prompt_config = prompt_config or {}
        self._prompt_repository = PromptRepository(config=prompt_config or {})
        self._enable_llm = enable_llm

    COMMON_LIB_FUNCTIONS = {
        "abort",
        "asprintf",
        "atoi",
        "calloc",
        "close",
        "fclose",
        "fgets",
        "fopen",
        "fprintf",
        "free",
        "fwrite",
        "gets",
        "malloc",
        "memcmp",
        "memcpy",
        "memmove",
        "memset",
        "open",
        "printf",
        "realloc",
        "read",
        "snprintf",
        "sprintf",
        "strcat",
        "strcmp",
        "strcpy",
        "strlen",
        "strncmp",
        "strncpy",
        "write",
    }

    @property
    def name(self) -> str:
        return "analyze_patch"

    @property
    def description(self) -> str:
        return """深度分析补丁文件，提取漏洞模式。

功能:
- 解析补丁文件格式（git diff / unified diff）
- 识别变更的文件和代码行
- 提取漏洞模式和触发条件
- 识别跨文件依赖
- 生成检测策略建议

返回结构化的分析结果，帮助生成更精确的检测器。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "patch_content": {
                    "type": "string",
                    "description": "补丁文件内容"
                },
                "patch_path": {
                    "type": "string",
                    "description": "补丁文件路径（与patch_content二选一）"
                },
                "analysis_depth": {
                    "type": "string",
                    "enum": ["basic", "standard", "deep"],
                    "default": "standard",
                    "description": "分析深度: basic=基础, standard=标准, deep=深度"
                }
            },
            "oneOf": [
                {"required": ["patch_content"]},
                {"required": ["patch_path"]}
            ]
        }

    def execute(
        self,
        patch_content: str = None,
        patch_path: str = None,
        analysis_depth: str = "standard"
    ) -> ToolResult:
        """
        执行补丁分析

        Args:
            patch_content: 补丁内容
            patch_path: 补丁文件路径
            analysis_depth: 分析深度

        Returns:
            ToolResult
        """
        try:
            # 获取补丁内容
            if patch_content is None:
                if patch_path is None:
                    return ToolResult(
                        success=False,
                        output="",
                        error="必须提供patch_content或patch_path"
                    )

                path = Path(patch_path)
                if not path.exists():
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"补丁文件不存在: {patch_path}"
                    )

                with open(path, 'r', encoding='utf-8') as f:
                    patch_content = f.read()

            # 解析补丁
            file_changes = self._parse_patch(patch_content)

            if not file_changes:
                return ToolResult(
                    success=False,
                    output="",
                    error="无法解析补丁文件，可能格式不正确"
                )

            structural_result = self._build_structural_analysis(file_changes)
            llm_result: Dict[str, Any] = {}
            if analysis_depth in {"standard", "deep"}:
                llm_result = self._analyze_with_llm(
                    patch_content=patch_content,
                    patch_path=patch_path or "",
                    file_changes=file_changes,
                    structural_result=structural_result,
                    analysis_depth=analysis_depth,
                )

            result = self._finalize_analysis(
                structural_result=structural_result,
                llm_result=llm_result,
            )

            # 格式化输出
            output = self._format_analysis_result(result)

            return ToolResult(
                success=True,
                output=output,
                metadata=result
            )

        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=f"补丁分析失败: {str(e)}"
            )

    def _build_structural_analysis(self, file_changes: List[FileChange]) -> Dict[str, Any]:
        """Build structural patch facts without rule-based vulnerability classification."""
        cross_file_deps = self._analyze_cross_file_dependencies(file_changes)
        deleted_lines = [line for fc in file_changes for line in fc.deletions]
        added_lines = [line for fc in file_changes for line in fc.additions]
        affected_functions = self._extract_affected_functions(
            file_changes=file_changes,
            deleted_lines=deleted_lines,
            added_lines=added_lines,
        )
        patch_semantics = self._collect_patch_semantics(file_changes)
        return {
            "files_changed": [fc.new_path for fc in file_changes],
            "file_details": [
                {
                    "path": fc.new_path,
                    "additions": len(fc.additions),
                    "deletions": len(fc.deletions),
                    "hunks": len(fc.hunks),
                }
                for fc in file_changes
            ],
            "vulnerability_patterns": [],
            "cross_file_dependencies": cross_file_deps,
            "detection_strategy": {
                "primary_pattern": "unknown",
                "check_types": [],
                "entry_points": list(affected_functions),
                "data_flow_tracking": False,
                "cross_file_analysis": len(file_changes) > 1 or len(cross_file_deps) > 0,
                "suggestions": [],
            },
            "checker_name_suggestion": "PatchFocusedChecker",
            "affected_functions": affected_functions,
            "key_functions": list(affected_functions),
            "patch_semantics": patch_semantics,
            "analysis_backend": "structural",
            "analysis_confidence": 0.0,
        }

    def _analyze_with_llm(
        self,
        patch_content: str,
        patch_path: str,
        file_changes: List[FileChange],
        structural_result: Dict[str, Any],
        analysis_depth: str,
    ) -> Dict[str, Any]:
        """Ask the model for a structured patch analysis and normalize the response."""
        client = self._get_llm_client()
        if client is None:
            return {}

        prompt = self._build_llm_prompt(
            patch_content=patch_content,
            patch_path=patch_path,
            file_changes=file_changes,
            structural_result=structural_result,
            analysis_depth=analysis_depth,
        )
        response = client.generate(
            prompt=prompt,
            temperature=self._analysis_temperature(),
            max_tokens=16384,
        )
        if not response:
            return {}

        usage = normalize_usage(
            getattr(client, "get_last_usage", lambda: {})(),
        )
        payload = self._parse_llm_json(response)
        if not payload:
            return {}
        normalized = self._normalize_llm_result(payload, structural_result)
        if normalized:
            normalized["analysis_backend"] = "llm"
            normalized["llm_usage"] = usage
        return normalized

    def _get_llm_client(self):
        if not self._enable_llm:
            return None
        if self._llm_client is not None:
            return self._llm_client
        if not self._llm_config:
            return None
        try:
            from ..llm import create_llm_client

            self._llm_client = create_llm_client(self._llm_config)
            return self._llm_client
        except Exception:
            return None

    def _analysis_temperature(self) -> float:
        agent_config = (
            self._prompt_config.get("agent", {})
            if isinstance(self._prompt_config.get("agent", {}), dict)
            else {}
        )
        temperature = agent_config.get("generate_patch_analysis_temperature")
        if temperature is None:
            temperature = agent_config.get("generate_temperature")
        if temperature is None:
            temperature = agent_config.get("temperature")
        if temperature is None:
            temperature = 0.1
        return float(temperature)

    def _build_llm_prompt(
        self,
        patch_content: str,
        patch_path: str,
        file_changes: List[FileChange],
        structural_result: Dict[str, Any],
        analysis_depth: str,
    ) -> str:
        summary = {
            "patch_path": patch_path,
            "files_changed": structural_result.get("files_changed", []),
            "file_details": structural_result.get("file_details", []),
            "affected_functions": structural_result.get("affected_functions", []),
            "key_functions": structural_result.get("key_functions", []),
            "cross_file_dependencies": structural_result.get("cross_file_dependencies", []),
            "patch_semantics": structural_result.get("patch_semantics", {}),
        }
        schema = {
            "primary_pattern": "canonical vulnerability type used by project taxonomy or unknown",
            "confidence": "float in [0,1]",
            "analysis_rationale": "short explanation tied to concrete patch evidence",
            "vulnerability_patterns": [
                {
                    "type": "canonical vulnerability type; omit uncertain candidates instead of inventing a wrong type",
                    "description": "short explanation",
                    "trigger_conditions": ["..."],
                    "fix_patterns": ["..."],
                    "affected_functions": ["..."],
                    "cross_file": True,
                    "evidence_lines": ["specific patch evidence"],
                }
            ],
            "detection_strategy": {
                "primary_pattern": "same as primary_pattern",
                "check_types": ["..."],
                "entry_points": ["..."],
                "data_flow_tracking": True,
                "cross_file_analysis": True,
                "suggestions": ["..."],
            },
            "checker_name_suggestion": "UseAfterFreeChecker",
            "affected_functions": ["..."],
            "key_functions": ["..."],
        }

        return self._prompt_repository.render(
            "analysis.patch",
            {
                "ANALYSIS_DEPTH": analysis_depth,
                "PATCH_PATH": patch_path,
                "STRUCTURAL_SUMMARY_JSON": json.dumps(summary, ensure_ascii=False, indent=2),
                "REQUIRED_SCHEMA_JSON": json.dumps(schema, ensure_ascii=False, indent=2),
                "PATCH_EXCERPT": patch_content,
            },
            strict=True,
        )

    def _parse_llm_json(self, response: str) -> Dict[str, Any]:
        text = str(response or "").strip()
        if not text:
            return {}
        if "```" in text:
            fenced = re.findall(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
            if fenced:
                text = fenced[0].strip()
        try:
            payload = json.loads(text)
            return payload if isinstance(payload, dict) else {}
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if not match:
                return {}
            try:
                payload = json.loads(match.group(0))
                return payload if isinstance(payload, dict) else {}
            except json.JSONDecodeError:
                return {}

    def _normalize_llm_result(
        self,
        payload: Dict[str, Any],
        structural_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        normalized_patterns: List[Dict[str, Any]] = []
        seen_types = set()
        for item in payload.get("vulnerability_patterns", []) or []:
            if not isinstance(item, dict):
                continue
            vuln_type = normalize_vulnerability_type(str(item.get("type", "") or ""), default="unknown")
            if not vuln_type or vuln_type == "unknown" or vuln_type in seen_types:
                continue
            seen_types.add(vuln_type)
            normalized_patterns.append({
                "type": vuln_type,
                "description": str(item.get("description", "") or self._describe_vulnerability(vuln_type)),
                "trigger_conditions": self._clean_string_list(item.get("trigger_conditions", []), limit=8),
                "fix_patterns": self._clean_string_list(item.get("fix_patterns", []), limit=8),
                "affected_functions": self._filter_function_tokens(
                    self._clean_string_list(item.get("affected_functions", []), limit=12)
                ),
                "cross_file": bool(item.get("cross_file", False)),
                "source": "llm",
                "confidence": self._clamp_confidence(item.get("confidence", payload.get("confidence", 0.75))),
                "evidence_lines": self._clean_string_list(item.get("evidence_lines", []), limit=6),
            })

        detection_strategy = payload.get("detection_strategy", {}) or {}
        primary_pattern = normalize_vulnerability_type(
            str(payload.get("primary_pattern", "") or detection_strategy.get("primary_pattern", "") or ""),
            default="unknown",
        )
        affected_functions = self._filter_function_tokens(
            self._clean_string_list(
                payload.get("affected_functions", []),
                limit=16,
            )
        )
        if not affected_functions:
            for pattern in normalized_patterns:
                affected_functions.extend(pattern.get("affected_functions", []))
        affected_functions = self._filter_function_tokens(affected_functions)

        llm_strategy = {
            "primary_pattern": primary_pattern,
            "check_types": self._normalize_type_list(
                detection_strategy.get("check_types", []) or [item.get("type", "") for item in normalized_patterns]
            ),
            "entry_points": self._filter_function_tokens(
                self._clean_string_list(detection_strategy.get("entry_points", []), limit=16)
                or list(affected_functions)
            ),
            "data_flow_tracking": bool(detection_strategy.get("data_flow_tracking", False)),
            "cross_file_analysis": bool(
                detection_strategy.get("cross_file_analysis", False)
                or structural_result.get("cross_file_dependencies")
            ),
            "suggestions": self._clean_string_list(detection_strategy.get("suggestions", []), limit=8),
        }

        checker_name = str(payload.get("checker_name_suggestion", "") or "").strip()
        if not checker_name:
            checker_name = self._fallback_checker_name(primary_pattern)

        cross_file_deps = structural_result.get("cross_file_dependencies", []) or []
        return {
            "files_changed": list(structural_result.get("files_changed", [])),
            "file_details": list(structural_result.get("file_details", [])),
            "vulnerability_patterns": normalized_patterns,
            "cross_file_dependencies": cross_file_deps,
            "detection_strategy": llm_strategy,
            "checker_name_suggestion": checker_name,
            "affected_functions": affected_functions,
            "key_functions": self._filter_function_tokens(
                self._clean_string_list(payload.get("key_functions", []), limit=16) or list(affected_functions)
            ),
            "analysis_rationale": str(payload.get("analysis_rationale", "") or ""),
            "analysis_confidence": self._clamp_confidence(payload.get("confidence", 0.75)),
            "patch_semantics": dict(structural_result.get("patch_semantics", {}) or {}),
        }

    def _finalize_analysis(
        self,
        structural_result: Dict[str, Any],
        llm_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        result = json.loads(json.dumps(structural_result))
        if llm_result:
            result.update(llm_result)

        strategy = dict(result.get("detection_strategy", {}) or {})
        primary_pattern = normalize_vulnerability_type(
            str(strategy.get("primary_pattern", "") or ""),
            default="unknown",
        )
        strategy["primary_pattern"] = primary_pattern
        if not strategy.get("check_types"):
            strategy["check_types"] = self._normalize_type_list(
                [item.get("type", "") for item in (result.get("vulnerability_patterns", []) or [])]
            )
        if not strategy.get("entry_points"):
            strategy["entry_points"] = list(result.get("affected_functions", []) or [])
        strategy["cross_file_analysis"] = bool(
            strategy.get("cross_file_analysis", False)
            or result.get("cross_file_dependencies")
        )
        result["detection_strategy"] = strategy

        if not result.get("checker_name_suggestion"):
            result["checker_name_suggestion"] = self._fallback_checker_name(primary_pattern)
        result["affected_functions"] = self._filter_function_tokens(result.get("affected_functions", []) or [])
        result["key_functions"] = self._filter_function_tokens(
            list(result.get("key_functions", []) or []) or list(result.get("affected_functions", []) or [])
        )
        result["analysis_backend"] = result.get("analysis_backend", "structural")
        result["analysis_confidence"] = self._clamp_confidence(result.get("analysis_confidence", 0.0))
        result["patch_semantics"] = dict(result.get("patch_semantics", {}) or {})
        return result

    def _normalize_type_list(self, items: List[str]) -> List[str]:
        normalized: List[str] = []
        seen = set()
        for item in items:
            canonical = normalize_vulnerability_type(str(item or ""), default="")
            if not canonical or canonical in seen:
                continue
            seen.add(canonical)
            normalized.append(canonical)
        return normalized

    def _clean_string_list(self, items: List[Any], limit: int = 12) -> List[str]:
        cleaned: List[str] = []
        seen = set()
        for item in items or []:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            cleaned.append(text)
            if len(cleaned) >= limit:
                break
        return cleaned

    def _clamp_confidence(self, value: Any) -> float:
        try:
            conf = float(value)
        except Exception:
            conf = 0.0
        return max(0.0, min(1.0, conf))

    def _suggest_checker_name_from_type(self, vuln_type: str) -> str:
        pattern = VulnerabilityPattern(
            pattern_type=normalize_vulnerability_type(vuln_type, default="unknown") or "unknown",
            description="",
            trigger_conditions=[],
            fix_patterns=[],
            affected_functions=[],
        )
        return self._suggest_checker_name([pattern])

    def _fallback_checker_name(self, vuln_type: str) -> str:
        suggested = self._suggest_checker_name_from_type(vuln_type)
        if suggested == "CustomChecker":
            return "PatchFocusedChecker"
        return suggested

    def _collect_patch_semantics(self, file_changes: List[FileChange]) -> Dict[str, Any]:
        additions = [line.strip() for fc in file_changes for line in fc.additions if str(line).strip()]
        deletions = [line.strip() for fc in file_changes for line in fc.deletions if str(line).strip()]
        added_guards = [
            line for line in additions
            if re.search(r"\b(if|switch|while)\s*\(", line)
        ]
        state_resets = [
            line for line in additions
            if re.search(r"=\s*(?:NULL|nullptr|0|-1)\s*;", line)
        ]
        lifecycle_changes = [
            line for line in additions
            if any(token in line for token in ("find_", "_id", "destroy_", "release_", "free(", "delete "))
        ]
        return {
            "added_guards": added_guards[:8],
            "added_api_calls": self._extract_called_functions(additions)[:12],
            "removed_api_calls": self._extract_called_functions(deletions)[:12],
            "state_resets": state_resets[:8],
            "lifecycle_changes": lifecycle_changes[:8],
        }

    def _parse_patch(self, patch_content: str) -> List[FileChange]:
        """解析补丁内容"""
        file_changes = []

        # 分割补丁为文件块
        file_pattern = re.compile(
            r'^diff --git a/(.*?) b/(.*?)$',
            re.MULTILINE
        )

        # 查找所有文件
        matches = list(file_pattern.finditer(patch_content))

        for i, match in enumerate(matches):
            old_path = match.group(1)
            new_path = match.group(2)

            # 获取这个文件块的内容
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(patch_content)
            file_block = patch_content[start:end]

            # 解析变更
            file_change = FileChange(
                old_path=old_path,
                new_path=new_path,
                is_rename=(old_path != new_path),
                is_new=old_path == "/dev/null",
                is_deleted=new_path == "/dev/null"
            )

            # 解析hunks
            hunk_pattern = re.compile(
                r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$',
                re.MULTILINE
            )

            for hunk_match in hunk_pattern.finditer(file_block):
                hunk_start = hunk_match.end()
                next_hunk = hunk_pattern.search(file_block, hunk_start)
                hunk_end = next_hunk.start() if next_hunk else len(file_block)

                hunk_content = file_block[hunk_start:hunk_end]

                additions = []
                deletions = []

                for line in hunk_content.split('\n'):
                    if line.startswith('+') and not line.startswith('+++'):
                        additions.append(line[1:])
                    elif line.startswith('-') and not line.startswith('---'):
                        deletions.append(line[1:])

                file_change.additions.extend(additions)
                file_change.deletions.extend(deletions)
                file_change.hunks.append({
                    "old_start": int(hunk_match.group(1)),
                    "old_count": int(hunk_match.group(2) or 1),
                    "new_start": int(hunk_match.group(3)),
                    "new_count": int(hunk_match.group(4) or 1),
                    "header_context": (hunk_match.group(5) or "").strip(),
                    "additions": additions,
                    "deletions": deletions,
                    "context_lines": [
                        line[1:] if line.startswith(' ') else line
                        for line in hunk_content.split('\n')
                        if line and not line.startswith('+') and not line.startswith('-')
                    ],
                })

            file_changes.append(file_change)

        return file_changes

    def _extract_affected_functions(
        self,
        file_changes: List[FileChange],
        deleted_lines: List[str],
        added_lines: Optional[List[str]] = None,
    ) -> List[str]:
        """提取受影响函数，优先返回补丁触及的项目函数，而非 libc 调用。"""
        scores: Dict[str, float] = {}
        first_seen: Dict[str, int] = {}

        def bump(name: str, weight: float):
            token = str(name or "").strip()
            if not token:
                return
            first_seen.setdefault(token, len(first_seen))
            scores[token] = scores.get(token, 0.0) + weight

        for file_change in file_changes:
            for hunk in file_change.hunks:
                for name in self._extract_function_names_from_header(str(hunk.get("header_context", "") or "")):
                    bump(name, 14.0)

                structural_lines: List[str] = []
                structural_lines.extend(list(hunk.get("context_lines", []) or []))
                structural_lines.extend(list(hunk.get("deletions", []) or []))
                structural_lines.extend(list(hunk.get("additions", []) or []))

                for name in self._extract_function_definitions(structural_lines):
                    bump(name, 12.0)

        signal_lines = list(deleted_lines or []) + list(added_lines or [])
        for name in self._extract_function_definitions(signal_lines):
            bump(name, 10.0)

        for name in self._extract_called_functions(signal_lines):
            bump(name, 3.0 if name not in self.COMMON_LIB_FUNCTIONS else 1.0)

        ranked = sorted(
            scores,
            key=lambda name: (
                name in self.COMMON_LIB_FUNCTIONS,
                -scores[name],
                first_seen[name],
                name,
            ),
        )
        return ranked[:8]

    def _extract_function_names_from_header(self, header_context: str) -> List[str]:
        candidates = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', header_context or "")
        return self._filter_function_tokens(candidates)

    def _extract_function_definitions(self, code_lines: List[str]) -> List[str]:
        definition_pattern = re.compile(
            r'^\s*(?:static\s+|inline\s+|extern\s+|const\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|volatile\s+)*'
            r'[A-Za-z_][\w\s\*]*\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{?\s*$'
        )
        functions: List[str] = []
        for line in code_lines:
            match = definition_pattern.match((line or "").strip())
            if match:
                functions.append(match.group(1))
        return self._filter_function_tokens(functions)

    def _extract_called_functions(self, code_lines: List[str]) -> List[str]:
        functions: List[str] = []
        func_pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
        for line in code_lines:
            functions.extend(func_pattern.findall(line or ""))
        return self._filter_function_tokens(functions)

    def _filter_function_tokens(self, tokens: List[str]) -> List[str]:
        keywords = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof'}
        seen = set()
        filtered: List[str] = []
        for token in tokens:
            name = str(token or "").strip()
            if not name or name in keywords or name in seen:
                continue
            seen.add(name)
            filtered.append(name)
        return filtered

    def _describe_vulnerability(self, vuln_type: str) -> str:
        """描述漏洞类型"""
        descriptions = {
            "buffer_overflow": "缓冲区溢出：写入数据超过缓冲区边界，可能导致内存破坏",
            "stack_overflow": "栈缓冲区溢出：局部缓冲区上的越界写入，通常与固定大小局部数组相关",
            "heap_overflow": "堆缓冲区溢出：堆上对象被越界写入，通常与 malloc/calloc/realloc 后的长度控制失效相关",
            "out_of_bounds_write": "越界写：写操作超出目标缓冲区或数组边界",
            "out_of_bounds_read": "越界读：读取超出目标缓冲区或数组合法范围的数据",
            "buffer_overread": "缓冲区过读：通过索引或指针读取了缓冲区末尾之后的内存",
            "null_dereference": "空指针解引用：未检查指针有效性直接使用，可能导致程序崩溃",
            "use_after_free": "释放后使用：访问已释放的内存，可能导致数据损坏或任意代码执行",
            "double_free": "双重释放：同一资源在有效生命周期内被重复释放",
            "integer_overflow": "整数溢出：算术运算结果超出类型范围，可能导致逻辑错误或缓冲区溢出",
            "integer_underflow": "整数下溢：减法或偏移结果低于类型最小值，可能破坏长度、索引或循环边界",
            "divide_by_zero": "除零：除数或取模分母可能为零，导致运行时错误或异常行为",
            "format_string": "格式化字符串漏洞：用户输入作为格式化字符串，可能导致信息泄露或代码执行",
            "memory_leak": "内存泄漏：动态分配的内存未释放，可能导致资源耗尽",
            "race_condition": "竞态条件：共享状态的检查、更新或释放缺乏同步，可能导致越权、双重释放或状态损坏",
            "toctou": "TOCTOU 竞态：检查资源状态和实际使用之间存在可被并发或外部变化打破的时间窗口",
            "command_injection": "命令注入：外部输入未经严格约束进入 shell/exec 类敏感执行接口",
            "sql_injection": "SQL 注入：外部输入未经参数化或约束进入 SQL 执行语句",
            "path_traversal": "路径穿越：外部输入构造的路径逃逸预期根目录或受限目录",
            "uninitialized_variable": "未初始化变量使用：变量或字段在缺少确定初始化的情况下被读取或参与控制流",
        }
        return descriptions.get(vuln_type, f"未知漏洞类型: {vuln_type}")

    def _analyze_cross_file_dependencies(
        self,
        file_changes: List[FileChange]
    ) -> List[Dict[str, Any]]:
        """分析跨文件依赖"""
        dependencies = []

        if len(file_changes) <= 1:
            return dependencies

        # 收集所有头文件包含
        includes = {}
        for fc in file_changes:
            includes[fc.new_path] = []
            for line in fc.additions + fc.deletions:
                if '#include' in line:
                    match = re.search(r'#include\s*[<"]([^>"]+)[>"]', line)
                    if match:
                        includes[fc.new_path].append(match.group(1))

        # 分析依赖关系
        for fc in file_changes:
            for other_fc in file_changes:
                if fc.new_path == other_fc.new_path:
                    continue

                # 检查是否有共同的头文件
                common_includes = set(includes.get(fc.new_path, [])) & set(includes.get(other_fc.new_path, []))
                if common_includes:
                    dependencies.append({
                        "from": fc.new_path,
                        "to": other_fc.new_path,
                        "shared_includes": list(common_includes)
                    })

        return dependencies

    def _suggest_checker_name(self, patterns: List[VulnerabilityPattern]) -> str:
        """建议检测器名称"""
        if not patterns:
            return "CustomChecker"

        # 根据主要漏洞类型命名
        name_map = {
            "buffer_overflow": "BufferOverflowChecker",
            "stack_overflow": "StackOverflowChecker",
            "heap_overflow": "HeapOverflowChecker",
            "out_of_bounds_write": "BoundsWriteChecker",
            "out_of_bounds_read": "BoundsReadChecker",
            "buffer_overread": "BoundsReadChecker",
            "null_dereference": "NullDereferenceChecker",
            "use_after_free": "UseAfterFreeChecker",
            "double_free": "DoubleFreeChecker",
            "integer_overflow": "IntegerOverflowChecker",
            "integer_underflow": "IntegerUnderflowChecker",
            "divide_by_zero": "DivideByZeroChecker",
            "format_string": "FormatStringChecker",
            "memory_leak": "MemoryLeakChecker",
            "uninitialized_variable": "UninitializedVariableChecker",
            "race_condition": "RaceConditionChecker",
            "toctou": "TOCTOUChecker",
            "command_injection": "CommandInjectionChecker",
            "sql_injection": "SQLInjectionChecker",
            "path_traversal": "PathTraversalChecker",
        }

        primary = patterns[0].pattern_type
        return name_map.get(primary, "CustomChecker")

    def _format_analysis_result(self, result: Dict[str, Any]) -> str:
        """格式化分析结果"""
        backend = str(result.get("analysis_backend", "structural") or "structural")
        confidence = float(result.get("analysis_confidence", 0.0) or 0.0)
        affected_functions = list(result.get("affected_functions", []) or [])
        patch_semantics = dict(result.get("patch_semantics", {}) or {})
        cross_file_dependencies = list(result.get("cross_file_dependencies", []) or [])

        lines = [
            "📋 补丁分析结果",
            "=" * 50,
            "",
            f"🧠 分析后端: {backend}",
            f"🎯 置信度: {confidence:.2f}",
            "",
            f"📁 变更文件 ({len(result['files_changed'])}个):"
        ]

        for fd in result["file_details"]:
            lines.append(f"  - {fd['path']}: +{fd['additions']}/-{fd['deletions']}")

        lines.append("")
        lines.append(f"🔍 漏洞模式 ({len(result['vulnerability_patterns'])}个):")

        if not result["vulnerability_patterns"]:
            lines.append("  - 未形成高置信度漏洞分类，当前以结构语义为主。")
        else:
            for vp in result["vulnerability_patterns"]:
                lines.append(f"  - {vp['type']}: {vp['description']}")
                if vp['trigger_conditions']:
                    lines.append(f"    触发条件: {', '.join(vp['trigger_conditions'])}")
                if vp.get('fix_patterns'):
                    lines.append(f"    修复模式: {', '.join(vp['fix_patterns'])}")
                if vp['affected_functions']:
                    lines.append(f"    受影响函数: {', '.join(vp['affected_functions'])}")

        lines.append("")
        lines.append(f"📊 检测策略:")
        lines.append(f"  - 主要模式: {result['detection_strategy']['primary_pattern']}")
        lines.append(f"  - 数据流追踪: {'需要' if result['detection_strategy']['data_flow_tracking'] else '不需要'}")
        lines.append(f"  - 跨文件分析: {'需要' if result['detection_strategy']['cross_file_analysis'] else '不需要'}")
        if result["detection_strategy"].get("entry_points"):
            lines.append(f"  - 入口函数: {', '.join(result['detection_strategy']['entry_points'])}")
        if result["detection_strategy"].get("suggestions"):
            lines.append(f"  - 建议: {'; '.join(result['detection_strategy']['suggestions'])}")

        if affected_functions:
            lines.append("")
            lines.append(f"🧩 受影响函数: {', '.join(affected_functions)}")

        if any(patch_semantics.get(key) for key in ("added_guards", "added_api_calls", "removed_api_calls", "state_resets", "lifecycle_changes")):
            lines.append("")
            lines.append("🛠️ Patch 语义摘要:")
            if patch_semantics.get("added_guards"):
                lines.append(f"  - 新增 Guard: {', '.join(patch_semantics['added_guards'][:4])}")
            if patch_semantics.get("added_api_calls"):
                lines.append(f"  - 新增 API: {', '.join(patch_semantics['added_api_calls'][:6])}")
            if patch_semantics.get("removed_api_calls"):
                lines.append(f"  - 移除 API: {', '.join(patch_semantics['removed_api_calls'][:6])}")
            if patch_semantics.get("state_resets"):
                lines.append(f"  - 状态重置: {', '.join(patch_semantics['state_resets'][:4])}")
            if patch_semantics.get("lifecycle_changes"):
                lines.append(f"  - 生命周期变化: {', '.join(patch_semantics['lifecycle_changes'][:4])}")

        if cross_file_dependencies:
            lines.append("")
            lines.append("🔗 跨文件依赖:")
            for item in cross_file_dependencies[:6]:
                shared_includes = ", ".join(item.get("shared_includes", []) or [])
                lines.append(
                    f"  - {item.get('from', '')} -> {item.get('to', '')}"
                    + (f" (shared includes: {shared_includes})" if shared_includes else "")
                )

        lines.append("")
        lines.append(f"💡 建议检测器名称: {result['checker_name_suggestion']}")

        return "\n".join(lines)
