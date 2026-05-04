"""
生成产物结构审查工具

用于在本地编译/语法检查通过后，对生成的 CSA/CodeQL 产物做确定性质量审查，
拦截明显的占位实现、字符串匹配式 guard 建模、以及 API 名称一把抓等高风险模式。
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ..agent.tools import Tool, ToolResult


class ArtifactReviewTool(Tool):
    """对生成的 detector/query 做确定性结构审查。"""

    _RISKY_API_PATTERN = re.compile(
        r'hasName\("(?P<name>strcpy|strcat|memcpy|memmove|sprintf|snprintf|gets|strncpy|memcpy_s)"\)'
    )
    _SAFE_BOUNDED_API_PATTERN = re.compile(
        r'hasName\("(?P<name>strncpy|strncat|snprintf)"\)'
    )
    _BOOL_FUNCTION_PATTERN = re.compile(
        r"""
        (?P<signature>
            \bbool\s+
            (?P<name>[A-Za-z_]\w*)
            \s*\((?P<params>[^)]*)\)\s*
            (?:const\s*)?
        )
        \{
        (?P<body>.*?)
        \}
        """,
        re.DOTALL | re.VERBOSE,
    )
    _CSA_VOID_FUNCTION_PATTERN = re.compile(
        r"""
        (?P<signature>
            \bvoid\s+
            (?P<name>[A-Za-z_]\w*)
            \s*\((?P<params>[^)]*)\)\s*
            (?:const\s*)?
        )
        \{
        (?P<body>.*?)
        \}
        """,
        re.DOTALL | re.VERBOSE,
    )
    _QL_PREDICATE_PATTERN = re.compile(
        r"""
        \bpredicate\s+
        (?P<name>[A-Za-z_]\w*)
        \s*\((?P<params>[^)]*)\)\s*
        \{
        (?P<body>.*?)
        \n\}
        """,
        re.DOTALL | re.VERBOSE,
    )
    _CSA_DIRECT_FUNCNAME_PATTERN = re.compile(
        r'FuncName\s*==\s*"(?P<name>strcpy|strcat|memcpy|memmove|sprintf|snprintf|gets|strncpy|strncat)"'
    )
    _CSA_SEMANTIC_HELPER_NAME_TOKENS = (
        "guard",
        "barrier",
        "overflow",
        "underflow",
        "uaf",
        "useafterfree",
        "lifetime",
        "dangling",
        "released",
        "doublefree",
        "bound",
        "bounds",
        "sizeproof",
        "lookup",
        "relookup",
        "authoritative",
        "fresh",
        "reinit",
        "invalidate",
        "alias",
    )
    _CSA_SEMANTIC_HELPER_PARAM_PATTERN = re.compile(
        r"\b(CallEvent|CheckerContext|ProgramStateRef|SVal|SymbolRef|MemRegion|Expr|Stmt|Decl|SourceRange|LocationContext)\b"
    )
    _CSA_QUALITY_COMMENT_PATTERN = re.compile(
        r"(总是报告|always report|简化版本|simplified version|简化实现|simplified implementation|simplified approach|simple check|for now|占位实现|placeholder implementation|保守地不报告|假设无法确定|假设没有|实际实现需要|这里应该实现|这里应实现)",
        re.IGNORECASE,
    )
    _CSA_HELPER_PLACEHOLDER_PATTERN = re.compile(
        r"(简化实现|简化处理|这里简化|simplified approach|simple check|for now|保守地不报告|假设无法确定|假设没有|实际实现需要|在实际实现中|在实际分析中|这里应该实现|这里应实现|placeholder|todo)",
        re.IGNORECASE,
    )
    _CSA_SEMANTIC_TOKENS = (
        "Call.getArgSVal(",
        "Call.getArgExpr(",
        "Call.getArgSourceRange(",
        "Call.getArg(",
        "State->",
        "C.getState()",
        "assume(",
        "assumeDual(",
        "getAsRegion(",
        "getKnownValue(",
        "ConstraintManager",
        "SValBuilder",
        "dyn_cast_or_null<",
        "hasSameBlockStringBarrier(",
        "hasSameBlockMemcpyBarrier(",
        "hasSameBlockStatusBarrier(",
        "getStaticDestinationBytes(",
        "getStaticStringLiteralBytes(",
    )
    _CSA_STATEFUL_CLAIM_PATTERN = re.compile(
        r"(ProgramState|路径敏感|path-sensitive|path sensitive|状态跟踪|state tracking|track .* state|validation state)",
        re.IGNORECASE,
    )

    def __init__(self, work_dir: Optional[str] = None):
        self.work_dir = work_dir

    def set_work_dir(self, work_dir: str):
        """设置工作目录，便于解析相对路径。"""
        self.work_dir = work_dir

    @property
    def name(self) -> str:
        return "review_artifact"

    @property
    def description(self) -> str:
        return (
            "对已生成并通过本地检查的检测器做结构审查。"
            "用于拦截明显错误的占位 helper、按 API 名称一把抓的 CodeQL 查询、"
            "以及用字符串匹配代替真实语义建模的反模式。"
        )

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "artifact_path": {
                    "type": "string",
                    "description": "待审查的源文件路径，通常是 .cpp 或 .ql 文件",
                },
                "analyzer": {
                    "type": "string",
                    "description": "分析器类型，可选值为 csa/codeql；省略时自动推断",
                },
                "source_code": {
                    "type": "string",
                    "description": "可选，直接提供源代码文本；未提供时会从 artifact_path 读取",
                },
                "review_mode": {
                    "type": "string",
                    "description": "审查模式，可选 generate/refine；refine 会启用更严格的精炼质量门",
                },
            },
            "required": ["artifact_path"],
        }

    def execute(
        self,
        artifact_path: str,
        analyzer: str = "",
        source_code: str = "",
        review_mode: str = "generate",
    ) -> ToolResult:
        resolved_path = self._resolve_path(artifact_path)
        analyzer_id = self._infer_analyzer(analyzer, resolved_path)
        mode = str(review_mode or "generate").strip().lower()
        if mode not in {"generate", "refine"}:
            mode = "generate"

        if analyzer_id not in {"csa", "codeql"}:
            return ToolResult(
                success=False,
                output="",
                error=f"无法推断产物类型: {artifact_path}",
            )

        code = source_code
        if not code:
            if not os.path.exists(resolved_path):
                return ToolResult(
                    success=False,
                    output="",
                    error=f"待审查文件不存在: {resolved_path}",
                )
            try:
                with open(resolved_path, "r", encoding="utf-8") as fh:
                    code = fh.read()
            except Exception as exc:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"读取待审查文件失败: {exc}",
                )

        warnings: List[str] = []
        if analyzer_id == "codeql":
            findings, warnings = self._review_codeql(code, review_mode=mode)
        else:
            findings, warnings = self._review_csa(code, review_mode=mode)

        if findings:
            lines = ["结构审查未通过，发现以下高风险问题:"]
            lines.extend(f"- {item}" for item in findings)
            if warnings:
                lines.append("")
                lines.append("附加提示（非阻断）:")
                lines.extend(f"- {item}" for item in warnings)
            fix_hints = self._build_fix_hints(analyzer_id, findings)
            if fix_hints:
                lines.append("")
                lines.append("定向修复建议:")
                lines.extend(f"- {item}" for item in fix_hints)
            lines.append("请在保留漏洞语义目标的前提下做定点修复，不要通过删逻辑或改名绕过审查。")
            return ToolResult(
                success=False,
                output="\n".join(lines),
                error="生成产物结构审查未通过（存在语义空壳、占位实现或高风险结构问题）",
                metadata={
                    "artifact_path": resolved_path,
                    "analyzer": analyzer_id,
                    "review_mode": mode,
                    "findings": findings,
                    "warnings": warnings,
                },
            )

        if warnings:
            lines = ["结构审查通过，但发现以下提示:"]
            lines.extend(f"- {item}" for item in warnings)
            return ToolResult(
                success=True,
                output="\n".join(lines),
                metadata={
                    "artifact_path": resolved_path,
                    "analyzer": analyzer_id,
                    "review_mode": mode,
                    "findings": [],
                    "warnings": warnings,
                },
            )

        return ToolResult(
            success=True,
            output=f"结构审查通过: {resolved_path}",
            metadata={
                "artifact_path": resolved_path,
                "analyzer": analyzer_id,
                "review_mode": mode,
                "findings": [],
                "warnings": [],
            },
        )

    def _build_fix_hints(self, analyzer_id: str, findings: List[str]) -> List[str]:
        if analyzer_id == "csa":
            return self._build_csa_fix_hints(findings)
        return []

    def _build_csa_fix_hints(self, findings: List[str]) -> List[str]:
        hints: List[str] = []
        if any("callee 名称把" in item for item in findings):
            hints.append(
                "对被点名的 helper，至少读取当前 call 的实参与相关 guard，并引入真实 `if` 分支；不要保留无条件 `reportBug`。"
            )
            hints.append(
                "对当前这类 buffer-overflow patch，优先围绕 `strcpy`/`strcat`/未校验 `memcpy` 与新增长度检查建立对应关系；把 `snprintf` 视为 bounded replacement，不要额外保留独立 `sprintf` 黑名单规则。"
            )
        if any("ProgramState" in item for item in findings):
            hints.append(
                "如果没有真实的 `ProgramState` 读写、约束传播或状态转移，就删除相关说明，改成基于 AST、实参与显式 guard 的最小语义修复。"
            )
        if any("占位" in item or "placeholder" in item.lower() for item in findings):
            hints.append(
                "删掉 `for now`、`placeholder`、`in a more complete implementation` 一类占位说明，避免再次触发空壳实现审查。"
            )
        if any("字符串启发式" in item or "relookup" in item or "stable-handle" in item for item in findings):
            hints.append(
                "把正触发绑定到同一 cached receiver / owner field / stable-handle peer，或用 `ProgramState` 显式记录 release-state；不要只比较字段名、成员名或函数名前缀。"
            )
            hints.append(
                "如果补丁主机制是 authoritative relookup，应围绕 nested `MemberExpr`、稳定句柄 sibling、显式 invalidation/reset 或同资源 freshness 合同建模，而不是保留名字猜测式触发。"
            )
        return self._dedupe(hints)

    def _resolve_path(self, artifact_path: str) -> str:
        if not artifact_path:
            return artifact_path
        if os.path.isabs(artifact_path):
            return artifact_path
        raw_candidate = os.path.abspath(artifact_path)
        if os.path.exists(raw_candidate):
            return raw_candidate
        if self.work_dir:
            candidates = [
                os.path.join(self.work_dir, artifact_path),
                os.path.join(self.work_dir, "csa", artifact_path),
                os.path.join(self.work_dir, "codeql", artifact_path),
            ]
            for candidate in candidates:
                if os.path.exists(candidate):
                    return os.path.abspath(candidate)
            return os.path.abspath(candidates[0])
        return os.path.abspath(artifact_path)

    def _infer_analyzer(self, analyzer: str, artifact_path: str) -> str:
        analyzer_id = str(analyzer or "").strip().lower()
        if analyzer_id in {"csa", "codeql"}:
            return analyzer_id
        lower_path = str(artifact_path or "").lower()
        if lower_path.endswith(".ql"):
            return "codeql"
        if lower_path.endswith((".cpp", ".cc", ".cxx", ".hpp", ".h")):
            return "csa"
        return ""

    def _review_codeql(self, code: str, review_mode: str = "generate") -> Tuple[List[str], List[str]]:
        if str(review_mode or "generate").strip().lower() != "refine":
            return self._review_codeql_generate(code)
        return self._review_codeql_refine(code)

    def _review_codeql_generate(self, code: str) -> Tuple[List[str], List[str]]:
        return [], []

    def _review_codeql_refine(self, code: str) -> Tuple[List[str], List[str]]:
        findings: List[str] = []
        warnings: List[str] = []
        normalized = code or ""
        lower_code = normalized.lower()
        risky_names = sorted({match.group("name") for match in self._RISKY_API_PATTERN.finditer(normalized)})
        bounded_names = sorted({match.group("name") for match in self._SAFE_BOUNDED_API_PATTERN.finditer(normalized)})

        if re.search(r"\btoString\s*\(\)\s*\.\s*matches\s*\(", normalized):
            warnings.append("CodeQL 查询在用 `toString().matches(...)` 推断 guard/安全条件；建议改为显式建模 AST、参数和控制条件。")
        if (
            "tostring()" in lower_code and
            any(token in lower_code for token in ("guard", "bounds", "length", "sizeof", "condition", "check"))
        ):
            warnings.append("CodeQL 查询使用 `toString()` 近似建模 guard/边界条件；这通常不是稳定的语义约束。")
        if re.search(r"\bregexpMatch\s*\(", normalized):
            warnings.append("CodeQL 查询依赖 `regexpMatch(...)` 做漏洞/guard 识别；这通常只是近似建模，除非已绑定到真实参数/AST 关系，否则应继续收紧。")
        if re.search(
            r"getLocation\(\)\.getStartLine\(\)\s*[<>]=?\s*\w+\.getLocation\(\)\.getStartLine\(\)",
            normalized,
        ):
            warnings.append("CodeQL 查询使用行号先后关系近似 guard 支配关系；这在代码重排、宏展开或跨语句条件下不稳定。")

        if len(risky_names) >= 3 and ("memcpy" in risky_names or "snprintf" in risky_names or "sprintf" in risky_names):
            if "getArgument(1)" not in normalized and "getArgument(2)" not in normalized:
                findings.append("CodeQL 查询覆盖了多参数写入 API，但没有建模 size/length 实参；这通常会退化成按 callee 名称一把抓。")

        predicate_findings = self._review_codeql_predicates(normalized)
        barrier_findings = self._review_codeql_barrier_predicates(normalized)
        findings.extend(predicate_findings)
        findings.extend(barrier_findings)

        if bounded_names and not self._models_bounded_api_semantics(normalized, bounded_names):
            findings.append("CodeQL 查询把 `strncpy`/`strncat`/`snprintf` 一类 bounded API 当成直接危险点，但没有建模其 size 或返回值语义。")

        if len(risky_names) >= 3 and re.search(r"\bselect\s+\w+\s*,\s*\"[^\"]*(unsafe|overflow)", normalized, re.IGNORECASE):
            if "toString().matches(" in normalized or "regexpMatch(" in normalized:
                findings.append("CodeQL 查询目前主要依赖危险 API 名称加字符串式 guard 判断，容易产生 patched false positive。")
        if self._uses_null_check_as_lifetime_barrier(normalized):
            findings.append("CodeQL 查询把 null/non-null 检查当成 stale/dangling 资源的 barrier；空值只能证明是否为空，不能证明对象仍然新鲜可用。")

        return self._dedupe(findings), self._dedupe(warnings)

    def _review_csa(self, code: str, review_mode: str = "generate") -> Tuple[List[str], List[str]]:
        if str(review_mode or "generate").strip().lower() != "refine":
            return self._review_csa_generate(code)
        return self._review_csa_refine(code)

    def _review_csa_generate(self, code: str) -> Tuple[List[str], List[str]]:
        warnings: List[str] = []
        placeholder_hits: List[Tuple[str, str]] = []
        lifecycle_family = self._is_lifecycle_checker_family(code or "")

        for match in self._BOOL_FUNCTION_PATTERN.finditer(code or ""):
            name = match.group("name")
            params = match.group("params") or ""
            body = match.group("body") or ""
            if not self._is_semantic_helper_candidate(name, params):
                continue

            body_without_comments = re.sub(r"//.*?$|/\*.*?\*/", "", body, flags=re.MULTILINE | re.DOTALL)
            condensed = re.sub(r"\s+", "", body_without_comments)
            if condensed in {"returnfalse;", "returntrue;"}:
                placeholder_hits.append((name, "helper 直接常量返回"))
                continue
            if self._CSA_HELPER_PLACEHOLDER_PATTERN.search(body):
                if re.search(r"\breturn\s+(false|true)\s*;", body_without_comments):
                    placeholder_hits.append((name, "helper 以注释占位并直接返回常量"))

        for name, reason in placeholder_hits:
            warnings.append(f"CSA helper `{name}` 仍像占位实现: {reason}；生成阶段允许继续，但 refine 前应补成真实语义。")

        if self._has_empty_program_state_modeling(code or ""):
            warnings.append("CSA 代码声明了 `ProgramState`，但没有实际状态读写；生成阶段允许继续，但这通常说明骨架还未收紧。")

        callee_only_dispatch_reports = self._find_csa_callee_only_dispatch_reports(code or "")
        if callee_only_dispatch_reports:
            warnings.append(
                "CSA checker 对 "
                + ", ".join(callee_only_dispatch_reports[:4])
                + " 的分支仍偏向按 callee 名称分流；生成阶段允许继续，但 refine 应补齐 guard/边界/状态约束。"
            )

        if self._claims_stateful_modeling_without_implementation(code or ""):
            warnings.append("CSA 代码声称使用 `ProgramState` 或路径敏感状态跟踪，但实现还没形成真实状态流；生成阶段允许继续，但 refine 应收紧。")

        if self._reports_release_as_bug_for_lifecycle(code or ""):
            warnings.append("CSA checker 直接把 release/free 回调当成漏洞点；生成阶段允许继续，但 refine 应把真正报告点收敛到后续 use/deref。")

        if lifecycle_family and self._uses_name_only_lifecycle_trigger(code or ""):
            warnings.append("CSA 生命周期 checker 仍主要依赖字段名/函数名字符串启发式触发；生成阶段允许继续，但 refine 应绑定到同一资源合同。")

        if lifecycle_family and self._has_placeholder_primary_callbacks(code or ""):
            warnings.append("CSA 生命周期 checker 在主 callback 中仍含 placeholder 风格说明；生成阶段允许继续，但后续应落到真实分支。")

        if lifecycle_family and self._claims_relookup_without_contract_binding(code or ""):
            warnings.append("CSA checker 声称 authoritative relookup / stable-handle 语义，但 freshness 合同尚未真正绑定；生成阶段允许继续，但 refine 应补齐。")

        if self._CSA_QUALITY_COMMENT_PATTERN.search(code or ""):
            warnings.append("CSA 代码含有“简化实现 / for now / placeholder”一类说明注释；生成阶段仅提示，不作阻断。")

        direct_api_reports = self._find_csa_direct_api_reports(code or "")
        if direct_api_reports:
            warnings.append(
                "CSA checker 对 "
                + ", ".join(direct_api_reports[:4])
                + " 仍偏向按 API 名称直接报警；生成阶段允许继续，但 refine 应补充实参/边界/状态语义。"
            )

        if re.search(r"destination buffer size unknown", code or "", re.IGNORECASE):
            warnings.append("CSA checker 仅因目标缓冲区大小未知就报警；生成阶段仅提示，不作阻断。")

        if self._uses_nullness_as_bounds_proof(code or ""):
            warnings.append("CSA checker 把空/非空判断当成边界证明；生成阶段仅提示，不作阻断。")

        if self._drops_symbolic_size_paths(code or ""):
            warnings.append("CSA checker 在符号长度无法具体化时直接静默；生成阶段仅提示，不作阻断。")

        if self._uses_location_type_only_for_buffer_size(code or ""):
            warnings.append("CSA checker 仅靠 `getLocationType()` 推断目标容量；生成阶段仅提示，不作阻断。")

        if self._uses_field_or_var_only_buffer_recovery(code or ""):
            warnings.append("CSA checker 的固定缓冲区恢复仍不完整；生成阶段仅提示，不作阻断。")

        return [], self._dedupe(warnings)

    def _review_csa_refine(self, code: str) -> Tuple[List[str], List[str]]:
        findings: List[str] = []
        warnings: List[str] = []
        placeholder_hits: List[Tuple[str, str]] = []
        lifecycle_family = self._is_lifecycle_checker_family(code or "")

        for match in self._BOOL_FUNCTION_PATTERN.finditer(code or ""):
            name = match.group("name")
            params = match.group("params") or ""
            body = match.group("body") or ""
            if not self._is_semantic_helper_candidate(name, params):
                continue

            body_without_comments = re.sub(r"//.*?$|/\*.*?\*/", "", body, flags=re.MULTILINE | re.DOTALL)
            condensed = re.sub(r"\s+", "", body_without_comments)
            if condensed in {"returnfalse;", "returntrue;"}:
                placeholder_hits.append((name, "helper 直接常量返回"))
                continue
            if self._CSA_HELPER_PLACEHOLDER_PATTERN.search(body):
                if re.search(r"\breturn\s+(false|true)\s*;", body_without_comments):
                    placeholder_hits.append((name, "helper 以注释占位并直接返回常量"))

        for name, reason in placeholder_hits:
            findings.append(f"CSA helper `{name}` 存在占位实现: {reason}；必须真实读取 AST、ProgramState 或路径条件。")

        if self._has_empty_program_state_modeling(code or ""):
            findings.append("CSA 代码声明了 `ProgramState`，但没有任何实际读取、写入或状态转移，说明状态建模仍是空壳。")

        callee_only_dispatch_reports = self._find_csa_callee_only_dispatch_reports(code or "")
        if callee_only_dispatch_reports:
            findings.append(
                "CSA checker 按 callee 名称把 "
                + ", ".join(callee_only_dispatch_reports[:4])
                + " 分发到无条件 `reportBug` 的 helper，缺少 guard、边界或状态约束；这仍是 API 黑名单式实现。"
            )

        if self._claims_stateful_modeling_without_implementation(code or ""):
            warnings.append(
                "CSA 代码引入了 `ProgramState` / 路径敏感相关符号或说明，但实现里没有对应的状态读写、约束传播或 guard 绑定。"
                " 如果当前路线本来就是 AST/实参/guard 建模，应删掉这类 stateful 话术；只有显式声明了状态建模却完全未落地时才应继续升级处理。"
            )

        if self._reports_release_as_bug_for_lifecycle(code or ""):
            findings.append(
                "CSA checker 把 release/free/destroy 回调本身当成漏洞点直接 `reportBug`。"
                " 对 use-after-free / stale-cache 一类生命周期问题，释放点应写入状态或约束，真正报告应落在后续 use/deref/consumer 位置。"
            )

        if lifecycle_family and self._uses_name_only_lifecycle_trigger(code or ""):
            findings.append(
                "CSA 生命周期 checker 仍主要依赖字段名/函数名字符串启发式触发 `reportBug`，但没有把同一 receiver、stable-handle/relookup 或 release-state 绑定到同一资源；这类实现通常会编译通过但 0 hit。"
            )

        if lifecycle_family and self._has_placeholder_primary_callbacks(code or ""):
            findings.append(
                "CSA 生命周期 checker 在主 callback 中仍保留“for now / placeholder / full implementation”一类占位注释，说明 free/relookup/state 分支尚未真正实现。"
            )

        if lifecycle_family and self._claims_relookup_without_contract_binding(code or ""):
            findings.append(
                "CSA checker 声称 authoritative relookup / stable-handle 语义，但没有建立同 receiver / 同 owner 字段 / ProgramState 的 freshness 合同，只剩名称匹配式触发。"
            )

        if self._CSA_QUALITY_COMMENT_PATTERN.search(code or ""):
            if callee_only_dispatch_reports or self._has_empty_program_state_modeling(code or ""):
                findings.append("CSA 代码仍含有“简化实现 / for now / placeholder”一类占位说明，而关键 guard/state 语义尚未真正落地。")
            else:
                warnings.append("CSA 代码含有“简化实现 / for now / placeholder”一类说明注释；仅作提示，真正阻断仍以空壳 helper、空状态建模或 API 黑名单式报告为准。")

        direct_api_reports = self._find_csa_direct_api_reports(code or "")
        if direct_api_reports:
            findings.append(
                "CSA checker 对 "
                + ", ".join(direct_api_reports[:4])
                + " 主要按 callee 名称直接 `reportBug`，未读取实参值、缓冲区边界或路径状态；这会退化成 API 黑名单。"
            )

        if re.search(r"destination buffer size unknown", code or "", re.IGNORECASE):
            findings.append("CSA checker 仅因目标缓冲区大小未知就直接报警；“unknown size” 本身不是漏洞证据，必须再结合固定缓冲区、拷贝长度或缺失的 patch 式 barrier。")

        if self._uses_nullness_as_bounds_proof(code or ""):
            findings.append("CSA checker 把 `isNull` / `isNonNull` 一类空值判断当成边界证明并直接静默；空/非空只证明指针有效性，不证明写入不会越界。")

        if self._drops_symbolic_size_paths(code or ""):
            findings.append("CSA checker 在 `srcLength` / `copySize` / `bufferSize` 等符号长度无法具体化时直接 `return`；对 patch 删除的 copy/write 机制，这会把真实漏洞路径整体静默。")

        if self._uses_location_type_only_for_buffer_size(code or ""):
            findings.append("CSA checker 仅靠 `TypedRegion::getLocationType()` 推断目标容量，却没有沿 `FieldRegion` / `ElementRegion` / super-region 恢复固定数组大小；这会把结构体字段缓冲区错误地退化成指针并整体漏报。")

        if self._uses_field_or_var_only_buffer_recovery(code or ""):
            findings.append(
                "CSA checker 试图从 `FieldRegion` / `VarRegion` 恢复固定缓冲区容量，但没有先 `StripCasts()`、也没有沿 `ElementRegion` / super-region 回溯。"
                " 对 `record->buf`、`slot[i]` 这类 decayed 目的地，这通常会直接 0 hit。"
            )

        if self._reports_missing_capacity_without_semantics(code or ""):
            findings.append(
                "CSA checker 声称“缺少 destination size/capacity validation”，但实现里既没有恢复目标缓冲区容量，也没有把 patch guard/barrier 绑定到当前 call；这仍然是表面化匹配。"
            )

        if self._lacks_same_call_barrier_binding(code or ""):
            findings.append(
                "CSA checker 已恢复 destination capacity / size carrier，但仍缺少 same-call barrier binding。"
                " 仅凭函数级 guard 存在感不能证明当前 write 已被 patch-style bounds barrier 静默。"
            )

        if self._uses_length_or_name_heuristics_without_capacity_model(code or ""):
            findings.append(
                "CSA checker 仅凭 `strlen/strnlen` 或变量名含 `len/size/bytes` 判断 copy 风险，却没有恢复 destination capacity；这还是启发式名字匹配，不是稳定的语义建模。"
            )

        return self._dedupe(findings), self._dedupe(warnings)

    def _review_codeql_predicates(self, code: str) -> List[str]:
        findings: List[str] = []
        for match in self._QL_PREDICATE_PATTERN.finditer(code or ""):
            name = match.group("name")
            params = match.group("params") or ""
            body = match.group("body") or ""
            if "FunctionCall" not in params:
                continue
            if ".getTarget()" not in body:
                continue
            if "hasName(" not in body and not re.search(r"\bis[A-Z]\w+\(", body):
                continue
            if any(
                token in body
                for token in (
                    "getArgument(",
                    "getQualifier(",
                    "VariableAccess",
                    "ArrayExpr",
                    "DataFlow",
                    "TaintTracking",
                    "dominates",
                    "postdominates",
                )
            ):
                continue
            findings.append(
                f"CodeQL 谓词 `{name}` 仅按 callee 名称分流，未读取实参、目标对象或数据流语义；这会退化成按 API 名称一把抓。"
            )
        return findings

    def _review_codeql_barrier_predicates(self, code: str) -> List[str]:
        findings: List[str] = []
        for match in self._QL_PREDICATE_PATTERN.finditer(code or ""):
            name = str(match.group("name") or "")
            lowered_name = name.lower()
            if not any(token in lowered_name for token in ("guard", "barrier", "bound", "check", "safe", "silence")):
                continue
            body = match.group("body") or ""
            if "IfStmt" not in body:
                continue
            if "call.getEnclosingFunction()" not in body:
                continue
            if any(
                token in body
                for token in (
                    "call.getArgument(",
                    "VariableAccess",
                    "getQualifier(",
                    "dominates",
                    "postdominates",
                    "DataFlow",
                    "TaintTracking",
                )
            ):
                continue
            findings.append(
                f"CodeQL guard/barrier 谓词 `{name}` 只因同一函数里存在任意 `if`/比较就静默，没有把 barrier 绑定到当前 call 的参数或相关变量。"
            )
        return findings

    def _models_bounded_api_semantics(self, code: str, bounded_names: List[str]) -> bool:
        normalized = code or ""
        if "snprintf" in bounded_names and "getArgument(1)" not in normalized:
            return False
        if any(name in bounded_names for name in ("strncpy", "strncat")):
            if "getArgument(2)" not in normalized or "getArgument(0)" not in normalized:
                return False
        return True

    def _uses_null_check_as_lifetime_barrier(self, code: str) -> bool:
        lowered = (code or "").lower()
        if not any(token in lowered for token in ("use_after_free", "use-after-free", "stale", "dangling", "released")):
            return False
        return bool(
            re.search(
                r'predicate\s+\w*(guard|barrier|check|safe|silence)\w*\s*\([^)]*\)\s*\{.*?(getOperator\(\)\s*=\s*"!"|getValue\(\)\s*=\s*"0"|nullptr|null)',
                code or "",
                flags=re.IGNORECASE | re.DOTALL,
            )
        )

    def _find_csa_direct_api_reports(self, code: str) -> List[str]:
        direct: List[str] = []
        normalized = code or ""
        for match in self._CSA_DIRECT_FUNCNAME_PATTERN.finditer(normalized):
            name = match.group("name")
            window = normalized[match.start(): match.start() + 360]
            if "reportBug" not in window:
                continue
            if any(token in window for token in self._CSA_SEMANTIC_TOKENS):
                continue
            if name not in direct:
                direct.append(name)
        return direct

    def _find_csa_callee_only_dispatch_reports(self, code: str) -> List[str]:
        normalized = code or ""
        helper_bodies: Dict[str, str] = {}
        for match in self._CSA_VOID_FUNCTION_PATTERN.finditer(normalized):
            helper_bodies[str(match.group("name") or "").strip()] = match.group("body") or ""

        findings: List[str] = []
        dispatch_pattern = re.compile(
            r'FuncName\s*==\s*"(?P<name>strcpy|strcat|memcpy|memmove|sprintf|snprintf|gets|strncpy|strncat)"'
            r'[\s\S]{0,120}?\{\s*(?P<helper>[A-Za-z_]\w*)\s*\('
        )
        for match in dispatch_pattern.finditer(normalized):
            api_name = str(match.group("name") or "").strip()
            helper_name = str(match.group("helper") or "").strip()
            if not api_name or not helper_name:
                continue
            body = helper_bodies.get(helper_name, "")
            if not body:
                continue
            if not self._is_callee_only_report_helper(body):
                continue
            if api_name not in findings:
                findings.append(api_name)
        return findings

    def _is_callee_only_report_helper(self, body: str) -> bool:
        body_without_comments = re.sub(r"//.*?$|/\*.*?\*/", "", body or "", flags=re.MULTILINE | re.DOTALL)
        if "reportBug(" not in body_without_comments:
            return False
        if any(token in body_without_comments for token in ("if (", "if(", "switch (", "switch(", "while (", "for (")):
            return False
        if any(token in body_without_comments for token in ("State->", "assume(", "addTransition(", "contains<", "get<", "set<", "remove<")):
            return False
        return True

    def _has_empty_program_state_modeling(self, code: str) -> bool:
        normalized = code or ""
        declarations = list(
            re.finditer(r"ProgramStateRef\s+(?P<name>\w+)\s*=\s*C\.getState\(\)\s*;", normalized)
        )
        if not declarations:
            return False

        meaningful_uses = 0
        for match in declarations:
            state_name = str(match.group("name") or "").strip()
            if not state_name:
                continue
            remainder = normalized[match.end():]
            if (
                re.search(rf"\b{re.escape(state_name)}\s*->\s*(?:get|getSVal|get_context|set|assume)\s*(?:<|\()", remainder)
                or re.search(rf"\b{re.escape(state_name)}\s*=\s*{re.escape(state_name)}\s*->", remainder)
                or re.search(rf"\baddTransition\(\s*{re.escape(state_name)}\s*\)", remainder)
                or re.search(rf"[\(,]\s*{re.escape(state_name)}\s*[\),]", remainder)
            ):
                meaningful_uses += 1

        return meaningful_uses == 0

    def _has_meaningful_csa_state_modeling(self, code: str) -> bool:
        normalized = code or ""
        if re.search(r"REGISTER_(?:MAP|SET|LIST|TRAIT)_WITH_PROGRAMSTATE", normalized):
            return True
        if re.search(r"State\s*=\s*State->(?:set|add|remove)\s*<", normalized):
            return True
        if re.search(r"\baddTransition\(\s*State\s*\)", normalized):
            return True
        if "assumeDual(" in normalized and "ConstraintManager" in normalized:
            return True
        if re.search(r"\bProgramStateRef\s+\w+\s*=\s*C\.getState\(\)\s*;", normalized):
            return not self._has_empty_program_state_modeling(normalized)
        return False

    def _claims_stateful_modeling_without_implementation(self, code: str) -> bool:
        normalized = code or ""
        if not self._CSA_STATEFUL_CLAIM_PATTERN.search(normalized):
            return False
        return not self._has_meaningful_csa_state_modeling(normalized)

    def _reports_release_as_bug_for_lifecycle(self, code: str) -> bool:
        normalized = code or ""
        lowered = normalized.lower()
        if not any(token in lowered for token in ("use-after-free", "use after free", "stale", "dangling", "relookup", "released", "lifetime")):
            return False
        postcall_match = re.search(
            r"void\s+checkPostCall\s*\([^)]*\)\s*const\s*\{(?P<body>.*?)\n\s*\}",
            normalized,
            flags=re.DOTALL,
        )
        if not postcall_match:
            return False
        body = postcall_match.group("body") or ""
        if "reportBug(" not in body:
            return False
        if not re.search(r'FuncName\s*==\s*"[^"]*(free|destroy|release|delete)[^"]*"', body, flags=re.IGNORECASE):
            if not re.search(r"\b(isReleaseFunction|isFreeLike|isDestroyLike|isReleaseLike)\s*\(", body):
                return False
        if self._has_lifecycle_state_transition(normalized):
            return False
        return True

    def _has_lifecycle_state_transition(self, code: str) -> bool:
        normalized = code or ""
        return bool(
            re.search(r"REGISTER_(?:MAP|SET|LIST|TRAIT)_WITH_PROGRAMSTATE", normalized)
            or re.search(r"State\s*=\s*State->(?:set|remove|add)\s*<", normalized)
            or re.search(r"addTransition\(\s*State\s*\)", normalized)
            or re.search(r"contains\s*<", normalized)
            or re.search(r"get\s*<", normalized)
        )

    def _is_lifecycle_checker_family(self, code: str) -> bool:
        lowered = (code or "").lower()
        return any(
            token in lowered
            for token in (
                "use-after-free",
                "use after free",
                "stale",
                "dangling",
                "released",
                "lifetime",
                "relookup",
                "stable-handle",
                "stable handle",
                "cached pointer",
            )
        )

    def _has_relookup_contract_binding(self, code: str) -> bool:
        normalized = code or ""
        lowered = normalized.lower()
        if self._has_lifecycle_state_transition(normalized):
            return True

        receiver_binding = any(
            token in normalized
            for token in (
                "check::PreStmt<MemberExpr>",
                "dyn_cast<MemberExpr>(",
                "dyn_cast_or_null<MemberExpr>(",
                "IgnoreParenImpCasts(",
                "getBase()",
                "getBase(",
                "getQualifier()",
                "getQualifier(",
                "getMemberDecl()",
                "getMemberDecl(",
            )
        )
        owner_binding = any(
            token in normalized
            for token in (
                "getDeclContext()",
                "getDeclContext(",
                "RecordDecl",
                "FieldDecl",
                "fields()",
                "Owner->fields()",
                "decls()",
            )
        )
        role_binding = any(
            token in lowered
            for token in (
                'ends_with("_id")',
                'endswith("_id")',
                "stable-handle",
                "stable handle",
                "authoritative lookup",
                "authoritative relookup",
                "relookup",
                "cached pointer",
                "ispointertype()",
                "isintegertype()",
                "isenumeraltype()",
            )
        )
        return receiver_binding and owner_binding and role_binding

    def _has_placeholder_primary_callbacks(self, code: str) -> bool:
        normalized = code or ""
        primary_callbacks = {
            "checkprecall",
            "checkpostcall",
            "checkprestmt",
            "checklocation",
            "checkbind",
        }
        for match in self._CSA_VOID_FUNCTION_PATTERN.finditer(normalized):
            name = str(match.group("name") or "").strip().lower()
            if name not in primary_callbacks:
                continue
            body = match.group("body") or ""
            if not self._CSA_HELPER_PLACEHOLDER_PATTERN.search(body):
                continue
            return True
        return False

    def _uses_name_only_lifecycle_trigger(self, code: str) -> bool:
        normalized = code or ""
        if not self._is_lifecycle_checker_family(normalized):
            return False
        if self._has_lifecycle_state_transition(normalized):
            return False
        if self._has_relookup_contract_binding(normalized):
            return False

        name_match_pattern = re.compile(
            r"(getNameAsString\(\)|FuncName\s*(?:==|!=)|\.startswith\(|\.contains\(|getCalleeIdentifier\(\))"
        )
        for match in name_match_pattern.finditer(normalized):
            window = normalized[max(0, match.start() - 220): match.start() + 520]
            if any(token in window for token in ("reportBug(", "emitReport(", "generateNonFatalErrorNode(", "generateErrorNode(")):
                return True
        return False

    def _claims_relookup_without_contract_binding(self, code: str) -> bool:
        normalized = code or ""
        lowered = normalized.lower()
        if not any(
            token in lowered
            for token in (
                "authoritative relookup",
                "authoritative lookup",
                "stable-handle",
                "stable handle",
                "relookup",
                "cached pointer",
            )
        ):
            return False
        if self._has_relookup_contract_binding(normalized):
            return False
        return any(
            token in normalized
            for token in ("reportBug(", "emitReport(", "generateNonFatalErrorNode(", "generateErrorNode(")
        )

    def _uses_nullness_as_bounds_proof(self, code: str) -> bool:
        normalized = code or ""
        for match in re.finditer(r"State->is(?:Non)?Null\((?P<expr>[^)]*)\)", normalized):
            window = normalized[max(0, match.start() - 220): match.end() + 260]
            if "return;" not in window:
                continue
            if not any(token in window for token in ("SizeSym", "SizeSVal", "SrcSVal", "Length", "length", "size", "copy", "strlen")):
                continue
            return True
        return False

    def _drops_symbolic_size_paths(self, code: str) -> bool:
        normalized = code or ""
        patterns = (
            r"if\s*\(\s*!\s*(srcLength|copySize|bufferSize|destSize|requestedBytes|sourceLength)\s*\)\s*return\s*;",
            r"if\s*\(\s*!\s*(srcLength|copySize|bufferSize|destSize|requestedBytes|sourceLength)\s*\)\s*\{\s*return\s*;\s*\}",
        )
        if not any(re.search(pattern, normalized) for pattern in patterns):
            return False
        return any(
            token in normalized
            for token in (
                'FuncName == "strcpy"',
                'FuncName == "strcat"',
                'FuncName == "sprintf"',
                'FuncName == "gets"',
                'FuncName == "memcpy"',
                'hasName("strcpy")',
                'hasName("strcat")',
                'hasName("memcpy")',
            )
        )

    def _uses_location_type_only_for_buffer_size(self, code: str) -> bool:
        normalized = code or ""
        if "getLocationType()" not in normalized:
            return False
        if "FieldRegion" in normalized or "ElementRegion" in normalized or "getSuperRegion()" in normalized:
            return False
        if self._has_alternative_buffer_size_recovery(normalized):
            return False
        if "getRegionSize" not in normalized and "destSize" not in normalized:
            return False
        return any(
            token in normalized
            for token in (
                'FuncName == "strcpy"',
                'FuncName == "strcat"',
                'FuncName == "sprintf"',
                'FuncName == "gets"',
                'FuncName == "memcpy"',
                "checkUnboundedStringFunction",
                "checkMemcpyWithoutBoundCheck",
            )
        )

    def _uses_field_or_var_only_buffer_recovery(self, code: str) -> bool:
        normalized = code or ""
        if "FieldRegion" not in normalized and "VarRegion" not in normalized:
            return False
        if "StripCasts(" in normalized:
            return False
        if "ElementRegion" in normalized or "getSuperRegion(" in normalized:
            return False
        if not any(
            token in normalized
            for token in (
                "getTypeSizeInChars(",
                "getAsConstantArrayType(",
                "ConstantArrayType",
                "isArrayType(",
            )
        ):
            return False
        return any(
            token in normalized
            for token in (
                'FuncName == "strcpy"',
                'FuncName == "strcat"',
                'FuncName == "memcpy"',
                'FuncName == "memmove"',
                "fixed-size buffer",
                "destination capacity",
            )
        )

    def _is_semantic_helper_candidate(self, name: str, params: str) -> bool:
        lowered = str(name or "").lower()
        if lowered in {"checkprecall", "checkpostcall", "checklocation"}:
            return False
        if not any(token in lowered for token in self._CSA_SEMANTIC_HELPER_NAME_TOKENS):
            return False
        if self._CSA_SEMANTIC_HELPER_PARAM_PATTERN.search(params or ""):
            return True
        return any(token in lowered for token in ("guard", "barrier", "overflow", "uaf", "useafterfree"))

    def _has_alternative_buffer_size_recovery(self, code: str) -> bool:
        return any(
            token in (code or "")
            for token in (
                "getAsArrayType(",
                "getAsConstantArrayType(",
                "ConstantArrayType",
                "getTypeSizeInChars(",
                "ASTContext",
                "C.getASTContext()",
                "getASTContext()",
            )
        )

    def _reports_missing_capacity_without_semantics(self, code: str) -> bool:
        normalized = code or ""
        if not re.search(r"destination (?:buffer size|capacity) validation", normalized, re.IGNORECASE):
            return False
        if not any(
            token in normalized
            for token in (
                'FuncName == "strcpy"',
                'FuncName == "strcat"',
                'FuncName == "memcpy"',
                'FuncName == "memmove"',
            )
        ):
            return False
        if self._has_destination_capacity_modeling(normalized):
            return False
        if self._has_guard_barrier_binding(normalized):
            return False
        return True

    def _uses_length_or_name_heuristics_without_capacity_model(self, code: str) -> bool:
        normalized = code or ""
        if self._has_destination_capacity_modeling(normalized):
            return False
        length_heuristics = (
            '.contains("len")',
            '.contains("size")',
            '.contains("bytes")',
            'FD->getName() == "strlen"',
            'FD->getName() == "strnlen"',
            'CalleeName == "strlen"',
            'CalleeName == "strnlen"',
        )
        if not any(token in normalized for token in length_heuristics):
            return False
        return any(
            token in normalized
            for token in (
                'FuncName == "memcpy"',
                'FuncName == "memmove"',
                "destination capacity validation",
            )
        )

    def _has_destination_capacity_modeling(self, code: str) -> bool:
        return any(
            token in (code or "")
            for token in (
                "MemRegion",
                "TypedRegion",
                "ElementRegion",
                "FieldRegion",
                "SymbolicRegion",
                "getAsRegion(",
                "getLocationType(",
                "getAsArrayType(",
                "getAsConstantArrayType(",
                "ConstantArrayType",
                "getTypeSizeInChars(",
                "getDynamicExtent(",
                "getSuperRegion(",
                "getASTContext(",
                "C.getASTContext(",
                "ASTContext",
            )
        )

    def _has_guard_barrier_binding(self, code: str) -> bool:
        normalized = code or ""
        ast_navigation = any(
            token in normalized
            for token in (
                "getParents(",
                "CompoundStmt",
                "IfStmt",
                "getCond(",
                "getThen(",
                "ReturnStmt",
                "body()",
            )
        )
        if not ast_navigation:
            return False
        comparison_logic = any(
            token in normalized
            for token in (
                "BO_GE",
                "BO_GT",
                "BO_LE",
                "BO_LT",
                "isComparisonOp(",
                "BinaryOperator::isComparisonOp",
                "BinaryOperator",
                "getLHS(",
                "getRHS(",
            )
        )
        call_binding = any(
            token in normalized
            for token in (
                "Call.getArgExpr(",
                "Call.getArgSVal(",
                "DeclRefExpr",
                "MemberExpr",
                "IgnoreParenImpCasts(",
            )
        )
        role_binding = any(
            token in normalized
            for token in (
                "sizeof",
                "HasCompanionSizeParameter",
                "getTypeSizeInChars(",
                "getAsConstantArrayType(",
                "UnaryExprOrTypeTraitExpr",
            )
        )
        return comparison_logic and call_binding and role_binding

    def _lacks_same_call_barrier_binding(self, code: str) -> bool:
        normalized = code or ""
        if not self._has_destination_capacity_modeling(normalized):
            return False
        if self._has_guard_barrier_binding(normalized):
            return False
        if not re.search(r"destination (?:buffer size|capacity) validation", normalized, re.IGNORECASE):
            return False
        return any(
            token in normalized
            for token in (
                'FuncName == "memcpy"',
                'FuncName == "memmove"',
                "checkMemcpyOperation",
                "missing destination capacity validation",
            )
        )


    def _dedupe(self, items: List[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped[:6]
