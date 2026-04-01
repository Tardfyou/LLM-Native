"""
CodeQL 查询生成工具

提供:
- 根据漏洞模式生成 QL 查询
- QL 语法验证
- 查询模板库
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass

from loguru import logger

from ..agent.tools import Tool, ToolResult
from ..utils.vulnerability_taxonomy import normalize_vulnerability_type, supported_vulnerability_types


@dataclass
class QLQueryTemplate:
    """QL 查询模板"""
    name: str
    category: str
    description: str
    template: str
    params: List[str]


# 常用 QL 查询模板
QL_TEMPLATES = {
    "null_dereference": QLQueryTemplate(
        name="null_dereference",
        category="memory",
        description="检测空指针解引用",
        template="""
import cpp

from PointerDereferenceExpr deref
select deref, "Potential null pointer dereference."
""",
        params=["deref_expr"]
    ),

    "buffer_overflow": QLQueryTemplate(
        name="buffer_overflow",
        category="memory",
        description="检测缓冲区溢出",
        template="""
import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance

predicate isUnboundedWriteTarget(Function target) {
  target.hasName("strcpy") or
  target.hasName("strcat") or
  target.hasName("gets") or
  target.hasName("sprintf")
}

predicate isLengthBoundWriteTarget(Function target) {
  target.hasName("memcpy") or
  target.hasName("memmove") or
  target.hasName("strncpy") or
  target.hasName("strncat")
}

predicate isFormattingWriteTarget(Function target) {
  target.hasName("snprintf") or
  target.hasName("vsnprintf")
}

predicate destinationExpr(FunctionCall call, Expr dest) {
  dest = call.getArgument(0)
}

predicate exprContainsVariableAccess(Expr root, VariableAccess access) {
  access = root or root.getAChild*() = access
}

predicate exprContainsFieldAccess(Expr root, FieldAccess access) {
  access = root or root.getAChild*() = access
}

predicate sameValueExpr(Expr left, Expr right) {
  left = right
  or
  exists(VariableAccess l, VariableAccess r |
    exprContainsVariableAccess(left, l) and
    exprContainsVariableAccess(right, r) and
    l.getTarget() = r.getTarget()
  )
  or
  exists(FieldAccess l, FieldAccess r |
    exprContainsFieldAccess(left, l) and
    exprContainsFieldAccess(right, r) and
    l.getTarget() = r.getTarget() and
    sameValueExpr(l.getQualifier(), r.getQualifier())
  )
}

predicate writesIntoFixedBuffer(FunctionCall call, Expr dest) {
  destinationExpr(call, dest) and
  (
    exists(VariableAccess dst, Variable v |
      exprContainsVariableAccess(dest, dst) and
      v = dst.getTarget() and
      v.getType() instanceof ArrayType
    )
    or
    exists(FieldAccess dst, Field f |
      exprContainsFieldAccess(dest, dst) and
      f = dst.getTarget() and
      f.getType() instanceof ArrayType
    )
  )
}

predicate sourceExpr(FunctionCall call, Expr src) {
  exists(Function target |
    target = call.getTarget() and
    (
      (
        target.hasName("strcpy") or
        target.hasName("strcat") or
        target.hasName("memcpy") or
        target.hasName("memmove") or
        target.hasName("strncpy") or
        target.hasName("strncat")
      ) and
      src = call.getArgument(1)
    )
  )
}

predicate explicitBoundArg(FunctionCall call, Expr bound) {
  exists(Function target |
    target = call.getTarget() and
    (
      isLengthBoundWriteTarget(target) and
      bound = call.getArgument(2)
      or
      isFormattingWriteTarget(target) and
      bound = call.getArgument(1)
    )
  )
}

predicate isSourceLengthMeasurement(Expr expr, Expr src) {
  exists(FunctionCall lenCall, Function target |
    expr = lenCall and
    target = lenCall.getTarget() and
    (target.hasName("strlen") or target.hasName("strnlen")) and
    sameValueExpr(lenCall.getArgument(0), src)
  )
}

predicate dominatingAssignedValue(VariableAccess access, Expr value, FunctionCall call) {
  access.getEnclosingFunction() = call.getEnclosingFunction() and
  access.getTarget().getAnAssignedValue() = value and
  value.getEnclosingFunction() = call.getEnclosingFunction() and
  bbDominates(value.getBasicBlock(), call.getBasicBlock())
}

predicate trackedLengthExpr(FunctionCall call, Expr measured) {
  explicitBoundArg(call, measured)
  or
  exists(Expr src |
    sourceExpr(call, src) and
    isSourceLengthMeasurement(measured, src)
  )
  or
  exists(VariableAccess access, Expr value, Expr src |
    sourceExpr(call, src) and
    dominatingAssignedValue(access, value, call) and
    isSourceLengthMeasurement(value, src) and
    (
      measured = access
      or
      exists(Expr bound |
        explicitBoundArg(call, bound) and
        bound.getAChild*() = access and
        measured = access
      )
    )
  )
}

predicate isDestinationCapacityExpr(Expr expr, Expr dest) {
  exists(SizeofExprOperator sizeOf |
    expr = sizeOf and
    sameValueExpr(sizeOf.getExprOperand(), dest)
  )
}

predicate destinationCapacityCarrier(FunctionCall call, Expr capacity) {
  exists(Expr dest |
    destinationExpr(call, dest) and
    (
      isDestinationCapacityExpr(capacity, dest)
      or
      exists(VariableAccess access, Expr value |
        dominatingAssignedValue(access, value, call) and
        isDestinationCapacityExpr(value, dest) and
        capacity = access
      )
    )
  )
}

predicate explicitBoundMatchesDestinationCapacity(FunctionCall call) {
  exists(Expr bound, Expr capacity |
    explicitBoundArg(call, bound) and
    destinationCapacityCarrier(call, capacity) and
    sameValueExpr(bound, capacity)
  )
}

predicate hasPatchStyleBoundsGuard(FunctionCall call) {
  exists(Expr measured, Expr capacity, GuardCondition guard |
    trackedLengthExpr(call, measured) and
    destinationCapacityCarrier(call, capacity) and
    (
      guard.ensuresLt(measured, capacity, 0, call.getBasicBlock(), true)
      or
      guard.ensuresLt(measured, capacity, 1, call.getBasicBlock(), true)
    )
  )
}

from FunctionCall call, Function target, Expr dest, string message
where
  target = call.getTarget() and
  writesIntoFixedBuffer(call, dest) and
  (
    target.hasName("gets") and
    message = "Fixed-size destination is passed to gets without any destination-capacity contract."
    or
    isUnboundedWriteTarget(target) and
    not target.hasName("gets") and
    not hasPatchStyleBoundsGuard(call) and
    message = "Unbounded write into a fixed-size destination is not dominated by a destination-capacity guard."
    or
    isLengthBoundWriteTarget(target) and
    not explicitBoundMatchesDestinationCapacity(call) and
    not hasPatchStyleBoundsGuard(call) and
    message = "Length-driven write into a fixed-size destination is not tied to the destination capacity or a dominating bounds guard."
    or
    isFormattingWriteTarget(target) and
    not explicitBoundMatchesDestinationCapacity(call) and
    not hasPatchStyleBoundsGuard(call) and
    message = "Formatting write into a fixed-size destination uses a size argument that is not tied to the destination capacity."
  )
select call, message
""",
        params=["call_expr"]
    ),

    "use_after_free": QLQueryTemplate(
        name="use_after_free",
        category="memory",
        description="检测释放后使用",
        template="""
import cpp

predicate hasStableHandleSibling(Field pointerField, Field handleField) {
  handleField.getDeclaringType() = pointerField.getDeclaringType() and
  handleField.getName() = pointerField.getName() + "_id" and
  handleField.getType() instanceof IntegralType
}

predicate isManagedCachedPointerField(Field pointerField) {
  pointerField.getType() instanceof PointerType and
  exists(Field handleField | hasStableHandleSibling(pointerField, handleField))
}

predicate isDirectCachedPointerDereference(FieldAccess receiver, Field pointerField) {
  receiver.getTarget() = pointerField and
  isManagedCachedPointerField(pointerField)
}

from FieldAccess use, FieldAccess receiver, Field pointerField
where
  receiver = use.getQualifier() and
  isDirectCachedPointerDereference(receiver, pointerField)
select use,
  "Direct dereference of cached managed pointer field `" + pointerField.getName() +
  "` bypasses stable-handle relookup and can preserve a stale/dangling alias."
""",
        params=["free_call", "use_expr"]
    ),

    "double_free": QLQueryTemplate(
        name="double_free",
        category="memory",
        description="检测双重释放",
        template="""
import cpp

from FunctionCall free1, FunctionCall free2, Variable v, Function target1, Function target2
where
    target1 = free1.getTarget() and
    target2 = free2.getTarget() and
    target1.hasName("free") and
    target2.hasName("free") and
    free1 != free2 and
    free1.getArgument(0) instanceof VariableAccess and
    free2.getArgument(0) instanceof VariableAccess and
    v = free1.getArgument(0).(VariableAccess).getTarget() and
    v = free2.getArgument(0).(VariableAccess).getTarget() and
    free1.getEnclosingFunction() = free2.getEnclosingFunction() and
    free1.getLocation().getStartLine() < free2.getLocation().getStartLine()
select free2, "Potential double free of " + v.getName()
""",
        params=["free1", "free2"]
    ),

    "memory_leak": QLQueryTemplate(
        name="memory_leak",
        category="memory",
        description="检测潜在内存泄漏起点",
        template="""
import cpp

from FunctionCall allocCall, Function target
where
    target = allocCall.getTarget() and
    (
        target.hasName("malloc") or
        target.hasName("calloc") or
        target.hasName("realloc") or
        target.hasName("strdup")
    )
select allocCall, "Allocation site requires ownership and cleanup review."
""",
        params=["alloc_call"]
    ),

    "integer_overflow": QLQueryTemplate(
        name="integer_overflow",
        category="arithmetic",
        description="检测整数溢出",
        template="""
import cpp

from BinaryArithmeticOperation op
where
    op.getType() instanceof IntegralType
select op, "Potential integer overflow candidate."
""",
        params=["op_expr"]
    ),

    "divide_by_zero": QLQueryTemplate(
        name="divide_by_zero",
        category="arithmetic",
        description="检测除零候选点",
        template="""
import cpp

from BinaryOperation op
where
    op.getOperator() = "/" or
    op.getOperator() = "%"
select op, "Division or modulo requires proof that the divisor is non-zero."
""",
        params=["op_expr"]
    ),

    "format_string": QLQueryTemplate(
        name="format_string",
        category="security",
        description="检测格式化字符串漏洞",
        template="""
import cpp

from FunctionCall call, Function target, Expr fmtArg
where
    target = call.getTarget() and
    (
        target.hasName("printf") or
        target.hasName("sprintf") or
        target.hasName("snprintf")
    ) and
    fmtArg = call.getArgument(0) and
    not fmtArg instanceof StringLiteral
select call, "Non-literal format string passed to " + target.getName()
""",
        params=["call_expr"]
    ),

    "command_injection": QLQueryTemplate(
        name="command_injection",
        category="security",
        description="检测命令执行敏感点",
        template="""
import cpp

from FunctionCall call, Function target
where
    target = call.getTarget() and
    (
        target.hasName("system") or
        target.hasName("popen") or
        target.hasName("execl") or
        target.hasName("execve")
    )
select call, "Command execution sink requires strict input validation or allowlisting."
""",
        params=["call_expr"]
    ),

    "taint_tracking": QLQueryTemplate(
        name="taint_tracking",
        category="dataflow",
        description="污点追踪模板",
        template="""
import cpp

from FunctionCall sourceCall, FunctionCall sinkCall, Function source, Function sink
where
        source = sourceCall.getTarget() and
        sink = sinkCall.getTarget() and
    (
            source.hasName("getenv") or
            source.hasName("read") or
            source.hasName("recv")
    ) and
    (
            sink.hasName("system") or
            sink.hasName("execve") or
            sink.hasName("execl")
    ) and
    sourceCall.getEnclosingFunction() = sinkCall.getEnclosingFunction() and
    sourceCall.getLocation().getStartLine() <= sinkCall.getLocation().getStartLine()
select sinkCall, "Suspicious source-to-sink pattern in the same function."
""",
        params=["source", "sink"]
    ),

    "sql_injection": QLQueryTemplate(
        name="sql_injection",
        category="security",
        description="检测 SQL 注入",
        template="""
import cpp

from FunctionCall sourceCall, FunctionCall sinkCall, Function source, Function sink
where
        source = sourceCall.getTarget() and
        sink = sinkCall.getTarget() and
    (
            source.hasName("getenv") or
            source.hasName("fgets") or
            source.hasName("scanf")
    ) and
    (
            sink.hasName("mysql_query") or
            sink.hasName("sqlite3_exec")
    ) and
    sourceCall.getEnclosingFunction() = sinkCall.getEnclosingFunction() and
    sourceCall.getLocation().getStartLine() <= sinkCall.getLocation().getStartLine()
select sinkCall, "Suspicious user-input handling before SQL execution."
""",
        params=["source", "sink"]
    ),

    "path_traversal": QLQueryTemplate(
        name="path_traversal",
        category="security",
        description="检测路径处理敏感点",
        template="""
import cpp

from FunctionCall call, Function target
where
    target = call.getTarget() and
    (
        target.hasName("open") or
        target.hasName("fopen") or
        target.hasName("creat")
    )
select call, "Filesystem sink requires canonicalization or root-boundary validation."
""",
        params=["call_expr"]
    ),

    "race_condition": QLQueryTemplate(
        name="race_condition",
        category="concurrency",
                description="检测潜在竞态条件（共享状态未同步 + TOCTOU）",
        template="""
import cpp

predicate isMutexLockCall(FunctionCall call) {
    exists(Function target |
        target = call.getTarget() and
        (
            target.hasName("pthread_mutex_lock") or
            target.hasName("mtx_lock")
        )
    )
}

predicate isMutexUnlockCall(FunctionCall call) {
    exists(Function target |
        target = call.getTarget() and
        (
            target.hasName("pthread_mutex_unlock") or
            target.hasName("mtx_unlock")
        )
    )
}

predicate hasLockingInFunction(Function f) {
    exists(FunctionCall l | l.getEnclosingFunction() = f and isMutexLockCall(l)) and
    exists(FunctionCall u | u.getEnclosingFunction() = f and isMutexUnlockCall(u))
}

predicate isLikelySharedState(Variable v) {
    v instanceof GlobalVariable
    or
    // 覆盖常见静态全局命名，避免仅依赖 GlobalVariable 丢失 file-scope static
    v.getName().regexpMatch("^(g_|s_|global_|shared_).+")
}

predicate isAtomicitySensitiveAccess(Expr e) {
    // 赋值 / 复合赋值通常是竞态高风险点
    e instanceof AssignExpr
}

predicate isFileCheckCall(FunctionCall call) {
    exists(Function target |
        target = call.getTarget() and
        (
            target.hasName("access") or
            target.hasName("stat") or
            target.hasName("lstat")
        )
    )
}

predicate isFileUseCall(FunctionCall call) {
    exists(Function target |
        target = call.getTarget() and
        (
            target.hasName("open") or
            target.hasName("fopen") or
            target.hasName("creat")
        )
    )
}

from Expr node, string message
where
    (
        // 模式1：函数访问全局变量且缺少互斥保护
        exists(VariableAccess va, Variable v, Function f, Expr risky |
            isLikelySharedState(v) and
            va.getTarget() = v and
            va.getEnclosingFunction() = f and
            not hasLockingInFunction(f) and
            risky.getEnclosingFunction() = f and
            isAtomicitySensitiveAccess(risky) and
            node = risky and
            message = "Potential race condition: access to global shared state without mutex protection"
        )
        or
        // 模式2：TOCTOU（先检查后使用同一路径）
        exists(FunctionCall checkCall, FunctionCall useCall, Expr checkedPath, Expr usedPath, Function f |
            isFileCheckCall(checkCall) and
            isFileUseCall(useCall) and
            checkCall.getEnclosingFunction() = f and
            useCall.getEnclosingFunction() = f and
            checkedPath = checkCall.getArgument(0) and
            usedPath = useCall.getArgument(0) and
            checkedPath.toString() = usedPath.toString() and
            checkCall.getLocation().getStartLine() < useCall.getLocation().getStartLine() and
            not hasLockingInFunction(f) and
            node = useCall and
            message = "Potential TOCTOU race: resource checked before use without synchronization"
        )
    )
select node, message
""",
        params=["lock_call"]
    ),

    "toctou": QLQueryTemplate(
        name="toctou",
        category="concurrency",
        description="检测典型 TOCTOU 文件竞态",
        template="""
import cpp

from FunctionCall checkCall, FunctionCall useCall, Function checkTarget, Function useTarget, Expr checkedPath, Expr usedPath
where
    checkTarget = checkCall.getTarget() and
    useTarget = useCall.getTarget() and
    (
        checkTarget.hasName("access") or
        checkTarget.hasName("stat") or
        checkTarget.hasName("lstat")
    ) and
    (
        useTarget.hasName("open") or
        useTarget.hasName("fopen") or
        useTarget.hasName("creat")
    ) and
    checkedPath = checkCall.getArgument(0) and
    usedPath = useCall.getArgument(0) and
    checkedPath.toString() = usedPath.toString() and
    checkCall.getEnclosingFunction() = useCall.getEnclosingFunction() and
    checkCall.getLocation().getStartLine() < useCall.getLocation().getStartLine()
select useCall, "Potential TOCTOU race: path checked before use."
""",
        params=["check_call", "use_call"]
    ),

    "out_of_bounds_read": QLQueryTemplate(
        name="out_of_bounds_read",
        category="memory",
        description="检测越界读取候选点",
        template="""
import cpp

from ArrayExpr expr
select expr, "Array or pointer-based read requires proof that the access stays in bounds."
""",
        params=["array_expr"]
    ),

    "uninitialized_variable": QLQueryTemplate(
        name="uninitialized_variable",
        category="memory",
        description="检测可能缺少初始化证明的读取",
        template="""
import cpp

from VariableAccess use
select use, "Variable access requires initialization proof on the active path."
""",
        params=["var_access"]
    ),
}

TEMPLATE_ALIASES = {
    "stack_overflow": "buffer_overflow",
    "heap_overflow": "buffer_overflow",
    "out_of_bounds_write": "buffer_overflow",
    "buffer_overread": "out_of_bounds_read",
    "integer_underflow": "integer_overflow",
}


class CodeQLGenerateTool(Tool):
    """CodeQL 查询生成工具。"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    @property
    def name(self) -> str:
        return "generate_codeql_query"

    @property
    def description(self) -> str:
        return "根据漏洞模式生成 CodeQL 查询代码。"

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query_name": {"type": "string", "description": "查询名称"},
                "vulnerability_type": {
                    "type": "string",
                    "description": "漏洞类型",
                    "enum": sorted(supported_vulnerability_types(include_extended=True) | {"custom", "unknown"}),
                },
                "description": {"type": "string", "description": "查询描述"},
                "pattern_description": {"type": "string", "description": "模式补充说明"},
                "custom_query": {"type": "string", "description": "自定义 QL 查询（可选）"},
                "include_header": {"type": "boolean", "default": True},
            },
            "required": ["query_name", "vulnerability_type", "description"],
        }

    def execute(self, **kwargs) -> ToolResult:
        query_name = kwargs.get("query_name")
        vulnerability_type = kwargs.get("vulnerability_type")
        description = kwargs.get("description", "")
        pattern_description = kwargs.get("pattern_description", "")
        custom_query = kwargs.get("custom_query")
        include_header = kwargs.get("include_header", True)

        if not query_name or not vulnerability_type:
            return ToolResult(success=False, output="", error="缺少必需参数: query_name 或 vulnerability_type")

        try:
            normalized_vuln = normalize_vulnerability_type(vulnerability_type, vulnerability_type)
            resolved_vuln = TEMPLATE_ALIASES.get(normalized_vuln, normalized_vuln)
            if custom_query:
                query_code = custom_query
            elif resolved_vuln in {"unknown", "custom"}:
                query_code = self._build_generic_starter_query(pattern_description)
            elif resolved_vuln in QL_TEMPLATES:
                template = QL_TEMPLATES[resolved_vuln]
                query_code = self._customize_template(template, pattern_description)
            else:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"未知漏洞类型: {vulnerability_type}，可用: {list(QL_TEMPLATES.keys())}",
                )

            if include_header:
                query_code = self._add_header(query_name, description, normalized_vuln) + query_code

            validation = self._validate_query(query_code)
            if not validation["valid"]:
                logger.warning(f"QL 查询语法可能有问题: {validation['issues']}")

            query_file = f"{query_name}.ql"
            return ToolResult(
                success=True,
                output=(
                    f"成功生成 CodeQL 查询: {query_name}\n"
                    "这只是一份起始查询骨架。写入前先对照当前分析器自己的补丁分析结论与高相关 RAG 结果，确认主触发语义、patched silence/barrier 和泛化轴是否真的匹配当前样本；"
                    "如果 AST/CFG/DataFlow API、类型名或成员方法的 exact 写法不确定，必须先检索知识库再改，不要盲修。"
                    "如果它仍按 callee 名称一把抓、未建模 size/guard/barrier，review_artifact 会拒绝，届时必须做语义化定点收紧。\n\n"
                    f"{query_code}"
                ),
                metadata={
                    "query_name": query_name,
                    "query_code": query_code,
                    "query_file": query_file,
                    "vulnerability_type": normalized_vuln,
                    "template_type": resolved_vuln,
                    "validation": validation,
                },
            )
        except Exception as e:
            logger.exception("生成 CodeQL 查询失败")
            return ToolResult(success=False, output="", error=f"生成查询失败: {e}")

    def _customize_template(self, template: QLQueryTemplate, pattern_description: str) -> str:
        query_code = template.template
        if pattern_description:
            safe_desc = self._to_block_comment(pattern_description)
            query_code = f"/*\nPattern:\n{safe_desc}\n*/\n{query_code}"
        return query_code

    def _build_generic_starter_query(self, pattern_description: str) -> str:
        comment = self._to_block_comment(pattern_description or "Patch-guided custom query. Refine around evidence-backed state, guard, API, and flow relations.")
        return f"""/*
Pattern:
{comment}
*/
import cpp

/**
 * Patch-guided generic query starter.
 * Replace the placeholder predicate with evidence-backed semantic conditions.
 */
predicate patchweaverCustomMatch(Stmt node) {{
  false
}}

from Stmt node
where patchweaverCustomMatch(node)
select node, "Patch-guided custom query placeholder. Refine with semantic evidence."
"""

    def _to_block_comment(self, text: str) -> str:
        """将任意文本安全转换为块注释内容，避免破坏 QL 语法。"""
        if not text:
            return ""

        normalized = str(text).replace("\r\n", "\n").replace("\r", "\n")
        normalized = normalized.replace("*/", "* /")
        return "\n".join(f"  {line}" for line in normalized.split("\n"))

    def _add_header(self, query_name: str, description: str, vulnerability_type: str) -> str:
        return f"""/**
 * @name {query_name}
 * @description {description}
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/custom/{vulnerability_type}
 * @tags security
 *       correctness
 */

"""

    def _validate_query(self, query_code: str) -> Dict[str, Any]:
        issues: List[str] = []
        if "import cpp" not in query_code:
            issues.append("缺少 import cpp")
        if "select" not in query_code:
            issues.append("缺少 select 子句")
        return {"valid": len(issues) == 0, "issues": issues}
