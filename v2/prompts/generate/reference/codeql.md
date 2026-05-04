CodeQL 首稿骨架参考。首轮生成时提供，后续修复专精，仅供参考，实际怎么写自己决定。

```ql
/**
 * @name PatchGuidedChecker
 * @description Patch-local detector query generated from a security fix.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/custom/patch-guided-checker
 */

import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance

/**
 * Patch-guided query starter.
 * 稳定 API：SizeofExprOperator, getTarget(), getQualifier(),
 * bbDominates(...), GuardCondition.ensuresLt(...)
 * 不要改写成 sizeof(...), ComparisonOperation 等伪 API
 */

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

predicate hasPatchStyleGuard(FunctionCall call, Expr measured, Expr capacity) {
  exists(GuardCondition guard |
    guard.ensuresLt(measured, capacity, 0, call.getBasicBlock(), true)
    or
    guard.ensuresLt(measured, capacity, 1, call.getBasicBlock(), true)
  )
}

predicate patchGuidedCandidate(FunctionCall call) {
  // 注意：dest/measured/capacity 要在同一个 exists() 里声明
  exists(Expr dest, Expr measured, Expr capacity |
    dest = call.getArgument(0) and
    // 在这里添加补丁暴露的真实条件
    not hasPatchStyleGuard(call, measured, capacity)
  ) and
  false // 替换为真实条件
}

from FunctionCall call
where patchGuidedCandidate(call)
select call, "Patch-guided candidate: describe the issue."
```
