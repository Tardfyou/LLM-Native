"""
修复Agent - 负责代码错误修复和优化

使用 Knighter 风格的插件架构
"""

import asyncio
import re
from typing import Dict, Any, Optional, List
from pathlib import Path

# 使用loguru以支持logger.success()等方法
from loguru import logger

from .base_agent import BaseAgent, AgentMessage
from ..prompts.prompt_manager import PromptManager
from ..lsp.clangd_client import ClangdClient
from ..builders.plugin_builder import PluginBuilder, convert_to_plugin_style

class RepairAgent(BaseAgent):
    """修复Agent - 负责代码错误修复和优化"""

    def __init__(self, prompt_manager: Optional[PromptManager] = None,
                 lsp_client: Optional[ClangdClient] = None,
                 llm_client: Optional[Any] = None):
        super().__init__("repair_agent", "code_repair")
        self.prompt_manager = prompt_manager
        self.lsp_client = lsp_client
        self.llm_client = llm_client  # 保存 LLM client 用于 LLM 修复
        # 使用插件构建器（Knighter 风格）
        self.plugin_builder = PluginBuilder()

        # 错误模式数据库
        self.error_patterns = self._load_error_patterns()

        # 存储当前修复的上下文 - 用于在整个修复过程中保持对话历史
        self.current_repair_context: Optional[Dict[str, Any]] = None

    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理接收到的消息"""
        if message.message_type == "repair_needed":
            return await self._handle_repair_needed(message)
        elif message.message_type == "optimize_code":
            return await self._handle_optimize_code(message)
        else:
            logger.warning(f"RepairAgent received unknown message type: {message.message_type}")
            return None

    async def _handle_repair_needed(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理修复请求"""
        try:
            code = message.content.get("code", "")
            issues = message.content.get("issues", [])

            # 执行修复
            repair_result = await self.execute_task({
                "code": code,
                "issues": issues,
                "task_type": "error_repair"
            })

            # 发送修复结果
            return await self.send_message(
                "validation_agent",
                "repair_complete",
                repair_result
            )

        except Exception as e:
            logger.error(f"RepairAgent error in repair_needed: {e}")
            return await self.send_message(
                "orchestrator",
                "repair_failed",
                {"error": str(e)}
            )

    async def _handle_optimize_code(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理代码优化请求"""
        try:
            code = message.content.get("code", "")
            optimization_goals = message.content.get("goals", ["performance", "readability"])

            # 执行优化
            optimization_result = await self.execute_task({
                "code": code,
                "goals": optimization_goals,
                "task_type": "code_optimization"
            })

            # 发送优化结果
            return await self.send_message(
                "validation_agent",
                "optimization_complete",
                optimization_result
            )

        except Exception as e:
            logger.error(f"RepairAgent error in optimize_code: {e}")
            return None

    async def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行修复任务"""
        import asyncio
        start_time = asyncio.get_event_loop().time()

        try:
            task_type = task_data.get("task_type", "repair")

            if task_type == "error_repair":
                result = await self._repair_errors(task_data)
            elif task_type == "code_optimization":
                result = await self._optimize_code(task_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")

            # 更新性能统计
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, result.get("success", False))

            return result

        except Exception as e:
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, False)
            raise e

    async def _repair_errors(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """修复代码错误 - 先规则修复，失败后使用 LLM 修复（KNighter 风格）"""
        code = task_data["code"]
        issues = task_data["issues"]
        attempt = task_data.get("attempt", 1)  # 获取当前尝试次数

        # 提取上下文信息 - 保持与初始生成的对话历史
        self.current_repair_context = {
            "vulnerability_type": task_data.get("vulnerability_type"),
            "vulnerability_description": task_data.get("vulnerability_description"),
            "vulnerability_pattern": task_data.get("vulnerability_pattern"),
            "analysis_context": task_data.get("analysis_context")
        }

        logger.info("")
        logger.info("🔧 Starting Error Repair Process")
        if self.current_repair_context.get("vulnerability_type"):
            logger.info(f"   Context: {self.current_repair_context['vulnerability_type']}")
        logger.info("-" * 60)

        # 1. 分类错误
        categorized_issues = self._categorize_issues(issues)
        total_issues = len(issues)

        logger.info(f"📊 Issue Analysis (Iteration {attempt}):")
        logger.info(f"   Total Issues: {total_issues}")
        for category, category_issues in categorized_issues.items():
            if category_issues:
                logger.info(f"   - {category}: {len(category_issues)}")

        # 2. 按优先级进行规则修复
        repaired_code = code
        fix_history = []
        total_fixes = 0
        any_fixes_applied = False

        for category, category_issues in categorized_issues.items():
            if not category_issues:
                continue

            category_display = category.replace('_', ' ').title()
            logger.info("")
            logger.info(f"🔨 Fixing {category_display} ({len(category_issues)} issues)...")

            if category == "api_errors":
                # 优先处理 Clang-21 API 错误
                repaired_code, fixes = self._fix_api_errors(repaired_code, category_issues)
                fix_history.extend(fixes)
                total_fixes += len(fixes)
                if fixes:
                    any_fixes_applied = True
                    logger.success(f"   ✅ Applied {len(fixes)} API fix(es)")
                    for fix in fixes[:5]:
                        logger.info(f"      • {fix}")
                else:
                    logger.warning(f"   ⚠️  No API fixes applied (will try LLM repair)")

            elif category == "syntax_errors":
                repaired_code, fixes = self._fix_syntax_errors(repaired_code, category_issues)
                fix_history.extend(fixes)
                total_fixes += len(fixes)
                if fixes:
                    any_fixes_applied = True
                    logger.success(f"   ✅ Applied {len(fixes)} syntax fix(es)")
                    for fix in fixes[:3]:
                        logger.info(f"      • {fix}")
                else:
                    logger.warning(f"   ⚠️  No fixes applied for syntax errors")

            elif category == "missing_includes":
                repaired_code, fixes = self._fix_missing_includes(repaired_code, category_issues)
                fix_history.extend(fixes)
                total_fixes += len(fixes)
                if fixes:
                    any_fixes_applied = True
                    logger.success(f"   ✅ Added {len(fixes)} missing include(s)")
                    for fix in fixes:
                        logger.info(f"      • {fix}")
                else:
                    logger.warning(f"   ⚠️  No includes added")

            elif category == "undefined_symbols":
                repaired_code, fixes = self._fix_undefined_symbols(repaired_code, category_issues)
                fix_history.extend(fixes)
                total_fixes += len(fixes)
                if fixes:
                    any_fixes_applied = True
                    logger.success(f"   ✅ Fixed {len(fixes)} undefined symbol(s)")
                    for fix in fixes:
                        logger.info(f"      • {fix}")
                else:
                    logger.warning(f"   ⚠️  No symbol fixes applied")

            elif category == "logic_errors":
                repaired_code, fixes = self._fix_logic_errors(repaired_code, category_issues)
                fix_history.extend(fixes)
                total_fixes += len(fixes)
                if fixes:
                    any_fixes_applied = True
                    logger.success(f"   ✅ Applied {len(fixes)} logic fix(es)")
                    for fix in fixes[:3]:
                        logger.info(f"      • {fix}")
                else:
                    logger.warning(f"   ⚠️  No logic fixes applied")

        # 3. 如果规则修复没有效果，使用 LLM 修复 (KNighter 风格)
        if not any_fixes_applied and total_issues > 0:
            logger.info("")
            logger.info("🤖 Rule-based repair failed, attempting LLM-based repair (KNighter style)...")

            # 将所有错误转换为字符串列表
            all_errors_str = [str(issue) for issue in issues]

            # 调用 LLM 修复 - 传递上下文保持对话历史
            repaired_code = await self.repair_with_llm(
                repaired_code,
                all_errors_str,
                attempt,
                self.current_repair_context  # 传递上下文
            )

            if repaired_code and repaired_code != code:
                code_changed = True
                fix_history.append(f"LLM-based repair (iteration {attempt})")
                total_fixes += 1
                logger.success(f"   ✅ LLM repair succeeded on iteration {attempt}")
            else:
                logger.warning(f"   ⚠️  LLM repair attempt {attempt} failed")

        # 4. LSP验证修复结果
        if self.lsp_client:
            logger.info("")
            logger.info("🔍 Validating repairs with LSP...")
            validation = await self.lsp_client.validate_code(repaired_code, "repaired_checker")
            if validation.get("has_errors", False):
                remaining_errors = len(validation["errors"])
                logger.warning(f"   ⚠️  Still have {remaining_errors} error(s) after initial repair")

                # 如果仍有错误，尝试更复杂的修复
                repaired_code, additional_fixes = await self._advanced_repair(
                    repaired_code, validation["errors"]
                )
                fix_history.extend(additional_fixes)
                total_fixes += len(additional_fixes)
                if additional_fixes:
                    logger.success(f"   ✅ Applied {len(additional_fixes)} advanced fix(es)")
            else:
                logger.success(f"   ✅ LSP validation passed - No remaining errors")

        # 汇总
        # 确保 repaired_code 不为 None，如果为 None 则使用原代码
        if repaired_code is None:
            repaired_code = code
            logger.warning("   ⚠️  LLM repair returned None, using original code as fallback")

        code_changed = (code != repaired_code)
        logger.info("")
        logger.info("=" * 60)
        if code_changed:
            logger.success(f"🎉 Repair Complete: {total_fixes} fix(es) applied")
            logger.info(f"   Code size: {len(code)} → {len(repaired_code)} bytes")
        else:
            logger.warning(f"⚠️  Repair Complete: No changes made to code")
        logger.info("=" * 60)

        return {
            "original_code": code,
            "repaired_code": repaired_code,
            "issues_fixed": issues,
            "fix_history": fix_history,
            "total_fixes": total_fixes,
            "code_changed": code_changed,
            "success": len(issues) > 0 and code_changed,
            "confidence_score": 0.7
        }

    async def _optimize_code(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """优化代码"""
        code = task_data["code"]
        goals = task_data.get("goals", ["performance"])

        optimized_code = code
        optimizations_applied = []

        # 根据优化目标进行优化
        if "performance" in goals:
            optimized_code, perf_opts = self._optimize_performance(optimized_code)
            optimizations_applied.extend(perf_opts)

        if "readability" in goals:
            optimized_code, read_opts = self._optimize_readability(optimized_code)
            optimizations_applied.extend(read_opts)

        if "maintainability" in goals:
            optimized_code, maint_opts = self._optimize_maintainability(optimized_code)
            optimizations_applied.extend(maint_opts)

        return {
            "original_code": code,
            "optimized_code": optimized_code,
            "optimizations_applied": optimizations_applied,
            "goals": goals,
            "success": True,
            "confidence_score": 0.8
        }

    def _categorize_issues(self, issues: List[str]) -> Dict[str, List[str]]:
        """分类错误"""
        categories = {
            "api_errors": [],  # Clang-21 API 错误 - 优先处理
            "syntax_errors": [],
            "missing_includes": [],
            "undefined_symbols": [],
            "logic_errors": [],
            "other": []
        }

        for issue in issues:
            issue_lower = issue.lower()
            # 优先检测 Clang-21 API 错误
            if any(keyword in issue for keyword in [
                "APSIntPtr", "SymbolRef", "no viable conversion",
                "invalid operands to binary expression",
                "no member named 'isZero'",
                "too many arguments to function call"
            ]):
                categories["api_errors"].append(issue)
            elif any(keyword in issue_lower for keyword in ["expected", "unexpected", "syntax"]):
                categories["syntax_errors"].append(issue)
            elif "no such file" in issue_lower or "include" in issue_lower:
                categories["missing_includes"].append(issue)
            elif any(keyword in issue_lower for keyword in ["undefined", "not declared"]):
                categories["undefined_symbols"].append(issue)
            elif any(keyword in issue_lower for keyword in ["logic", "semantic", "type"]):
                categories["logic_errors"].append(issue)
            else:
                categories["other"].append(issue)

        return categories

    def _fix_syntax_errors(self, code: str, issues: List[str]) -> tuple[str, List[str]]:
        """修复语法错误"""
        fixed_code = code
        fixes_applied = []

        for issue in issues:
            # 简单的语法错误修复
            if "expected ';'" in issue:
                # 尝试添加缺失的分号
                fixed_code, fix = self._add_missing_semicolon(fixed_code, issue)
                if fix:
                    fixes_applied.append(f"Added missing semicolon: {fix}")

            elif "expected '}'" in issue:
                # 尝试添加缺失的右大括号
                fixed_code, fix = self._add_missing_brace(fixed_code, issue)
                if fix:
                    fixes_applied.append(f"Added missing brace: {fix}")

        return fixed_code, fixes_applied

    def _fix_api_errors(self, code: str, issues: List[str]) -> tuple[str, List[str]]:
        """
        修复 Clang-21 API 错误 - 规则修复

        处理常见的 API 兼容性问题：
        1. APSIntPtr 与 int 比较 - 需要解引用
        2. APSIntPtr.isZero() - 需要使用箭头操作符
        3. nonloc::SymbolVal(Sym) - 需要使用 SVB.makeSymbolVal(Sym)
        4. 函数参数数量错误
        5. APSIntPtr 转 bool - 需要检查指针是否为空
        6. EvaluateAsInt API 错误
        """
        fixed_code = code
        fixes_applied = []
        import re

        # 1. 修复 APSIntPtr.isZero() -> APSIntPtr->isZero()
        pattern_isZero_dot = r'(\w+)\.isZero\(\)'
        def replace_isZero_dot(match):
            var_name = match.group(1)
            # 检查是否是 APSIntPtr 类型（通过变量名推断）
            if any(hint in var_name.lower() for hint in ['apsint', 'concrete', 'val', 'int']):
                return f'{var_name}->isZero()'
            return match.group(0)

        new_code = re.sub(pattern_isZero_dot, replace_isZero_dot, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed APSIntPtr.isZero() -> APSIntPtr->isZero()")
            fixed_code = new_code

        # 2. 修复 nonloc::SymbolVal(Sym) -> SVB.makeSymbolVal(Sym)
        pattern_symbolval = r'nonloc::SymbolVal\((\w+)\)'
        def replace_symbolval(match):
            sym_name = match.group(1)
            return f'C.getSValBuilder().makeSymbolVal({sym_name})'

        new_code = re.sub(pattern_symbolval, replace_symbolval, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed nonloc::SymbolVal(Sym) -> C.getSValBuilder().makeSymbolVal(Sym)")
            fixed_code = new_code

        # 3. 修复 SVal SymVal = nonloc::SymbolVal(...) 模式
        pattern_sval_symbolval = r'SVal\s+(\w+)\s*=\s*nonloc::SymbolVal\((\w+)\)'
        def replace_sval_symbolval(match):
            var_name = match.group(1)
            sym_name = match.group(2)
            return f'SVal {var_name} = C.getSValBuilder().makeSymbolVal({sym_name})'

        new_code = re.sub(pattern_sval_symbolval, replace_sval_symbolval, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed SVal assignment from nonloc::SymbolVal")
            fixed_code = new_code

        # 4. 修复 APSIntPtr 与 int 直接比较
        pattern_getvalue_compare = r'(\w+)->getValue\(\)\s*(==|!=)\s*(\d+)'
        def replace_getvalue_compare(match):
            var_name = match.group(1)
            op = match.group(2)
            value = match.group(3)
            return f'*{var_name}->getValue() {op} {value}'

        new_code = re.sub(pattern_getvalue_compare, replace_getvalue_compare, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed APSIntPtr comparison: added dereference")
            fixed_code = new_code

        # 5. 修复 getAs<nonloc::ConcreteInt>()->getValue() == 0
        pattern_concreteval = r'(getAs<[^>]+>\(\))->getValue\(\)\s*(==|!=)\s*(\d+)'
        def replace_concreteval(match):
            getter = match.group(1)
            op = match.group(2)
            value = match.group(3)
            return f'*({getter})->getValue() {op} {value}'

        new_code = re.sub(pattern_concreteval, replace_concreteval, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed ConcreteInt getValue() comparison")
            fixed_code = new_code

        # 6. 修复 APSIntPtr 转 bool 错误 - if (auto IntPtr = ConcreteVal->getValue())
        # 问题：getValue() 返回指针，不能直接用于 if 条件
        pattern_ptr_to_bool = r'if\s*\(\s*auto\s+(\w+)\s*=\s*([^()]+)->getValue\(\)\s*\)'
        def replace_ptr_to_bool(match):
            var_name = match.group(1)
            getter = match.group(2)
            # 正确写法：if (auto IntPtr = ConcreteVal->getValue(); IntPtr)
            return f'if (auto {var_name} = {getter}->getValue(); {var_name})'

        new_code = re.sub(pattern_ptr_to_bool, replace_ptr_to_bool, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed APSIntPtr to bool conversion")
            fixed_code = new_code

        # 7. 修复 evalAsInt 函数 - 完整替换为正确的实现
        # 匹配整个函数并替换
        pattern_eval_func = r'bool\s+evalAsInt\s*\([^)]*llvm::APSInt\s*&[^}]*?return\s+[^;]+->\s*EvaluateAsInt\s*\([^)]*\)\s*;'
        def replace_eval_func(match):
            return '''bool evalAsInt(const Expr *E, llvm::APSInt &Result,
                 CheckerContext &C) const {
    return EvaluateExprToInt(Result, E, C);
  }'''

        new_code = re.sub(pattern_eval_func, replace_eval_func, fixed_code, flags=re.DOTALL)
        if new_code != fixed_code:
            fixes_applied.append("Fixed evalAsInt function - using EvaluateExprToInt from utility.h")
            fixed_code = new_code

        # 8. 修复另一种模式 - 逐行匹配 EvaluateAsInt 调用
        pattern_eval_line = r'(\w+)\s*->\s*EvaluateAsInt\s*\(\s*Result\s*,\s*\w+\s*\.getASTContext\s*\(\s*\)\s*\)'
        def replace_eval_line(match):
            expr_var = match.group(1)
            return f'EvaluateExprToInt(Result, {expr_var}, C)'

        new_code = re.sub(pattern_eval_line, replace_eval_line, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed EvaluateAsInt call - using EvaluateExprToInt")
            fixed_code = new_code

        # 9. 修复 APSIntPtr 直接用于 if 条件 (没有 auto 声明)
        # 例如：if (ConcreteVal->getValue())
        pattern_direct_ptr_check = r'if\s*\(\s*([^)]+->getValue\(\))\s*\)'
        def replace_direct_ptr_check(match):
            getter = match.group(1)
            # 如果 getValue() 返回指针，需要检查指针是否为空
            return f'if ({getter})'

        # 这个模式可能过于激进，暂时不应用
        # new_code = re.sub(pattern_direct_ptr_check, replace_direct_ptr_check, fixed_code)

        # 10. 修复 ProgramStateTrait MAP 的 get() 返回类型 - CRITICAL FIX
        # State->get<MapTrait>(Key) 的返回值类型取决于 Value 类型：
        # - 对于指针类型 (如 const MemRegion*): 返回 const Value*const * (double pointer)
        # - 对于非指针类型 (如 bool, int): 返回 const Value* (single pointer)
        # 错误示例：const MemRegion *Alias = State->get<PtrAliasMap>(CheckedMR);
        pattern_map_get_simple = r'const\s+(MemRegion|SVal|SymbolRef|Expr|Decl)\s+\*\s*(\w+)\s*=\s*State\s*->\s*get\s*<\s*(\w+)\s*>\s*\(\s*(\w+)\s*\)'
        def replace_map_get_simple(match):
            value_type = match.group(1)  # MemRegion, SVal, etc. (pointer type)
            var_name = match.group(2)    # Alias
            map_name = match.group(3)    # PtrAliasMap
            key_name = match.group(4)    # CheckedMR

            # 正确写法：对于指针类型，get<> 返回 const Value*const *
            # 需要声明为 const Value*const* 然后解引用
            return f'const {value_type}* const* {var_name}_ptr = State->get<{map_name}>({key_name}); const {value_type}* {var_name} = ({var_name}_ptr && *{var_name}_ptr) ? *{var_name}_ptr : nullptr'

        new_code = re.sub(pattern_map_get_simple, replace_map_get_simple, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed ProgramStateTrait MAP get() return type (pointer value type)")
            fixed_code = new_code

        # 11. 修复另一种常见模式：直接在条件中使用 get<> 结果
        # 例如：if (const MemRegion *Alias = State->get<PtrAliasMap>(MR))
        # 只针对指针类型（MemRegion, SVal等），不处理 bool/int 等非指针类型
        pattern_map_get_condition = r'if\s*\(\s*const\s+(MemRegion|SVal|SymbolRef|Expr|Decl)\s+\*\s*(\w+)\s*=\s*State\s*->\s*get\s*<\s*(\w+)\s*>\s*\(\s*(\w+)\s*\)\s*\)'
        def replace_map_get_condition(match):
            value_type = match.group(1)  # MemRegion, SVal, etc.
            var_name = match.group(2)    # Alias
            map_name = match.group(3)    # PtrAliasMap
            key_name = match.group(4)    # MR

            # 正确写法：使用 const Value*const* 类型
            return f'if (const {value_type}* const* {var_name}_ptr = State->get<{map_name}>({key_name}); {var_name}_ptr && *{var_name}_ptr) {{ const {value_type}* {var_name} = *{var_name}_ptr;'

        new_code = re.sub(pattern_map_get_condition, replace_map_get_condition, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed ProgramStateTrait MAP get() in condition (pointer value type)")
            fixed_code = new_code

        # 12. 修复 APSIntPtr 与 int 直接比较的错误（最常见）
        # 错误：return ConcreteVal->getValue() == 0; 或 if (ConcreteVal->getValue() == 0)
        # 根本原因：getValue() 返回 APSIntPtr（指针），需要解引用后比较
        # 模式1: return statement with getValue() == 0 或 != 0
        # Regex groups: group(1)=return, group(2)=var->getValue(), group(3)==或!=, group(4)=;
        # 错误原因：APSIntPtr 是 const llvm::APSInt*，需要使用 getExtValue() 获取值
        pattern_apsint_compare_return = r'(\breturn\s+)(\w+->getValue\(\))\s*(==|!=)\s*0\s*;'
        def replace_apsint_compare_return(match):
            return_keyword = match.group(1)      # "return "
            value_expr = match.group(2)           # e.g., "ConcreteVal->getValue()"
            operator = match.group(3)             # "==" or "!="

            # Extract variable name from expression like "ConcreteVal->getValue()"
            var_name = value_expr.split('->')[0]

            # Correct: use getExtValue() to get integer value from APSInt
            return f'{return_keyword}{var_name}->getExtValue() {operator} 0;'

        new_code = re.sub(pattern_apsint_compare_return, replace_apsint_compare_return, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed APSIntPtr comparison in return statement (using getExtValue)")
            fixed_code = new_code

        # 模式2: if 条件中的 APSIntPtr 比较
        pattern_apsint_compare_if = r'if\s*\((\w+)->getValue\(\)\s*(==|!=)\s*0\s*\)'
        def replace_apsint_compare_if(match):
            var_name = match.group(1)  # ConcreteVal
            operator = match.group(2)  # == 或 !=

            # Use getExtValue() to get integer value from APSInt
            if operator == '==':
                return f'if ({var_name} && {var_name}->getExtValue() == 0) {{'
            else:
                return f'if ({var_name} && {var_name}->getExtValue() != 0) {{'

        new_code = re.sub(pattern_apsint_compare_if, replace_apsint_compare_if, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed APSIntPtr comparison in if condition (using getExtValue)")
            fixed_code = new_code

        # 模式3: 修复旧的 isZero() 调用
        pattern_apsint_iszero = r'(\w+)->isZero\s*\(\s*\)'
        def replace_apsint_iszero(match):
            var_name = match.group(1)  # 变量名
            return f'{var_name}->getExtValue() == 0'

        new_code = re.sub(pattern_apsint_iszero, replace_apsint_iszero, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed APSIntPtr.isZero() - replaced with getExtValue() comparison")
            fixed_code = new_code

        # 13. 修复 APSIntPtr 在其他条件表达式中的使用
        # 错误：while (APSIntPtrVal) 或 return APSIntPtrVal
        pattern_apsint_expr = r'(\bwhile\s*\(|\breturn\s+)(\w*APSInt\w*)\s*([;})])'
        def replace_apsint_expr(match):
            prefix = match.group(1)  # while( 或 return
            var_name = match.group(2)  # APSIntPtrVal
            suffix = match.group(3)  # ; 或 } 或 )

            if 'while' in prefix.lower():
                return f'{prefix}{var_name} && {var_name}->getExtValue() == 0){suffix}'
            else:  # return
                return f'{prefix}{var_name} ? {var_name}->getExtValue() : 0{suffix}'

        new_code = re.sub(pattern_apsint_expr, replace_apsint_expr, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed APSIntPtr in expression context (using getExtValue)")
            fixed_code = new_code

        # 14. 修复 assume() 方法的参数类型错误
        # State->assume() 需要 DefinedOrUnknownSVal，不能直接传 SVal
        # 模式1: std::tie() = State->assume(var) 模式
        pattern_assume_tie = r'std::tie\s*\(\s*\w+\s*,\s*\w+\s*\)\s*=\s*State\s*->\s*assume\s*\(\s*(\w+)\s*\)'
        def replace_assume_tie(match):
            var_name = match.group(1)  # SVal 变量名

            # 使用 castAs<DefinedOrUnknownSVal>() 进行转换
            return f'State->assume({var_name}.castAs<DefinedOrUnknownSVal>())'

        new_code = re.sub(pattern_assume_tie, replace_assume_tie, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed assume() call in std::tie - added castAs<DefinedOrUnknownSVal>()")
            fixed_code = new_code

        # 模式2: State->assume(var, true) 模式
        pattern_assume_sval = r'State\s*->\s*assume\s*\(\s*(\w+)\s*,\s*true\s*\)'
        def replace_assume_sval(match):
            var_name = match.group(1)  # SVal 变量名

            # 使用 castAs<DefinedOrUnknownSVal>() 进行转换
            return f'State->assume({var_name}.castAs<DefinedOrUnknownSVal>(), true)'

        new_code = re.sub(pattern_assume_sval, replace_assume_sval, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed assume() call - added castAs<DefinedOrUnknownSVal>()")
            fixed_code = new_code

        # 15. 修复幻觉的 SValBuilder::makeNull() 方法（不存在）
        # 正确方法：使用 SValBuilder::makeNullWithPtr() 或构建 null SVal
        pattern_make_null = r"SValBuilder.*\.makeNull\s*\(\s*\)"
        def replace_make_null(match):
            # 正确方法：使用 evalZero() 或 constraintManager
            # 更简单的方法：直接移除 makeNull() 调用
            return "SVB.getZeroVal()"

        new_code = re.sub(pattern_make_null, replace_make_null, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed hallucinated makeNull() - replaced with correct API")
            fixed_code = new_code

        # 16. 修复 getAs<loc::ConcreteInt>()->getValue() 直接比较模式
        # 错误：return Val.getAs<loc::ConcreteInt>()->getValue() == 0;
        # 原因：getAs 返回 std::optional，->getValue() 返回 APSIntPtr，不能直接与 int 比较
        pattern_getas_compare = r'(\w+)\s*\.getAs\s*<\s*[^>]+\s*>\s*\(\s*\)\s*->\s*getValue\s*\(\s*\)\s*(==|!=)\s*0\s*;'
        def replace_getas_compare(match):
            var_name = match.group(1)  # Val
            operator = match.group(2)  # == 或 !=

            # Correct: use getExtValue() instead of getValue()
            return f'{var_name}.getAs<loc::ConcreteInt>()->getExtValue() {operator} 0;'

        new_code = re.sub(pattern_getas_compare, replace_getas_compare, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed getAs<ConcreteInt>()->getValue() comparison (using getExtValue)")
            fixed_code = new_code

        # 17. 修复非指针类型的 ProgramStateTrait MAP 返回值
        # 当 Value 是 bool（非指针）时，State->get<>() 返回 const bool*（单指针）
        # 错误：const bool *const *ValuePtr = State->get<PtrNullMap>(MR);
        # 正确：const bool *ValuePtr = State->get<PtrNullMap>(MR);
        pattern_map_nonptr_value = r'const\s+(bool|int|char|float|double)\s*\*\s*\*\s*\w+\s*=\s*State\s*->\s*get\s*<\s*(\w+)\s*>\s*\('
        def replace_map_nonptr_value(match):
            value_type = match.group(1)  # bool, int, etc.

            # 正确写法：对于非指针值类型，get<> 返回单指针
            return f'const {value_type} *ValuePtr = State->get<'

        new_code = re.sub(pattern_map_nonptr_value, replace_map_nonptr_value, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append(f"Fixed ProgramStateTrait MAP for non-pointer value type ({value_type})")
            fixed_code = new_code

        # 18. 修复 State->isNull() 调用 - 该方法不存在或签名错误
        # 错误：return State->isNull(*LocVal).isConstrainedTrue();
        # 正确：使用 SValBuilder 或 assume() 方法
        pattern_state_isnull = r'State\s*->\s*isNull\s*\(\s*\*?(\w+)\s*\)\s*\.'
        def replace_state_isnull(match):
            var_name = match.group(1)  # LocVal

            # 正确方法：使用 assume() 检查约束
            # State->assume(*LocVal, true).first 检查是否为 null
            return f'(State->assume({var_name}.castAs<DefinedOrUnknownSVal>()).first'

        new_code = re.sub(pattern_state_isnull, replace_state_isnull, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed State->isNull() - replaced with assume() pattern")
            fixed_code = new_code

        # 19. 修复 State->isNonNull() 调用
        pattern_state_isnonnull = r'State\s*->\s*isNonNull\s*\(\s*\*?(\w+)\s*\)\s*\.'
        def replace_state_isnonnull(match):
            var_name = match.group(1)  # LocVal

            # 正确方法：使用 assume() 检查非 null 约束
            return f'(State->assume({var_name}.castAs<DefinedOrUnknownSVal>()).second'

        new_code = re.sub(pattern_state_isnonnull, replace_state_isnonnull, fixed_code)
        if new_code != fixed_code:
            fixes_applied.append("Fixed State->isNonNull() - replaced with assume() pattern")
            fixed_code = new_code

        # 20. 修复 C.addTransition() 调用 - 可能需要额外的 tag 参数
        # 错误：C.addTransition(State); (某些版本需要2个参数)
        # 但通常只需要1个参数，这个错误可能是其他原因导致的
        # 暂时不处理，等待确认 API 签名

        return fixed_code, fixes_applied

    def _fix_missing_includes(self, code: str, issues: List[str]) -> tuple[str, List[str]]:
        """
        修复缺失的头文件 - Knighter 插件风格

        对于 BuiltinCheckerRegistration.h 错误，使用 convert_to_plugin_style 转换
        """
        fixed_code = code
        fixes_applied = []

        logger.info(f"      Processing {len(issues)} missing include issues...")

        # 检查是否有 BuiltinCheckerRegistration.h 相关错误
        has_builtin_registration_error = any(
            "BuiltinCheckerRegistration" in issue or
            "BuiltinCheckerRegistration.h" in issue
            for issue in issues
        )

        if has_builtin_registration_error:
            logger.info("      Detected BuiltinCheckerRegistration.h error, converting to plugin style...")
            # 使用 convert_to_plugin_style 转换整个代码
            fixed_code = convert_to_plugin_style(fixed_code)
            fixes_applied.append("Converted to plugin style (replaced BuiltinCheckerRegistration.h with CheckerRegistry.h)")
            return fixed_code, fixes_applied

        # 常见的头文件映射（插件式）
        include_mapping = {
            "Checker": '#include "clang/StaticAnalyzer/Core/Checker.h"',
            "BugType": '#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"',
            "CheckerContext": '#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"',
            "CallEvent": '#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"',
            "CheckerRegistry": '#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"',
        }

        # 检查错误信息并添加相应的include
        for issue in issues:
            logger.info(f"      Checking issue: {issue[:80]}...")

            for symbol, include in include_mapping.items():
                if symbol in issue:
                    logger.info(f"         Found symbol '{symbol}', checking if include exists...")
                    if include not in fixed_code:
                        fixed_code = include + '\n' + fixed_code
                        fixes_applied.append(f"Added include: {include}")
                        logger.info(f"      ✓ Added {include}")
                        break
                    else:
                        logger.info(f"         Include already exists")

        # 如果没有添加任何修复，尝试从错误消息中提取文件名
        if not fixes_applied:
            logger.info(f"      No standard fixes applied, trying regex extraction...")
            for issue in issues:
                # 匹配模式: fatal error: clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h: No such file or directory
                if "fatal error:" in issue and ": No such file" in issue:
                    import re
                    match = re.search(r'fatal error: (.*?): No such file', issue)
                    if match:
                        missing_file = match.group(1)
                        # 如果是 BuiltinCheckerRegistration.h，使用插件式转换
                        if "BuiltinCheckerRegistration" in missing_file:
                            fixed_code = convert_to_plugin_style(fixed_code)
                            fixes_applied.append("Converted to plugin style")
                            logger.info(f"      ✓ Converted to plugin style")
                        else:
                            include_stmt = f'#include "{missing_file}"'
                            if missing_file not in fixed_code and include_stmt not in fixed_code:
                                fixed_code = include_stmt + '\n' + fixed_code
                                fixes_applied.append(f"Added include: {include_stmt}")
                                logger.info(f"      ✓ Added {include_stmt} (from regex)")
                        break

        return fixed_code, fixes_applied

    def _fix_undefined_symbols(self, code: str, issues: List[str]) -> tuple[str, List[str]]:
        """修复未定义符号"""
        fixed_code = code
        fixes_applied = []

        # 符号修复映射
        symbol_fixes = {
            "BT": "mutable std::unique_ptr<BugType> BT;",
            "ento": "// Using namespace ento for checker registration"
        }

        for issue in issues:
            for symbol, fix in symbol_fixes.items():
                if symbol in issue and fix not in fixed_code:
                    # 在类中添加成员变量
                    if "BT" in symbol and "class" in fixed_code:
                        class_match = re.search(r'class\s+\w+\s*:\s*public\s+.*?\s*{', fixed_code, re.DOTALL)
                        if class_match:
                            insert_pos = class_match.end()
                            fixed_code = fixed_code[:insert_pos] + f'\nprivate:\n  {fix}\n' + fixed_code[insert_pos:]
                            fixes_applied.append(f"Added member: {fix}")

        return fixed_code, fixes_applied

    def _fix_logic_errors(self, code: str, issues: List[str]) -> tuple[str, List[str]]:
        """修复逻辑错误"""
        fixed_code = code
        fixes_applied = []

        # 简单的逻辑错误修复
        for issue in issues:
            if "null pointer" in issue.lower():
                # 添加空指针检查
                fixed_code, fix = self._add_null_check(fixed_code, issue)
                if fix:
                    fixes_applied.append(f"Added null check: {fix}")

        return fixed_code, fixes_applied

    async def _advanced_repair(self, code: str, errors: List[str]) -> tuple[str, List[str]]:
        """高级修复（使用LSP或LLM）"""
        if self.lsp_client:
            # 使用LSP获取修复建议
            suggestions = await self.lsp_client.get_fix_suggestions(code, errors)
            if suggestions:
                # 应用LSP建议
                fixed_code = self._apply_lsp_suggestions(code, suggestions)
                return fixed_code, ["Applied LSP suggestions"]

        # 如果有prompt_manager，使用LLM进行修复
        if self.prompt_manager:
            repair_prompt = self.prompt_manager.build_advanced_repair_prompt(code, errors)
            # 这里可以调用LLM进行更复杂的修复
            # llm_response = await self.llm.generate(repair_prompt)

        return code, ["Advanced repair attempted but no fixes applied"]

    def _optimize_performance(self, code: str) -> tuple[str, List[str]]:
        """性能优化"""
        optimized_code = code
        optimizations = []

        # 移除不必要的代码
        if "std::cout" in code and "// Debug" not in code:
            # 移除调试输出
            optimized_code = re.sub(r'std::cout\s*<<.*;', '', optimized_code)
            optimizations.append("Removed debug output statements")

        # 优化字符串操作
        if '"strcpy"' in code:
            # 建议使用更安全的替代方案
            optimizations.append("Consider using safer string functions")

        return optimized_code, optimizations

    def _optimize_readability(self, code: str) -> tuple[str, List[str]]:
        """可读性优化"""
        optimized_code = code
        optimizations = []

        # 格式化代码
        if "\n\n\n" in code:
            optimized_code = re.sub(r'\n\n\n+', '\n\n', optimized_code)
            optimizations.append("Removed excessive blank lines")

        # 添加注释
        if "void checkPreCall" in code and "// Check" not in code:
            optimized_code = optimized_code.replace(
                "void checkPreCall",
                "// Check function calls for security issues\nvoid checkPreCall"
            )
            optimizations.append("Added function documentation")

        return optimized_code, optimizations

    def _optimize_maintainability(self, code: str) -> tuple[str, List[str]]:
        """可维护性优化"""
        optimized_code = code
        optimizations = []

        # 提取常量
        if '"Buffer Overflow"' in code and "const char* MSG" not in code:
            optimized_code = optimized_code.replace(
                '"Buffer Overflow"',
                'const char* BUFFER_OVERFLOW_MSG = "Buffer Overflow";\n    BUFFER_OVERFLOW_MSG'
            )
            optimizations.append("Extracted magic strings to constants")

        return optimized_code, optimizations

    # 辅助修复方法
    def _add_missing_semicolon(self, code: str, issue: str) -> tuple[str, Optional[str]]:
        """添加缺失的分号"""
        # 简化的实现
        return code, None

    def _add_missing_brace(self, code: str, issue: str) -> tuple[str, Optional[str]]:
        """添加缺失的大括号"""
        # 简化的实现
        return code, None

    def _add_null_check(self, code: str, issue: str) -> tuple[str, Optional[str]]:
        """添加空指针检查"""
        # 简化的实现
        return code, None

    def _apply_lsp_suggestions(self, code: str, suggestions: List[Dict]) -> str:
        """应用LSP修复建议"""
        # 简化的实现
        return code

    def _load_error_patterns(self) -> Dict[str, Dict[str, Any]]:
        """加载错误模式数据库"""
        return {
            "missing_semicolon": {
                "pattern": r"expected ';'",
                "fix": "add_semicolon"
            },
            "missing_include": {
                "pattern": r"'(\w+)' file not found",
                "fix": "add_include"
            },
            "undefined_symbol": {
                "pattern": r"'(\w+)' was not declared",
                "fix": "declare_symbol"
            }
        }

    # ============================================================
    # KNighter 风格的 LLM 修复功能
    # ============================================================

    async def repair_with_llm(
        self,
        code: str,
        errors: List[str],
        attempt: int = 1,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        使用 LLM 修复编译错误 - KNighter 风格

        Args:
            code: 当前 checker 代码
            errors: 编译错误列表
            attempt: 当前尝试次数
            context: 可选的上下文信息（vulnerability_type, description, pattern等）

        Returns:
            修复后的代码，如果修复失败则返回 None
        """
        if not self.prompt_manager:
            logger.error("No prompt_manager available for LLM repair")
            return None

        # 获取 LLM client
        llm_client = self._get_llm_client()
        if not llm_client:
            logger.error("No LLM client available for repair")
            return None

        try:
            # 1. 格式化错误信息 (KNighter 风格)
            errors_md = self._format_errors_knighter(errors)

            # 2. 构建 repair prompt - 包含上下文以保持对话历史
            repair_prompt = self._build_repair_prompt(code, errors_md, context or {})

            # 3. 调用 LLM - 使用快速模型进行 repair
            # 注意：llm_client.generate() 是同步方法，需要用 asyncio.to_thread 包装
            logger.info(f"Calling LLM for repair attempt {attempt}...")
            logger.info(f"Repair prompt length: {len(repair_prompt)} chars")

            # 使用配置中的 max_tokens 和 fast_model
            max_tokens = getattr(llm_client.config, 'max_tokens', 10000)
            # 修复阶段使用低温确保确定性输出 (temperature=0.0)
            temperature = 0.0
            fast_model = getattr(llm_client.config, 'fast_model', 'deepseek-reasoner')

            logger.info(f"Using fast model: {fast_model}")

            # 使用 asyncio.wait_for 添加超时保护（5分钟超时）
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    llm_client.generate,
                    repair_prompt,
                    model=fast_model,  # 使用快速模型
                    temperature=temperature,
                    max_tokens=max_tokens
                ),
                timeout=300.0  # 5分钟超时
            )

            # 4. 提取修复后的代码
            repaired_code = self._extract_code_from_response(response)

            if repaired_code:
                logger.success(f"LLM repair attempt {attempt} succeeded")
                return repaired_code
            else:
                logger.warning(f"LLM repair attempt {attempt} failed to extract code")
                return None

        except asyncio.TimeoutError:
            logger.error(f"LLM repair attempt {attempt} timed out after 300 seconds")
            return None
        except Exception as e:
            logger.error(f"LLM repair attempt {attempt} failed with error: {type(e).__name__}: {str(e)[:200]}")
            return None

    def _get_llm_client(self):
        """获取 LLM client"""
        # 优先使用构造函数传入的 llm_client
        if self.llm_client:
            return self.llm_client

        try:
            # 尝试从 orchestrator 获取 llm_client
            if hasattr(self, 'orchestrator') and self.orchestrator:
                if hasattr(self.orchestrator, 'llm_client'):
                    return self.orchestrator.llm_client

            # 尝试从 global state 获取
            try:
                from ..core.orchestrator import GeneratorOrchestrator
                # 如果有单例或全局实例
                return None
            except:
                return None

            return None
        except Exception as e:
            logger.debug(f"Could not get LLM client: {e}")
            return None

    def _format_errors_knighter(self, errors: List[str]) -> str:
        """
        格式化错误信息 - KNighter 风格

        将错误列表转换为 Markdown 格式
        """
        errors_md = ""
        for error in errors:
            # 解析错误行和错误消息
            # 格式: "file:line:col: error: message"
            parts = error.split(":")
            if len(parts) >= 4:
                error_msg = ":".join(parts[3:]).strip()
                line_info = f"Line {parts[1]}"
            else:
                error_msg = error.strip()
                line_info = "Unknown"

            errors_md += f"- Error Line: {line_info}\n"
            errors_md += f"\t- Error Messages: {error_msg}\n\n"

        return errors_md

    def _build_repair_prompt(self, code: str, errors_md: str, context: Dict[str, Any]) -> str:
        """构建 repair prompt - 包含上下文以保持对话历史"""
        # 读取 KNighter 风格的 repair 模板
        template_path = Path(__file__).parent.parent / "prompts" / "templates" / "repair_knighter.md"

        if template_path.exists():
            template = template_path.read_text()
        else:
            # 回退到原有的 repair_syntax.md
            template_path = Path(__file__).parent.parent / "prompts" / "templates" / "repair_syntax.md"
            if template_path.exists():
                template = template_path.read_text()
            else:
                # 最简单的回退 prompt
                template = """## Task

Fix the following Clang Static Analyzer checker code that has compilation errors.

## Original Context (for reference)
{context_section}

## Current Code

```cpp
{checkercode}
```

## Errors

{errors}

## Instructions

1. Fix all compilation errors
2. Use Clang-21 compatible APIs
3. Return the complete fixed code
4. PRESERVE the original vulnerability detection logic

```cpp
{{fixed code here}}
```
"""

        # 替换占位符
        prompt = template.replace("{checkercode}", code).replace("{errors}", errors_md)

        # 添加上下文部分 - 保持从初始生成开始的对话历史
        context_section = self._build_context_section(context)
        if "{context_section}" in prompt:
            prompt = prompt.replace("{context_section}", context_section)
        elif context_section:
            # 如果模板没有上下文占位符，插入到错误信息之前
            prompt = prompt.replace("## Errors", f"{context_section}\n\n## Errors")

        return prompt

    def _build_context_section(self, context: Dict[str, Any]) -> str:
        """构建上下文部分 - 包含原始漏洞信息"""
        if not context:
            return ""

        parts = []

        # 漏洞类型和描述
        vuln_type = context.get("vulnerability_type")
        vuln_desc = context.get("vulnerability_description")
        vuln_pattern = context.get("vulnerability_pattern")

        if vuln_type or vuln_desc or vuln_pattern:
            if vuln_type:
                parts.append(f"**Vulnerability Type:** {vuln_type}")
            if vuln_pattern:
                parts.append(f"**Pattern:** {vuln_pattern}")
            if vuln_desc:
                # 截断过长的描述
                desc = vuln_desc[:500] + "..." if len(vuln_desc) > 500 else vuln_desc
                parts.append(f"**Description:** {desc}")
            parts.append("")

        # 分析上下文 - 支持多种数据结构
        analysis = context.get("analysis_context")
        if analysis and isinstance(analysis, dict):
            # 尝试从 analysis_result 结构中提取信息
            indicators = analysis.get("indicators") or analysis.get("vulnerability_indicators")
            technical_terms = analysis.get("technical_terms")
            pattern = analysis.get("pattern")
            inferred_type = analysis.get("inferred_vulnerability_type")

            detection_parts = []
            if indicators:
                if isinstance(indicators, list):
                    detection_parts.append(f"**Key Indicators:** {', '.join(str(i) for i in indicators)}")
                else:
                    detection_parts.append(f"**Key Indicators:** {indicators}")
            if technical_terms:
                if isinstance(technical_terms, list):
                    detection_parts.append(f"**Technical Terms:** {', '.join(str(t) for t in technical_terms)}")
                else:
                    detection_parts.append(f"**Technical Terms:** {technical_terms}")
            if pattern and not vuln_pattern:
                parts.append(f"**Detected Pattern:** {pattern}")
            if inferred_type and not vuln_type:
                parts.append(f"**Inferred Type:** {inferred_type}")

            if detection_parts:
                parts.append("### Detection Context")
                parts.extend(detection_parts)
                parts.append("")

        return "\n".join(parts) if parts else ""

    def _extract_code_from_response(self, response: str) -> Optional[str]:
        """
        从 LLM 响应中提取 C++ 代码

        支持多种代码块格式
        """
        if not response:
            return None

        import re

        # 模式 1: ```cpp ... ```
        pattern1 = r'```cpp\n([\s\S]*?)\n```'
        match = re.search(pattern1, response)
        if match:
            return match.group(1).strip()

        # 模式 2: ``` ... ```
        pattern2 = r'```\n([\s\S]*?)\n```'
        match = re.search(pattern2, response)
        if match:
            code = match.group(1).strip()
            # 确保是 C++ 代码
            if 'class ' in code or '#include' in code or 'namespace' in code:
                return code

        # 模式 3: 直接返回代码（没有代码块标记）
        if 'class ' in response and '#include' in response:
            # 可能是纯代码响应
            lines = response.split('\n')
            code_lines = []
            in_code = False
            for line in lines:
                if line.strip().startswith('#include') or 'class ' in line or 'namespace' in line:
                    in_code = True
                if in_code:
                    code_lines.append(line)
                # 检查是否到达结尾
                if in_code and 'extern "C"' in line:
                    code_lines.append(line)
                    break

            if code_lines:
                return '\n'.join(code_lines).strip()

        return None

    async def _advanced_repair(self, code: str, errors: List[Dict]) -> tuple[str, List[str]]:
        """
        高级修复 - 使用 LLM 处理复杂错误

        当简单的规则修复失败时，调用 LLM 进行修复
        """
        fixed_code = code
        fixes_applied = []

        # 将 LSP 错误转换为字符串列表
        error_strings = [error.get('message', '') for error in errors]

        # 尝试 LLM 修复 - 使用存储的上下文
        repaired_code = await self.repair_with_llm(
            fixed_code,
            error_strings,
            context=self.current_repair_context or {}
        )

        if repaired_code and repaired_code != fixed_code:
            fixed_code = repaired_code
            fixes_applied.append("Applied LLM-based repair")
            logger.success("   ✅ LLM repair applied successfully")
        else:
            logger.warning("   ⚠️  LLM repair did not produce valid code")

        return fixed_code, fixes_applied
