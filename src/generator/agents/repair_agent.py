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

        logger.info("")
        logger.info("🔧 Starting Error Repair Process")
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

            if category == "syntax_errors":
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

            # 调用 LLM 修复
            repaired_code = await self.repair_with_llm(repaired_code, all_errors_str, attempt)

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
            "syntax_errors": [],
            "missing_includes": [],
            "undefined_symbols": [],
            "logic_errors": [],
            "other": []
        }

        for issue in issues:
            issue_lower = issue.lower()
            if any(keyword in issue_lower for keyword in ["expected", "unexpected", "syntax"]):
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
        attempt: int = 1
    ) -> Optional[str]:
        """
        使用 LLM 修复编译错误 - KNighter 风格

        Args:
            code: 当前 checker 代码
            errors: 编译错误列表
            attempt: 当前尝试次数

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

            # 2. 构建 repair prompt
            repair_prompt = self._build_repair_prompt(code, errors_md)

            # 3. 调用 LLM - 使用快速模型进行 repair
            # 注意：llm_client.generate() 是同步方法，需要用 asyncio.to_thread 包装
            logger.info(f"Calling LLM for repair attempt {attempt}...")
            logger.info(f"Repair prompt length: {len(repair_prompt)} chars")

            # 使用配置中的 max_tokens、temperature 和 fast_model
            max_tokens = getattr(llm_client.config, 'max_tokens', 10000)
            temperature = getattr(llm_client.config, 'temperature', 0.3)
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

    def _build_repair_prompt(self, code: str, errors_md: str) -> str:
        """构建 repair prompt"""
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

```cpp
{{fixed code here}}
```
"""

        # 替换占位符
        prompt = template.replace("{checkercode}", code).replace("{errors}", errors_md)

        return prompt

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

        # 尝试 LLM 修复
        repaired_code = await self.repair_with_llm(fixed_code, error_strings)

        if repaired_code and repaired_code != fixed_code:
            fixed_code = repaired_code
            fixes_applied.append("Applied LLM-based repair")
            logger.success("   ✅ LLM repair applied successfully")
        else:
            logger.warning("   ⚠️  LLM repair did not produce valid code")

        return fixed_code, fixes_applied
