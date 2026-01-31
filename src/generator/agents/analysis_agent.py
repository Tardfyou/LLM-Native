"""
分析Agent - 负责补丁分析和漏洞模式提取
"""

import asyncio
from typing import Dict, Any, Optional, List

# 使用loguru以支持logger.success()等方法
from loguru import logger

from .base_agent import BaseAgent, AgentMessage
from ..lsp.clangd_client import ClangdClient
from ..prompts.prompt_manager import PromptManager

class AnalysisAgent(BaseAgent):
    """分析Agent - 负责补丁分析和漏洞模式提取"""

    def __init__(self,
                 lsp_client: Optional[ClangdClient] = None,
                 prompt_manager: Optional[PromptManager] = None,
                 llm_client: Optional[Any] = None):
        super().__init__("analysis_agent", "patch_analysis")
        self.lsp_client = lsp_client
        self.prompt_manager = prompt_manager
        self.llm_client = llm_client  # LLM客户端，用于模式提取

    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理接收到的消息"""
        if message.message_type == "analyze_patch":
            return await self._handle_analyze_patch(message)
        elif message.message_type == "extract_pattern":
            return await self._handle_extract_pattern(message)
        else:
            logger.warning(f"AnalysisAgent received unknown message type: {message.message_type}")
            return None

    async def _handle_analyze_patch(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理补丁分析请求"""
        try:
            patch = message.content.get("patch", "")
            context = message.content.get("context", {})

            # 执行分析
            analysis_result = await self.execute_task({
                "patch": patch,
                "context": context
            })

            # 发送结果给生成Agent
            return await self.send_message(
                "generation_agent",
                "analysis_complete",
                analysis_result
            )

        except Exception as e:
            logger.error(f"AnalysisAgent error in analyze_patch: {e}")
            return await self.send_message(
                "orchestrator",
                "analysis_failed",
                {"error": str(e), "original_message": message.content}
            )

    async def _handle_extract_pattern(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理模式提取请求"""
        try:
            code_changes = message.content.get("code_changes", "")
            metadata = message.content.get("metadata", {})

            # 执行模式提取
            pattern_result = await self.execute_task({
                "code_changes": code_changes,
                "metadata": metadata,
                "task_type": "pattern_extraction"
            })

            # 发送结果给规划Agent
            return await self.send_message(
                "planning_agent",
                "pattern_extracted",
                pattern_result
            )

        except Exception as e:
            logger.error(f"AnalysisAgent error in extract_pattern: {e}")
            return None

    async def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行具体分析任务"""
        start_time = asyncio.get_event_loop().time()

        try:
            task_type = task_data.get("task_type", "patch_analysis")

            if task_type == "patch_analysis":
                result = await self._analyze_patch(task_data)
            elif task_type == "description_analysis":
                result = await self._analyze_description(task_data)
            elif task_type == "poc_analysis":
                result = await self._analyze_poc(task_data)
            elif task_type == "pattern_extraction":
                result = await self._extract_pattern(task_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")

            # 更新性能统计
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, True)

            return result

        except Exception as e:
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, False)
            raise e

    async def _analyze_patch(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析补丁内容"""
        patch = task_data["patch"]
        context = task_data.get("context", {})
        known_vuln_type = task_data.get("vulnerability_type")  # 可能是None（0day情况）

        # 1. LSP分析（如果可用）
        lsp_analysis = {}
        if self.lsp_client:
            try:
                lsp_analysis = await self.lsp_client.analyze_patch(patch)
            except Exception as e:
                logger.warning(f"LSP analysis failed: {e}")

        # 2. 基于规则的初步分析
        basic_analysis = self._basic_patch_analysis(patch)

        # 3. 漏洞指标识别
        vulnerability_indicators = self._identify_vulnerability_indicators(patch)

        # 4. 0day漏洞分析（如果没有已知漏洞类型）
        inferred_vuln_type = known_vuln_type
        if not known_vuln_type:
            inferred_vuln_type = self._infer_vulnerability_type(patch, vulnerability_indicators)
            logger.info(f"Inferred vulnerability type for 0day: {inferred_vuln_type}")

        # 5. LLM 模式提取 (参考 Knighter patch2pattern)
        pattern = None
        pattern_source = "rule_based"

        if self.llm_client and self.prompt_manager:
            try:
                logger.info("Using LLM for pattern extraction from patch...")
                # 构建 prompt（使用项目统一的 invoke_llm 接口）
                extraction_prompt = self._build_patch2pattern_prompt(patch, inferred_vuln_type)

                # 调用 LLM（使用 asyncio.to_thread 避免阻塞）
                import asyncio
                # 分析阶段使用高温度激发创造力 (temperature=1.0)
                llm_response = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.llm_client.generate,
                        extraction_prompt,
                        temperature=1.0
                    ),
                    timeout=300.0  # 5分钟超时
                )

                # 从响应中提取 pattern
                if llm_response:
                    pattern = self._extract_pattern_from_llm_response(llm_response)
                    if pattern:
                        pattern_source = "llm_based"
                        logger.success(f"LLM extracted pattern: {pattern[:100]}...")
                    else:
                        logger.warning("LLM response did not contain valid pattern, falling back to rule-based")
                        pattern = self._rule_based_pattern_extraction(patch)
                else:
                    logger.warning("LLM returned empty response, falling back to rule-based")
                    pattern = self._rule_based_pattern_extraction(patch)

            except asyncio.TimeoutError:
                logger.warning("LLM pattern extraction timed out, falling back to rule-based")
                pattern = self._rule_based_pattern_extraction(patch)
            except Exception as e:
                logger.warning(f"LLM pattern extraction failed: {e}, falling back to rule-based")
                pattern = self._rule_based_pattern_extraction(patch)
        else:
            # 回退到规则-based模式提取
            pattern = self._rule_based_pattern_extraction(patch)
            logger.info("Using rule-based pattern extraction (no LLM client available)")

        # 6. 结合分析结果
        analysis_result = {
            "patch_summary": basic_analysis,
            "lsp_analysis": lsp_analysis,
            "vulnerability_indicators": vulnerability_indicators,
            "inferred_vulnerability_type": inferred_vuln_type,
            "pattern": pattern,
            "pattern_source": pattern_source,
            "code_changes": self._extract_code_changes(patch),
            "complexity_score": self._calculate_patch_complexity(patch),
            "confidence_score": 0.9 if pattern_source == "llm_based" else 0.7,
            "analysis_type": "patch_based"
        }

        return analysis_result

    async def _analyze_description(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析漏洞描述（0day支持）"""
        description = task_data["vulnerability_description"]
        vulnerability_type = task_data.get("vulnerability_type")
        context = task_data.get("context", {})

        # 1. 基于描述的规则分析
        description_summary = self._analyze_description_text(description)
        vulnerability_indicators = self._extract_indicators_from_description(description)

        # 2. LLM 模式提取
        pattern = None
        pattern_source = "rule_based"
        inferred_type = vulnerability_type

        if self.llm_client:
            try:
                logger.info("Using LLM for pattern extraction from description...")
                extraction_prompt = self._build_desc2pattern_prompt(description, vulnerability_type)

                import asyncio
                # 分析阶段使用高温度激发创造力 (temperature=1.0)
                llm_response = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.llm_client.generate,
                        extraction_prompt,
                        temperature=1.0
                    ),
                    timeout=300.0
                )

                if llm_response:
                    pattern = self._extract_pattern_from_llm_response(llm_response)
                    if pattern:
                        pattern_source = "llm_based"
                        logger.success(f"LLM extracted pattern from description: {pattern[:100]}...")

                        # 尝试从 LLM 响应中提取漏洞类型
                        if not vulnerability_type:
                            inferred_type = self._extract_vuln_type_from_llm_response(llm_response)
                            logger.info(f"Inferred vulnerability type from LLM: {inferred_type}")
                    else:
                        logger.warning("LLM response did not contain valid pattern")
                        pattern = self._infer_patterns_from_description(description, vulnerability_type)
                        if pattern:
                            pattern = pattern[0] if isinstance(pattern, list) else pattern
                else:
                    logger.warning("LLM returned empty response")
                    pattern = self._infer_patterns_from_description(description, vulnerability_type)
                    if pattern:
                        pattern = pattern[0] if isinstance(pattern, list) else pattern

            except asyncio.TimeoutError:
                logger.warning("LLM pattern extraction timed out")
                pattern = self._infer_patterns_from_description(description, vulnerability_type)
                if pattern:
                    pattern = pattern[0] if isinstance(pattern, list) else pattern
            except Exception as e:
                logger.warning(f"LLM pattern extraction failed: {e}")
                pattern = self._infer_patterns_from_description(description, vulnerability_type)
                if pattern:
                    pattern = pattern[0] if isinstance(pattern, list) else pattern
        else:
            # 回退到规则-based
            rule_patterns = self._infer_patterns_from_description(description, vulnerability_type)
            pattern = rule_patterns[0] if rule_patterns else "通用漏洞检测模式"

        # 3. 结合分析结果
        analysis_result = {
            "description_summary": description_summary,
            "vulnerability_indicators": vulnerability_indicators,
            "inferred_vulnerability_type": inferred_type or vulnerability_type,
            "pattern": pattern,
            "pattern_source": pattern_source,
            "potential_patterns": [pattern] if pattern else [],
            "suggested_detection_approaches": self._suggest_detection_methods(description, vulnerability_type),
            "analysis_type": "description_based",
            "confidence_score": 0.8 if pattern_source == "llm_based" else 0.5
        }

        return analysis_result

    async def _analyze_poc(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析PoC代码（0day支持）"""
        poc_code = task_data["poc_code"]
        vulnerability_type = task_data.get("vulnerability_type")
        context = task_data.get("context", {})

        # 1. 基础 PoC 结构分析
        code_structure = self._analyze_poc_structure(poc_code)
        vulnerability_indicators = self._extract_vuln_indicators_from_poc(poc_code)
        attack_vector = self._identify_attack_vector(poc_code)

        # 2. LLM 模式提取
        pattern = None
        pattern_source = "rule_based"
        inferred_type = vulnerability_type

        if self.llm_client:
            try:
                logger.info("Using LLM for pattern extraction from PoC...")
                extraction_prompt = self._build_poc2pattern_prompt(poc_code, vulnerability_type)

                import asyncio
                # 分析阶段使用高温度激发创造力 (temperature=1.0)
                llm_response = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.llm_client.generate,
                        extraction_prompt,
                        temperature=1.0
                    ),
                    timeout=300.0
                )

                if llm_response:
                    pattern = self._extract_pattern_from_llm_response(llm_response)
                    if pattern:
                        pattern_source = "llm_based"
                        logger.success(f"LLM extracted pattern from PoC: {pattern[:100]}...")

                        # 尝试从 LLM 响应中提取漏洞类型
                        if not vulnerability_type:
                            inferred_type = self._extract_vuln_type_from_llm_response(llm_response)
                            logger.info(f"Inferred vulnerability type from PoC analysis: {inferred_type}")
                    else:
                        logger.warning("LLM response did not contain valid pattern")
                        rule_patterns = self._derive_patterns_from_poc(poc_code, vulnerability_type)
                        pattern = rule_patterns[0] if rule_patterns else "基于PoC的模式分析"
                else:
                    logger.warning("LLM returned empty response")
                    rule_patterns = self._derive_patterns_from_poc(poc_code, vulnerability_type)
                    pattern = rule_patterns[0] if rule_patterns else "基于PoC的模式分析"

            except asyncio.TimeoutError:
                logger.warning("LLM pattern extraction timed out")
                rule_patterns = self._derive_patterns_from_poc(poc_code, vulnerability_type)
                pattern = rule_patterns[0] if rule_patterns else "基于PoC的模式分析"
            except Exception as e:
                logger.warning(f"LLM pattern extraction failed: {e}")
                rule_patterns = self._derive_patterns_from_poc(poc_code, vulnerability_type)
                pattern = rule_patterns[0] if rule_patterns else "基于PoC的模式分析"
        else:
            # 回退到规则-based
            rule_patterns = self._derive_patterns_from_poc(poc_code, vulnerability_type)
            pattern = rule_patterns[0] if rule_patterns else "基于PoC的模式分析"

        # 3. 结合分析结果
        poc_analysis = {
            "code_structure": code_structure,
            "vulnerability_indicators": vulnerability_indicators,
            "inferred_vulnerability_type": inferred_type or vulnerability_type,
            "attack_vector": attack_vector,
            "pattern": pattern,
            "pattern_source": pattern_source,
            "detection_patterns": [pattern] if pattern else [],
            "analysis_type": "poc_based",
            "confidence_score": 0.85 if pattern_source == "llm_based" else 0.6
        }

        return poc_analysis

    async def _extract_pattern(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """提取漏洞模式"""
        code_changes = task_data["code_changes"]
        metadata = task_data.get("metadata", {})

        # 使用提示词管理器生成分析提示词
        if self.prompt_manager:
            analysis_prompt = self.prompt_manager.build_pattern_extraction_prompt(
                code_changes, metadata
            )
            # 这里可以调用LLM进行模式提取
            # llm_response = await self.llm.generate(analysis_prompt)

        # 基于规则的模式提取
        pattern = self._rule_based_pattern_extraction(code_changes)

        return {
            "pattern": pattern,
            "pattern_type": self._classify_pattern(pattern),
            "confidence_score": 0.7,
            "supporting_evidence": self._extract_evidence(code_changes)
        }

    def _basic_patch_analysis(self, patch: str) -> Dict[str, Any]:
        """基础补丁分析"""
        lines = patch.split('\n')
        added_lines = [line for line in lines if line.startswith('+')]
        removed_lines = [line for line in lines if line.startswith('-')]

        return {
            "total_lines": len(lines),
            "added_lines": len(added_lines),
            "removed_lines": len(removed_lines),
            "modified_files": self._extract_modified_files(patch),
            "change_type": self._classify_change_type(patch)
        }

    def _identify_vulnerability_indicators(self, patch: str) -> List[str]:
        """识别漏洞指标"""
        indicators = []

        # 常见漏洞模式识别
        vulnerability_patterns = {
            "buffer_overflow": ["strcpy", "strcat", "sprintf", "vsprintf"],
            "use_after_free": ["free", "delete"],
            "null_pointer": ["NULL", "nullptr"],
            "integer_overflow": ["malloc", "calloc", "realloc"],
            "format_string": ["printf", "sprintf", "fprintf"]
        }

        patch_lower = patch.lower()
        for vuln_type, patterns in vulnerability_patterns.items():
            for pattern in patterns:
                if pattern.lower() in patch_lower:
                    indicators.append(f"{vuln_type}:{pattern}")

        return indicators

    def _infer_vulnerability_type(self, patch: str, indicators: List[str]) -> str:
        """推断0day漏洞类型"""
        # 基于漏洞指标进行智能推断
        indicator_types = {}

        for indicator in indicators:
            vuln_type, pattern = indicator.split(':', 1)
            if vuln_type not in indicator_types:
                indicator_types[vuln_type] = 0
            indicator_types[vuln_type] += 1

        if not indicator_types:
            # 如果没有明确指标，进行更深入的分析
            return self._deep_vulnerability_analysis(patch)

        # 返回出现频率最高的漏洞类型
        most_common = max(indicator_types.items(), key=lambda x: x[1])
        return most_common[0]

    def _deep_vulnerability_analysis(self, patch: str) -> str:
        """深度漏洞分析 - 用于没有明确指标的情况"""
        patch_lower = patch.lower()

        # 分析代码变更模式
        changes = self._extract_code_changes(patch)
        additions = [c for c in changes if c['type'] == 'addition']
        deletions = [c for c in changes if c['type'] == 'deletion']

        # 基于变更模式的启发式推断
        if any('null' in add.lower() or 'nullptr' in add.lower() for add in additions):
            return "null_pointer_dereference"

        if any('free' in deletion.lower() or 'delete' in deletion.lower() for deletion in deletions):
            return "use_after_free"

        if any('sizeof' in add.lower() or 'length' in add.lower() for add in additions):
            return "buffer_overflow"

        # 如果无法确定，返回通用类型
        return "unknown_security_issue"

    def _extract_code_changes(self, patch: str) -> List[Dict[str, Any]]:
        """提取代码变更"""
        changes = []
        current_file = None

        for line in patch.split('\n'):
            if line.startswith('+++ b/'):
                current_file = line[6:]
            elif line.startswith('@@'):
                # 新的hunk
                pass
            elif line.startswith('+') and not line.startswith('+++'):
                changes.append({
                    "type": "addition",
                    "content": line[1:],
                    "file": current_file
                })
            elif line.startswith('-') and not line.startswith('---'):
                changes.append({
                    "type": "deletion",
                    "content": line[1:],
                    "file": current_file
                })

        return changes

    def _calculate_patch_complexity(self, patch: str) -> float:
        """计算补丁复杂度"""
        lines = len(patch.split('\n'))
        files = len(self._extract_modified_files(patch))
        changes = len([line for line in patch.split('\n') if line.startswith(('+', '-'))])

        # 简单复杂度计算
        complexity = min(1.0, (lines / 100) + (files / 5) + (changes / 50))
        return complexity

    def _extract_modified_files(self, patch: str) -> List[str]:
        """提取修改的文件"""
        files = []
        for line in patch.split('\n'):
            if line.startswith('+++ b/'):
                files.append(line[6:])
        return files

    def _classify_change_type(self, patch: str) -> str:
        """分类变更类型"""
        if 'if (' in patch or 'if(' in patch:
            return "conditional_logic"
        elif 'free(' in patch or 'delete' in patch:
            return "memory_management"
        elif 'strcpy(' in patch or 'memcpy(' in patch:
            return "data_copy"
        else:
            return "general"

    def _rule_based_pattern_extraction(self, code_changes: str) -> str:
        """基于规则的模式提取"""
        # 简化的规则-based模式提取
        if "free" in code_changes and "NULL" in code_changes:
            return "Double-free prevention: setting pointer to NULL after free"
        elif "strncpy" in code_changes and "strcpy" in code_changes:
            return "Buffer overflow prevention: using strncpy instead of strcpy"
        elif "if (" in code_changes and "NULL" in code_changes:
            return "Null pointer check: adding null pointer validation"
        else:
            return "General code modification pattern"

    def _classify_pattern(self, pattern: str) -> str:
        """分类模式类型"""
        if "buffer" in pattern.lower():
            return "buffer_overflow"
        elif "free" in pattern.lower() or "memory" in pattern.lower():
            return "memory_management"
        elif "null" in pattern.lower():
            return "null_pointer"
        else:
            return "general"

    def _extract_evidence(self, code_changes: str) -> List[str]:
        """提取支持证据"""
        evidence = []
        lines = code_changes.split('\n')

        for i, line in enumerate(lines):
            if any(keyword in line.lower() for keyword in
                   ["if", "free", "strcpy", "memcpy", "null", "check"]):
                evidence.append(f"Line {i+1}: {line.strip()}")

        return evidence

    # ===== 0day漏洞分析支持方法 =====

    def _analyze_description_text(self, description: str) -> Dict[str, Any]:
        """分析漏洞描述文本"""
        # 基础NLP分析（可扩展为更复杂的分析）
        summary = {
            "length": len(description),
            "sentences": len(description.split('.')),
            "contains_code": '```' in description or 'code' in description.lower(),
            "technical_terms": self._extract_technical_terms(description),
            "severity_indicators": self._assess_severity(description)
        }
        return summary

    def _extract_indicators_from_description(self, description: str) -> List[str]:
        """从描述中提取漏洞指标"""
        indicators = []

        # 关键词检测
        vuln_keywords = [
            "overflow", "buffer", "heap", "stack", "memory", "corruption",
            "use after free", "double free", "null pointer", "dereference",
            "race condition", "integer overflow", "format string"
        ]

        for keyword in vuln_keywords:
            if keyword in description.lower():
                indicators.append(keyword)

        return indicators

    def _infer_patterns_from_description(self, description: str, vuln_type: Optional[str] = None) -> List[str]:
        """从描述推断检测模式"""
        patterns = []

        if vuln_type == "buffer_overflow" or "buffer" in description.lower():
            patterns.extend([
                "检查缓冲区边界",
                "验证输入长度",
                "使用安全函数"
            ])
        elif vuln_type == "use_after_free" or "use after free" in description.lower():
            patterns.extend([
                "检查指针有效性",
                "避免悬挂指针",
                "正确的内存管理"
            ])

        # 通用模式
        if not patterns:
            patterns = ["输入验证", "边界检查", "资源管理"]

        return patterns

    def _suggest_detection_methods(self, description: str, vuln_type: Optional[str] = None) -> List[str]:
        """建议检测方法"""
        methods = ["静态分析", "污点跟踪"]

        if "memory" in description.lower():
            methods.append("内存分析")
        if "input" in description.lower():
            methods.append("输入验证")

        return methods

    def _analyze_poc_structure(self, poc_code: str) -> Dict[str, Any]:
        """分析PoC代码结构"""
        return {
            "lines": len(poc_code.split('\n')),
            "functions": len([line for line in poc_code.split('\n') if '{' in line and '(' in line]),
            "includes": len([line for line in poc_code.split('\n') if '#include' in line]),
            "language": "cpp" if '#include' in poc_code else "unknown"
        }

    def _extract_vuln_indicators_from_poc(self, poc_code: str) -> List[str]:
        """从PoC中提取漏洞指标"""
        indicators = []

        dangerous_functions = ["strcpy", "strcat", "sprintf", "gets", "malloc", "free"]
        for func in dangerous_functions:
            if func in poc_code:
                indicators.append(f"使用危险函数: {func}")

        return indicators

    def _identify_attack_vector(self, poc_code: str) -> str:
        """识别攻击向量"""
        if "strcpy" in poc_code or "buffer" in poc_code.lower():
            return "缓冲区溢出"
        elif "free" in poc_code:
            return "内存破坏"
        else:
            return "通用攻击"

    def _derive_patterns_from_poc(self, poc_code: str, vuln_type: Optional[str] = None) -> List[str]:
        """从PoC推导检测模式"""
        patterns = []

        # 基于PoC代码分析推导检测逻辑
        if "strcpy" in poc_code:
            patterns.append("检测不安全的字符串拷贝操作")
        if "malloc" in poc_code and "free" in poc_code:
            patterns.append("检查内存分配和释放的配对使用")

        return patterns or ["基于PoC的模式分析"]

    def _extract_technical_terms(self, text: str) -> List[str]:
        """提取技术术语"""
        terms = []
        technical_keywords = [
            "buffer", "overflow", "heap", "stack", "memory", "corruption",
            "pointer", "allocation", "deallocation", "integer", "arithmetic"
        ]

        for term in technical_keywords:
            if term in text.lower():
                terms.append(term)

        return terms

    def _assess_severity(self, description: str) -> Dict[str, Any]:
        """评估严重程度"""
        severity_keywords = {
            "critical": ["remote code execution", "privilege escalation", "system compromise"],
            "high": ["memory corruption", "arbitrary code", "denial of service"],
            "medium": ["information disclosure", "crash", "hang"]
        }

        severity = "low"
        for level, keywords in severity_keywords.items():
            if any(keyword in description.lower() for keyword in keywords):
                severity = level
                break

        return {"level": severity, "confidence": 0.7}

    # ============================================================
    # LLM 模式提取辅助方法 (参考 Knighter patch2pattern)
    # ============================================================

    def _build_patch2pattern_prompt(self, patch: str, vuln_type: Optional[str] = None) -> str:
        """
        构建 patch2pattern prompt (参考 Knighter 模板)

        Args:
            patch: 补丁内容
            vuln_type: 推断的漏洞类型（可选）

        Returns:
            构建好的 prompt
        """
        # Knighter 风格的简洁模板
        prompt = """# Instruction

You will be provided with a patch in C/C++ code.
Please analyze the patch and find out the **bug pattern** in this patch.

A **bug pattern** is the root cause of this bug, meaning that programs with this pattern will have a great possibility of having the same bug.
Note that the bug pattern should be specific and accurate, which can be used to identify the buggy code provided in the patch.

# Target Patch

```diff
{patch}
```

# Formatting

Please tell me the **bug pattern** of the provided patch.
Please try not to wrap your response in functions if several lines of code are enough to express this pattern.

Your response should be like:

```
## Bug Pattern

{{describe the bug pattern here}}
```
"""

        # 替换占位符
        prompt = prompt.replace("{patch}", patch)

        # 如果有漏洞类型，添加上下文
        if vuln_type:
            prompt = f"""# Context

The vulnerability type is: {vuln_type}

""" + prompt

        return prompt

    def _build_desc2pattern_prompt(self, description: str, vuln_type: Optional[str] = None) -> str:
        """
        构建 description-to-pattern prompt (0day 支持)

        Args:
            description: 漏洞描述
            vuln_type: 漏洞类型（可选）

        Returns:
            构建好的 prompt
        """
        prompt = """# Instruction

You are an expert security analyst specializing in static analysis.
Your task is to analyze a vulnerability description and extract a structured bug pattern.

# What is a Bug Pattern?

A **bug pattern** is the root cause and characteristic signature of a vulnerability. It should:
- Describe the specific conditions that lead to the bug
- Identify the key code elements involved (functions, operations, types)
- Be specific enough to distinguish buggy code from similar safe code
- Be general enough to detect the same pattern in different contexts

# Vulnerability Description

{description}
"""

        # 替换占位符
        prompt = prompt.replace("{description}", description)

        # 如果有漏洞类型，添加上下文
        if vuln_type:
            prompt += f"\n# Vulnerability Type\n\n{vuln_type}\n"

        prompt += """
# Output Format

Provide your response in the following format:

```
## Bug Pattern

### Vulnerability Type
[type of vulnerability]

### Trigger Conditions
[what conditions trigger the bug]

### Key Code Elements
- **Functions/APIs**: [relevant functions]
- **Types**: [relevant data types]
- **Operations**: [key operations]

### Detection Strategy
[how to detect this pattern in code]

### Root Cause
[fundamental reason this bug occurs]
```
"""
        return prompt

    def _build_poc2pattern_prompt(self, poc_code: str, vuln_type: Optional[str] = None) -> str:
        """
        构建 poc-to-pattern prompt

        Args:
            poc_code: PoC 代码
            vuln_type: 漏洞类型（可选）

        Returns:
            构建好的 prompt
        """
        prompt = """# Instruction

You are an expert security analyst specializing in vulnerability detection.
Your task is to analyze a Proof-of-Concept (PoC) code and extract the vulnerability pattern that should be detected.

# PoC Code

```cpp
{poc_code}
```
"""

        # 替换占位符
        prompt = prompt.replace("{poc_code}", poc_code)

        # 如果有漏洞类型，添加上下文
        if vuln_type:
            prompt += f"\n# Vulnerability Type\n\n{vuln_type}\n"

        prompt += """
# Output Format

Analyze the PoC and extract:

```
## Bug Pattern

### Vulnerability Type
[type demonstrated by PoC]

### Attack Vector
[how the PoC exploits the vulnerability]

### Detection Strategy
[how to detect code vulnerable to this attack]

### Key Code Elements
- Functions/APIs to monitor
- Patterns to look for
- Conditions that indicate vulnerability
```
"""
        return prompt

    def _extract_pattern_from_llm_response(self, response: str) -> Optional[str]:
        """
        从 LLM 响应中提取 Bug Pattern

        支持 Knighter 风格的 "## Bug Pattern" 格式

        Args:
            response: LLM 响应文本

        Returns:
            提取的 pattern，失败返回 None
        """
        if not response:
            return None

        # 移除 think 标签（推理模型特殊输出）
        try:
            from ..utils.code_utils import remove_think_tags
            response = remove_think_tags(response)
        except:
            pass

        import re

        # 模式 1: Knighter 风格 - "## Bug Pattern"
        pattern1_match = re.search(r'##\s*Bug\s*Pattern\s*\n+(.*?)(?=\n##|\n\n\n|$)', response, re.DOTALL | re.IGNORECASE)
        if pattern1_match:
            pattern = pattern1_match.group(1).strip()
            # 清理多余内容，保留核心 pattern
            lines = pattern.split('\n')
            core_lines = []
            for line in lines:
                line = line.strip()
                # 跳过空行和明显的标记行
                if not line or line.startswith('###') or line.startswith('#'):
                    continue
                # 跳过 "Vulnerability Type:" 等标记
                if line.endswith(':'):
                    continue
                core_lines.append(line)
            if core_lines:
                return '\n'.join(core_lines[:20])  # 最多 20 行

        # 模式 2: 直接寻找包含关键描述的段落
        # 匹配 "root cause", "trigger", "detect" 等关键词附近的段落
        keywords = ['root cause', 'trigger', 'detect', 'vulnerability', 'bug occurs']
        for keyword in keywords:
            pattern_match = re.search(rf'.*?{keyword}.*?:?\s*([^\n]+(?:\n[^\n#]+)*?)(?=\n\n|\n#|$)', response, re.IGNORECASE)
            if pattern_match:
                candidate = pattern_match.group(1).strip()
                if len(candidate) > 20:  # 确保不是太短
                    return candidate

        # 模式 3: 没有明确标记，提取前几段有意义的文本
        paragraphs = response.split('\n\n')
        for para in paragraphs[:5]:
            para = para.strip()
            # 跳过标题和空段落
            if para.startswith('#') or len(para) < 50:
                continue
            # 确保包含一些关键词
            if any(kw in para.lower() for kw in ['bug', 'vulnerability', 'pattern', 'detect', 'check']):
                return para[:500]  # 最多 500 字符

        return None

    def _extract_vuln_type_from_llm_response(self, response: str) -> Optional[str]:
        """
        从 LLM 响应中提取漏洞类型

        Args:
            response: LLM 响应文本

        Returns:
            提取的漏洞类型，失败返回 None
        """
        if not response:
            return None

        import re

        # 常见漏洞类型映射
        vuln_type_mapping = {
            'buffer overflow': 'buffer_overflow',
            'buffer overflow': 'buffer_overflow',
            'use after free': 'use_after_free',
            'use-after-free': 'use_after_free',
            'null pointer': 'null_pointer',
            'null pointer dereference': 'null_pointer',
            'double free': 'double_free',
            'double-free': 'double_free',
            'memory leak': 'memory_leak',
            'memory leak': 'memory_leak',
            'race condition': 'race_condition',
            'integer overflow': 'integer_overflow',
            'format string': 'format_string',
            'format string': 'format_string',
        }

        response_lower = response.lower()

        # 匹配 "Vulnerability Type: xxx" 或 "### Vulnerability Type\nxxx" 格式
        type_patterns = [
            r'(?:vulnerability\s+type|vulnerability)\s*[:\s]\s*([^\n#]+?)(?:\n|$|###)',
            r'###?\s*vulnerability\s+type\s*\n\s*([^\n#]+?)(?:\n|$|###)',
        ]

        for pattern in type_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                extracted = match.group(1).strip().lower()
                # 映射到标准类型名
                for key, value in vuln_type_mapping.items():
                    if key in extracted:
                        return value
                # 如果没有映射，返回原始值（清理后）
                return extracted.replace(' ', '_').replace('-', '_')[:50]

        # 如果没有找到明确标记，尝试从响应中推断
        for key, value in vuln_type_mapping.items():
            if key in response_lower:
                return value

        return None
