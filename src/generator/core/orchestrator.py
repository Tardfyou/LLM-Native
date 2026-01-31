"""
生成引擎编排器 - 协调各个Agent完成代码生成任务
"""

import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

# 使用loguru以支持logger.success()等方法
from loguru import logger

from ..models.generation_models import (
    GenerationInput,
    GenerationOutput,
    GenerationState,
    ValidationResult,
    DetectionPlan
)
from ..agents import (
    AnalysisAgent,
    GenerationAgent,
    ValidationAgent,
    RepairAgent,
    KnowledgeAgent
)
from ..prompts.prompt_manager import PromptManager, EnhancedPromptManager
from ..lsp.clangd_client import ClangdClient
from knowledge_base.manager import KnowledgeBaseManager

class GeneratorOrchestrator:
    """生成引擎编排器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.is_running = False

        # 初始化组件 - 使用 PromptManager 包装器以支持完整功能
        self.knowledge_base = KnowledgeBaseManager(self.config)
        self.prompt_manager = PromptManager()  # 修复：使用包装器而不是 EnhancedPromptManager
        # 从配置读取 clangd 路径
        clangd_path = self.config.get("generator", {}).get("compilation", {}).get("clangd_path", "clangd")
        self.lsp_client = ClangdClient(clangd_path=clangd_path)

        # 初始化Agent
        self.agents = self._initialize_agents()

        # 状态管理
        self.current_state = None

        logger.info("GeneratorOrchestrator initialized")

    def _initialize_agents(self) -> Dict[str, Any]:
        """初始化所有Agent"""
        # 尝试从配置获取LLM客户端
        llm_client = self.config.get("llm_client", None)

        return {
            "analysis": AnalysisAgent(
                lsp_client=self.lsp_client,
                prompt_manager=self.prompt_manager,
                llm_client=llm_client  # 传入LLM客户端用于模式提取
            ),
            "generation": GenerationAgent(
                prompt_manager=self.prompt_manager,
                lsp_client=self.lsp_client,
                llm_client=llm_client  # 传入LLM客户端
            ),
            "validation": ValidationAgent(lsp_client=self.lsp_client),
            "repair": RepairAgent(
                prompt_manager=self.prompt_manager,
                lsp_client=self.lsp_client,
                llm_client=llm_client  # 传入LLM客户端给 repair agent
            ),
            "knowledge": KnowledgeAgent(knowledge_base=self.knowledge_base)
        }

    async def start(self):
        """启动编排器"""
        if self.is_running:
            return

        try:
            # 启动LSP客户端
            project_root = Path(self.config.get("project_root", ".")).resolve()
            if not await self.lsp_client.initialize_server(project_root):
                logger.warning("LSP client initialization failed, continuing without LSP")

            # 启动所有Agent
            for agent_name, agent in self.agents.items():
                await agent.start()
                logger.info(f"Started agent: {agent_name}")

            self.is_running = True
            logger.info("GeneratorOrchestrator started successfully")

        except Exception as e:
            logger.error(f"Failed to start GeneratorOrchestrator: {e}")
            await self.stop()
            raise

    async def stop(self):
        """停止编排器"""
        if not self.is_running:
            return

        try:
            # 停止所有Agent
            for agent_name, agent in self.agents.items():
                await agent.stop()
                logger.info(f"Stopped agent: {agent_name}")

            # 停止LSP客户端
            await self.lsp_client.stop_server()

            self.is_running = False
            logger.info("GeneratorOrchestrator stopped")

        except Exception as e:
            logger.error(f"Error stopping GeneratorOrchestrator: {e}")

    async def generate_checker(self, input_data: GenerationInput) -> GenerationOutput:
        """生成静态分析检测器"""
        if not self.is_running:
            await self.start()

        start_time = datetime.now()
        logger.info(f"Starting checker generation for: {input_data.vulnerability_type}")

        # 初始化生成状态
        self.current_state = GenerationState(input_data=input_data)
        self.current_state.update_stage("initialized")

        try:
            # 第一阶段：补丁or漏洞描述分析
            await self._stage_patch_analysis()

            # 第二阶段：知识检索
            await self._stage_knowledge_retrieval()

            # 第二阶段半：基于RAG结果精化plan和pattern
            await self._stage_plan_pattern_refinement()

            # 第三阶段：代码生成
            await self._stage_code_generation()

            # 第四阶段：验证修复循环
            await self._stage_validation_and_repair()

            # 第五阶段：最终优化
            await self._stage_final_optimization()

            # 生成输出
            output = self._create_output(start_time)

            logger.info(f"Checker generation completed successfully in {output.generation_time:.2f}s")
            return output

        except Exception as e:
            logger.error(f"Checker generation failed: {e}")
            # 创建失败输出
            return GenerationOutput(
                checker_code="",
                success=False,
                pattern="",  # 默认空模式
                plan=DetectionPlan(vulnerability_pattern="", detection_strategy=""),  # 默认空计划
                final_validation=ValidationResult(
                    success=False,
                    errors=[f"Generation failed: {str(e)}"]
                ),
                generation_time=(datetime.now() - start_time).total_seconds()
            )

    async def _stage_patch_analysis(self):
        """第一阶段：补丁分析"""
        logger.info("Stage 1: Patch Analysis")
        self.current_state.update_stage("patch_analysis")

        # 根据输入类型选择分析方法
        analysis_agent = self.agents["analysis"]

        # 确定分析任务类型和数据
        if self.current_state.input_data.patch:
            task_type = "patch_analysis"
            task_data = {"patch": self.current_state.input_data.patch}
        elif self.current_state.input_data.vulnerability_description:
            task_type = "description_analysis"
            task_data = {"vulnerability_description": self.current_state.input_data.vulnerability_description}
        elif self.current_state.input_data.poc_code:
            task_type = "poc_analysis"
            task_data = {"poc_code": self.current_state.input_data.poc_code}
        else:
            raise ValueError("没有可用的输入数据进行分析")

        # 添加上下文信息
        task_data.update({
            "task_type": task_type,
            "vulnerability_type": self.current_state.input_data.vulnerability_type,
            "context": {
                "framework": self.current_state.input_data.framework,
                "language": self.current_state.input_data.language,
                "cwe_id": self.current_state.input_data.cwe_id
            }
        })

        analysis_result = await analysis_agent.execute_task(task_data)

        # 保存分析结果到状态中，供后续修复阶段使用
        self.current_state.analysis_result = analysis_result

        # 更新状态 - 根据分析类型处理结果
        analysis_type = analysis_result.get("analysis_type", "patch_based")
        inferred_type = None  # 初始化变量

        if analysis_type == "patch_based":
            # 传统补丁分析结果
            self.current_state.vulnerability_pattern = analysis_result.get("pattern", "")
            inferred_type = analysis_result.get("inferred_vulnerability_type")
            if inferred_type and not self.current_state.input_data.vulnerability_type:
                logger.info(f"Using inferred vulnerability type: {inferred_type}")
        elif analysis_type == "description_based":
            # 基于描述的分析结果
            patterns = analysis_result.get("potential_patterns", [])
            self.current_state.vulnerability_pattern = patterns[0] if patterns else ""
            logger.info(f"Description-based analysis completed")
        elif analysis_type == "poc_based":
            # 基于PoC的分析结果
            patterns = analysis_result.get("detection_patterns", [])
            self.current_state.vulnerability_pattern = patterns[0] if patterns else ""
            logger.info(f"PoC-based analysis completed")

        # 如果没有指定漏洞类型，尝试从结果中推断
        if inferred_type and not self.current_state.input_data.vulnerability_type:
            self.current_state.input_data.vulnerability_type = inferred_type

        self.current_state.current_stage = "analysis_complete"

        logger.info("Patch analysis completed")

    async def _stage_knowledge_retrieval(self):
        """第二阶段：知识检索"""
        logger.info("Stage 2: Knowledge Retrieval")
        self.current_state.update_stage("knowledge_retrieval")

        # 构建检索查询 - 优先使用漏洞描述（vulnerability_type可能为空）
        vuln_desc = self.current_state.input_data.vulnerability_description or ""
        vuln_type = self.current_state.input_data.vulnerability_type or ""

        # 使用描述作为主要查询，类型作为补充
        query_parts = []
        if vuln_desc:
            query_parts.append(vuln_desc[:200])  # 限制长度避免过长
        if vuln_type and vuln_type not in vuln_desc:
            query_parts.append(vuln_type)
        query_parts.append("checker patterns")

        search_query = " ".join(query_parts) if query_parts else "static analysis checker patterns"

        logger.debug(f"Knowledge retrieval query: {search_query[:100]}...")

        # 检索相关知识 - 增加top_k以获取更多Knighter示例
        knowledge_agent = self.agents["knowledge"]
        knowledge_result = await knowledge_agent.execute_task({
            "query": search_query,
            "context": {
                "vulnerability_type": vuln_type or "general",
                "framework": self.current_state.input_data.framework,
                "language": self.current_state.input_data.language
            },
            "task_type": "knowledge_retrieval",
            "top_k": 3  # 增加到3以获取更多Knighter示例（pattern, plan, checker）
        })

        # 存储检索结果用于后续使用
        self.current_state.agent_messages.append({
            "stage": "knowledge_retrieval",
            "result": knowledge_result,
            "timestamp": datetime.now().isoformat()
        })

        logger.info(f"Retrieved {len(knowledge_result.get('knowledge', []))} knowledge items")

    async def _stage_plan_pattern_refinement(self):
        """第二阶段半：基于 patch 生成漏洞模式和实现计划（参考 RAG 范式）"""
        logger.info("Stage 2.5: Plan/Pattern Generation (LLM-based with RAG paradigm)")
        self.current_state.update_stage("plan_pattern_refinement")

        # 从知识检索阶段获取RAG结果（用于范式参考）
        retrieved_knowledge = []
        for msg in self.current_state.agent_messages:
            if msg.get("stage") == "knowledge_retrieval":
                knowledge_result = msg.get("result", {})
                retrieved_knowledge = knowledge_result.get("knowledge", [])
                break

        # 收集 RAG 上下文（用于参考 Knighter 范式）
        rag_context_list = []
        if retrieved_knowledge:
            logger.info(f"Collected {len(retrieved_knowledge)} RAG entries for paradigm reference")

            for item in retrieved_knowledge:
                entry = item.entry if hasattr(item, 'entry') else item
                content = getattr(entry, 'content', '')
                title = getattr(entry, 'title', '')
                metadata = getattr(entry, 'metadata', {})

                if content:
                    rag_context_list.append({
                        'title': title,
                        'content': content,
                        'metadata': metadata
                    })

        # 存储 RAG 上下文到状态中（供代码生成阶段使用）
        self.current_state.rag_context = rag_context_list

        # 调用 LLM 生成 pattern 和 plan（基于 patch，参考 RAG 范式）
        logger.info("Generating pattern and plan from patch using LLM...")

        generation_agent = self.agents["generation"]

        # 构建生成任务
        generation_task = {
            "task_type": "generate_plan_pattern_from_patch",
            "patch": self.current_state.input_data.patch,
            "vulnerability_description": self.current_state.input_data.vulnerability_description,
            "vulnerability_type": self.current_state.input_data.vulnerability_type,
            "rag_context": rag_context_list  # 传递 RAG 上下文作为范式参考
        }

        # 调用 LLM 生成
        generation_result = await generation_agent.execute_task(generation_task)

        # 保存生成的 pattern 和 plan
        generated_pattern = generation_result.get("pattern", "")
        generated_plan = generation_result.get("plan", "")

        self.current_state.vulnerability_pattern = generated_pattern
        # 存储为 DetectionPlan 对象
        self.current_state.detection_plan = DetectionPlan(
            vulnerability_pattern=generated_pattern,
            detection_strategy=generated_plan
        )

        logger.info(f"Pattern generated: {len(generated_pattern)} chars")
        logger.info(f"Plan generated: {len(generated_plan)} chars")

        # 存储到消息历史
        self.current_state.agent_messages.append({
            "stage": "plan_pattern_refinement",
            "result": {
                "pattern": generated_pattern,
                "plan": generated_plan,
                "rag_context_count": len(rag_context_list)
            },
            "timestamp": datetime.now().isoformat()
        })

        logger.info("Plan/Pattern generation completed")

    async def _stage_code_generation(self):
        """第三阶段：代码生成"""
        logger.info("Stage 3: Code Generation")
        self.current_state.update_stage("code_generation")

        # 获取 RAG 上下文（已收集的完整 RAG 条目）
        rag_context = getattr(self.current_state, 'rag_context', [])
        vulnerability_pattern = self.current_state.vulnerability_pattern or ""

        logger.info(f"Using vulnerability pattern ({len(vulnerability_pattern)} chars) for code generation")
        logger.info(f"Using {len(rag_context)} RAG entries as reference context")

        # 生成初始代码 - 传递漏洞模式和完整 RAG 上下文
        generation_agent = self.agents["generation"]
        generation_result = await generation_agent.execute_task({
            "analysis": {
                "vulnerability_indicators": [self.current_state.input_data.vulnerability_type],
                "framework": self.current_state.input_data.framework,
                "description_summary": {
                    "summary": self.current_state.input_data.vulnerability_description,
                    "technical_terms": []
                },
                # 漏洞模式
                "vulnerability_pattern": vulnerability_pattern
            },
            # 完整的 RAG 上下文（包含 pattern、plan、checker code 等）
            "rag_context": rag_context,
            "task_type": "initial_generation"
        })

        # 更新状态
        self.current_state.generated_code = generation_result.get("generated_code", "")
        self.current_state.confidence_score = generation_result.get("confidence_score", 0.0)

        logger.info("Initial code generation completed")

    async def _stage_validation_and_repair(self):
        """第四阶段：验证修复循环 - 增强版，显示详细的自愈信息"""
        logger.info("Stage 4: Validation and Repair (Self-Healing)")
        self.current_state.update_stage("validation_repair")

        max_iterations = self.current_state.input_data.max_iterations
        iteration = 0

        logger.info("=" * 60)
        logger.info(f"🔄 Starting Self-Healing Loop (Max {max_iterations} iterations)")
        logger.info("=" * 60)

        while iteration < max_iterations:
            iter_num = iteration + 1
            logger.info("")
            logger.info(f"📍 Iteration {iter_num}/{max_iterations}")
            logger.info("-" * 60)

            # 验证代码
            validation_agent = self.agents["validation"]
            validation_result = await validation_agent.execute_task({
                "code": self.current_state.generated_code,
                "vulnerability_type": self.current_state.input_data.vulnerability_type,
                "task_type": "full_validation"
            })

            # 添加验证结果
            self.current_state.add_validation_result(validation_result["validation_result"])

            if validation_result["success"]:
                logger.success("")
                logger.success("=" * 60)
                logger.success(f"✅ Validation PASSED after {iter_num} iteration(s)")
                logger.success("=" * 60)
                break
            else:
                issues_count = len(validation_result.get("issues", []))
                logger.warning(f"❌ Validation failed - Found {issues_count} issue(s)")

                # 显示详细问题
                for i, issue in enumerate(validation_result.get("issues", [])[:5], 1):
                    logger.warning(f"   Issue {i}: {issue}")
                if issues_count > 5:
                    logger.warning(f"   ... and {issues_count - 5} more issue(s)")

                # 修复代码 - 传递上下文信息以保持对话历史
                logger.info("")
                logger.info(f"🔧 Attempting repair (Iteration {iter_num})...")
                repair_agent = self.agents["repair"]

                # 获取 RAG 上下文用于修复
                rag_context = getattr(self.current_state, 'rag_context', [])
                vulnerability_pattern = self.current_state.vulnerability_pattern or ""

                repair_context = {
                    "code": self.current_state.generated_code,
                    "issues": validation_result["issues"],
                    "task_type": "error_repair",
                    # 添加原始漏洞上下文
                    "vulnerability_type": self.current_state.input_data.vulnerability_type,
                    "vulnerability_description": self.current_state.input_data.vulnerability_description,
                    # 使用漏洞模式
                    "vulnerability_pattern": vulnerability_pattern,
                    # 传递 RAG 上下文用于修复参考
                    "rag_context": rag_context,
                    # 如果有分析结果，也传递过去
                    "analysis_context": getattr(self.current_state, 'analysis_result', None)
                }

                repair_result = await repair_agent.execute_task(repair_context)

                # 更新代码
                old_code = self.current_state.generated_code
                new_code = repair_result.get("repaired_code", self.current_state.generated_code)
                self.current_state.generated_code = new_code

                # 显示修复结果
                if repair_result.get("success"):
                    code_changed = old_code != new_code
                    if code_changed:
                        logger.success(f"   ✅ Repair applied successfully")
                        logger.info(f"   📝 Code size: {len(old_code)} → {len(new_code)} bytes")
                    else:
                        logger.warning(f"   ⚠️  Repair completed but code unchanged")
                else:
                    logger.error(f"   ❌ Repair failed")

                # 记录迭代
                self.current_state.iteration_count = iteration + 1

                iteration += 1

        if iteration >= max_iterations:
            logger.warning("")
            logger.warning("=" * 60)
            logger.warning(f"⚠️  Reached maximum iterations ({max_iterations})")
            logger.warning(f"   Attempting final verification and salvage...")
            logger.warning("=" * 60)

            # 最终验证：尝试最后一次规则修复
            await self._final_salvage_attempt(iteration)

    async def _final_salvage_attempt(self, iteration: int):
        """达到最大迭代次数后的最终挽救尝试"""
        logger.info("")
        logger.info("🔧 FINAL SALVAGE ATTEMPT")
        logger.info("-" * 60)

        # 获取最后一次验证结果
        if not self.current_state.validation_results:
            logger.warning("No validation results available for salvage")
            return

        last_validation = self.current_state.validation_results[-1]
        remaining_issues = last_validation.errors + last_validation.warnings

        if not remaining_issues:
            logger.success("No remaining issues - code is salvageable")
            return

        logger.info(f"Remaining issues: {len(remaining_issues)}")

        # 尝试最后一次规则修复（不带LLM，只使用规则）
        repair_agent = self.agents["repair"]

        # 提取上下文信息
        vuln_desc = self.current_state.input_data.vulnerability_description
        vuln_type = self.current_state.input_data.vulnerability_type
        vuln_pattern = self.current_state.vulnerability_pattern or ""
        rag_context = getattr(self.current_state, 'rag_context', [])
        analysis_context = getattr(self.current_state, 'analysis_result', None)

        salvage_context = {
            "vulnerability_type": vuln_type or "",
            "vulnerability_description": vuln_desc or "",
            "vulnerability_pattern": vuln_pattern,
            "analysis_context": analysis_context,
            "attempt": iteration + 1
        }

        # 只使用规则修复（快速）
        logger.info("Attempting rule-only salvage repair...")
        repair_result = await repair_agent.execute_task({
            "code": self.current_state.generated_code,
            "issues": remaining_issues,
            "task_type": "error_repair",
            **salvage_context
        })

        if repair_result.get("code_changed", False):
            self.current_state.generated_code = repair_result.get("repaired_code", self.current_state.generated_code)

            # 最终验证
            logger.info("Validating salvaged code...")
            validation_agent = self.agents["validation"]
            final_validation = await validation_agent.execute_task({
                "code": self.current_state.generated_code,
                "vulnerability_type": vuln_type or "",
                "task_type": "full_validation"
            })

            self.current_state.add_validation_result(final_validation["validation_result"])

            if final_validation.get("success", False):
                logger.success("=" * 60)
                logger.success("✅ SALVAGE SUCCESSFUL - Code compiled after final attempt!")
                logger.success("=" * 60)
            else:
                remaining = len(final_validation.get("issues", []))
                logger.warning(f"⚠️  Salvage partially successful - {remaining} issue(s) remain")
        else:
            logger.warning("⚠️  Salvage attempt did not change code")

        # 生成诊断报告
        self._generate_diagnostic_report(iteration, remaining_issues)

    def _generate_diagnostic_report(self, iteration: int, issues: list):
        """生成诊断报告用于调试"""
        logger.info("")
        logger.info("📋 DIAGNOSTIC REPORT")
        logger.info("-" * 60)

        # 按错误类型分组
        error_types = {}
        for issue in issues:
            # 提取错误类型
            if "error:" in issue:
                error_msg = issue.split("error:", 1)[1].strip() if "error:" in issue else issue
                error_type = error_msg.split()[0] if error_msg else "unknown"
                error_types[error_type] = error_types.get(error_type, 0) + 1

        logger.info("Remaining error breakdown:")
        for error_type, count in sorted(error_types.items(), key=lambda x: -x[1])[:10]:
            logger.info(f"  {error_type}: {count}")

        # 建议
        logger.info("")
        logger.info("💡 RECOMMENDATIONS:")
        logger.info("  1. Review the generated checker code for complex state tracking")
        logger.info("  2. Consider simplifying to avoid REGISTER_MAP_WITH_PROGRAMSTATE")
        logger.info("  3. Use SVal constraint checking instead of state maps where possible")
        logger.info("  4. Check LLM output for hallucinated APIs (e.g., makeNull)")

    async def _stage_final_optimization(self):
        """第五阶段：最终优化"""
        logger.info("Stage 5: Final Optimization")
        self.current_state.update_stage("final_optimization")

        # 代码优化
        repair_agent = self.agents["repair"]
        optimization_result = await repair_agent.execute_task({
            "code": self.current_state.generated_code,
            "goals": ["readability", "maintainability"],
            "task_type": "code_optimization"
        })

        # 更新最终代码
        if optimization_result.get("success"):
            self.current_state.generated_code = optimization_result.get("optimized_code",
                                                                       self.current_state.generated_code)

        logger.info("Final optimization completed")

    def _create_output(self, start_time: datetime) -> GenerationOutput:
        """创建输出结果"""
        # 获取最终验证结果
        final_validation = ValidationResult()
        if self.current_state.validation_results:
            final_validation = self.current_state.validation_results[-1]

        # 使用存储的 detection_plan（如果有的话）
        detection_plan = self.current_state.detection_plan
        if not detection_plan:
            # 如果没有生成 plan，使用默认值
            vulnerability_pattern = self.current_state.vulnerability_pattern or ""
            detection_plan = DetectionPlan(
                vulnerability_pattern=vulnerability_pattern,
                detection_strategy="static_analysis"
            )

        return GenerationOutput(
            checker_code=self.current_state.generated_code,
            success=final_validation.success,
            pattern=detection_plan.vulnerability_pattern or "",
            plan=detection_plan,
            final_validation=final_validation,
            confidence_score=self.current_state.confidence_score,
            generation_time=self.current_state.get_elapsed_time(),
            iterations_used=self.current_state.iteration_count,
            generation_trace=self.current_state.agent_messages
        )

    async def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        if not self.current_state:
            return {"status": "idle"}

        return {
            "status": "running" if self.is_running else "stopped",
            "current_stage": self.current_state.current_stage,
            "vulnerability_type": self.current_state.input_data.vulnerability_type,
            "iterations": self.current_state.iteration_count,
            "confidence_score": self.current_state.confidence_score,
            "elapsed_time": self.current_state.get_elapsed_time(),
            "validations_count": len(self.current_state.validation_results)
        }

    async def get_agent_stats(self) -> Dict[str, Any]:
        """获取Agent统计信息"""
        stats = {}
        for agent_name, agent in self.agents.items():
            stats[agent_name] = agent.get_performance_stats()

        return stats

    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.stop()
