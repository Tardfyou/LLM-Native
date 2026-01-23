"""
知识Agent - 负责知识管理和学习
"""

from typing import Dict, Any, Optional, List

# 使用loguru以支持logger.success()等方法
from loguru import logger

from .base_agent import BaseAgent, AgentMessage

class KnowledgeAgent(BaseAgent):
    """知识Agent - 负责知识管理和学习"""

    def __init__(self, knowledge_base=None):
        super().__init__("knowledge_agent", "knowledge_management")
        self.knowledge_base = knowledge_base

        # 学习统计
        self.patterns_learned = 0
        self.examples_added = 0

    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理接收到的消息"""
        if message.message_type == "retrieve_knowledge":
            return await self._handle_retrieve_knowledge(message)
        elif message.message_type == "store_knowledge":
            return await self._handle_store_knowledge(message)
        elif message.message_type == "learn_from_result":
            return await self._handle_learn_from_result(message)
        else:
            logger.warning(f"KnowledgeAgent received unknown message type: {message.message_type}")
            return None

    async def _handle_retrieve_knowledge(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理知识检索请求"""
        try:
            query = message.content.get("query", "")
            context = message.content.get("context", {})
            top_k = message.content.get("top_k", 5)

            # 执行检索
            knowledge_result = await self.execute_task({
                "query": query,
                "context": context,
                "top_k": top_k,
                "task_type": "knowledge_retrieval"
            })

            # 发送检索结果
            return await self.send_message(
                message.sender,
                "knowledge_retrieved",
                knowledge_result
            )

        except Exception as e:
            logger.error(f"KnowledgeAgent error in retrieve_knowledge: {e}")
            return None

    async def _handle_store_knowledge(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理知识存储请求"""
        try:
            knowledge_entry = message.content.get("knowledge_entry", {})
            category = message.content.get("category", "generated")

            # 执行存储
            store_result = await self.execute_task({
                "knowledge_entry": knowledge_entry,
                "category": category,
                "task_type": "knowledge_storage"
            })

            return await self.send_message(
                message.sender,
                "knowledge_stored",
                store_result
            )

        except Exception as e:
            logger.error(f"KnowledgeAgent error in store_knowledge: {e}")
            return None

    async def _handle_learn_from_result(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理从结果中学习"""
        try:
            generation_result = message.content.get("generation_result", {})
            feedback = message.content.get("feedback", {})

            # 执行学习
            learning_result = await self.execute_task({
                "generation_result": generation_result,
                "feedback": feedback,
                "task_type": "learning_from_feedback"
            })

            return await self.send_message(
                "orchestrator",
                "learning_complete",
                learning_result
            )

        except Exception as e:
            logger.error(f"KnowledgeAgent error in learn_from_result: {e}")
            return None

    async def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行知识管理任务"""
        import asyncio
        start_time = asyncio.get_event_loop().time()

        try:
            task_type = task_data.get("task_type", "knowledge_task")

            if task_type == "knowledge_retrieval":
                result = await self._retrieve_knowledge(task_data)
            elif task_type == "knowledge_storage":
                result = await self._store_knowledge(task_data)
            elif task_type == "learning_from_feedback":
                result = await self._learn_from_feedback(task_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")

            # 更新性能统计
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, result.get("success", True))

            return result

        except Exception as e:
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, False)
            raise e

    async def _retrieve_knowledge(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """检索知识"""
        if not self.knowledge_base:
            return {
                "success": False,
                "knowledge": [],
                "error": "Knowledge base not available"
            }

        query = task_data["query"]
        context = task_data.get("context", {})
        top_k = task_data.get("top_k", 5)

        try:
            # 构建检索查询
            search_query = self._build_search_query(query, context)

            # 执行检索
            results = await self.knowledge_base.search_async(
                search_query,
                top_k=top_k,
                filters=self._build_filters(context)
            )

            return {
                "success": True,
                "knowledge": results,
                "query": search_query,
                "top_k": top_k
            }

        except Exception as e:
            logger.error(f"Knowledge retrieval failed: {e}")
            return {
                "success": False,
                "knowledge": [],
                "error": str(e)
            }

    async def _store_knowledge(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """存储知识"""
        if not self.knowledge_base:
            return {
                "success": False,
                "error": "Knowledge base not available"
            }

        knowledge_entry = task_data["knowledge_entry"]
        category = task_data.get("category", "generated")

        try:
            # 添加元数据
            knowledge_entry["metadata"] = knowledge_entry.get("metadata", {})
            knowledge_entry["metadata"]["category"] = category
            knowledge_entry["metadata"]["added_by"] = "knowledge_agent"
            knowledge_entry["metadata"]["timestamp"] = self._get_timestamp()

            # 执行存储
            result = await self.knowledge_base.add_entry_async(knowledge_entry)

            if result:
                self.examples_added += 1

            return {
                "success": result,
                "entry_id": knowledge_entry.get("id"),
                "category": category
            }

        except Exception as e:
            logger.error(f"Knowledge storage failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _learn_from_feedback(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """从反馈中学习"""
        generation_result = task_data["generation_result"]
        feedback = task_data.get("feedback", {})

        learning_insights = []

        try:
            # 分析成功案例
            if generation_result.get("success", False):
                success_patterns = self._extract_success_patterns(generation_result)
                learning_insights.extend(success_patterns)

                # 存储成功模式
                for pattern in success_patterns:
                    await self._store_success_pattern(pattern)

            # 分析失败案例
            else:
                failure_patterns = self._extract_failure_patterns(generation_result, feedback)
                learning_insights.extend(failure_patterns)

                # 存储失败模式以避免重复
                for pattern in failure_patterns:
                    await self._store_failure_pattern(pattern)

            # 更新检索策略
            await self._update_retrieval_strategy(learning_insights)

            return {
                "success": True,
                "learning_insights": learning_insights,
                "patterns_learned": len(learning_insights)
            }

        except Exception as e:
            logger.error(f"Learning from feedback failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "learning_insights": []
            }

    def _build_search_query(self, query: str, context: Dict[str, Any]) -> str:
        """构建搜索查询"""
        # 增强查询以包含上下文信息
        enhanced_query = query

        if context.get("vulnerability_type"):
            enhanced_query += f" {context['vulnerability_type']}"

        if context.get("framework"):
            enhanced_query += f" {context['framework']}"

        if context.get("language"):
            enhanced_query += f" {context['language']}"

        return enhanced_query

    def _build_filters(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """构建检索过滤器

        注意：vulnerability_type（如"buffer overflow"）应该用于搜索查询，
        而不是作为category过滤器，因为知识库的category值是：
        cwe_patterns, code_examples, expert_knowledge, framework_api 等
        """
        filters = {}

        # 只使用 framework 和 language 作为过滤器
        # vulnerability_type 已经由 _build_search_query 加入查询字符串，不需要单独过滤
        if context.get("framework"):
            filters["framework"] = context["framework"]

        if context.get("language"):
            filters["language"] = context["language"]

        return filters

    def _extract_success_patterns(self, generation_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取成功模式"""
        patterns = []

        # 分析成功的生成结果
        if generation_result.get("validation_result", {}).get("quality_score", 0) > 0.8:
            patterns.append({
                "type": "success_pattern",
                "vulnerability_type": generation_result.get("vulnerability_type"),
                "framework": generation_result.get("framework"),
                "code_pattern": self._extract_code_pattern(generation_result.get("generated_code", "")),
                "validation_score": generation_result.get("validation_result", {}).get("quality_score", 0),
                "timestamp": self._get_timestamp()
            })

        return patterns

    def _extract_failure_patterns(self, generation_result: Dict[str, Any], feedback: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取失败模式"""
        patterns = []

        # 分析失败的原因
        errors = generation_result.get("validation_result", {}).get("errors", [])
        for error in errors:
            patterns.append({
                "type": "failure_pattern",
                "error_type": self._classify_error(error),
                "vulnerability_type": generation_result.get("vulnerability_type"),
                "context": error,
                "timestamp": self._get_timestamp()
            })

        return patterns

    async def _store_success_pattern(self, pattern: Dict[str, Any]):
        """存储成功模式"""
        if self.knowledge_base:
            try:
                await self.knowledge_base.add_entry_async({
                    "id": f"success_pattern_{self.patterns_learned}",
                    "content": f"Successful pattern for {pattern['vulnerability_type']}: {pattern['code_pattern']}",
                    "title": f"Success Pattern - {pattern['vulnerability_type']}",
                    "category": "success_patterns",
                    "framework": pattern.get('framework', 'general'),
                    "language": "cpp",
                    "metadata": pattern
                })
                self.patterns_learned += 1
            except Exception as e:
                logger.warning(f"Failed to store success pattern: {e}")

    async def _store_failure_pattern(self, pattern: Dict[str, Any]):
        """存储失败模式"""
        if self.knowledge_base:
            try:
                await self.knowledge_base.add_entry_async({
                    "id": f"failure_pattern_{self.patterns_learned}",
                    "content": f"Avoid this pattern: {pattern['context']}",
                    "title": f"Failure Pattern - {pattern['error_type']}",
                    "category": "failure_patterns",
                    "framework": "general",
                    "language": "cpp",
                    "metadata": pattern
                })
                self.patterns_learned += 1
            except Exception as e:
                logger.warning(f"Failed to store failure pattern: {e}")

    async def _update_retrieval_strategy(self, learning_insights: List[Dict[str, Any]]):
        """更新检索策略"""
        # 基于学习结果调整检索权重和过滤器
        # 这里可以实现更复杂的策略更新逻辑
        pass

    def _extract_code_pattern(self, code: str) -> str:
        """提取代码模式"""
        # 简化的代码模式提取
        if "strcpy" in code:
            return "uses_strcpy_function"
        elif "std::unique_ptr" in code:
            return "uses_smart_pointers"
        elif "checkPreCall" in code:
            return "clang_checker_pattern"
        else:
            return "general_pattern"

    def _classify_error(self, error: str) -> str:
        """分类错误类型"""
        error_lower = error.lower()
        if "syntax" in error_lower:
            return "syntax_error"
        elif "undefined" in error_lower:
            return "undefined_symbol"
        elif "include" in error_lower:
            return "missing_include"
        elif "type" in error_lower:
            return "type_error"
        else:
            return "general_error"

    def _get_timestamp(self) -> str:
        """获取当前时间戳"""
        from datetime import datetime
        return datetime.now().isoformat()

    def get_learning_stats(self) -> Dict[str, Any]:
        """获取学习统计"""
        return {
            "patterns_learned": self.patterns_learned,
            "examples_added": self.examples_added,
            "performance_stats": self.get_performance_stats()
        }
