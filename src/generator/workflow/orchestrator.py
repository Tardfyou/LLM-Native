"""
工作流编排器
Workflow orchestrator for complex generation tasks
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..core.orchestrator import GeneratorOrchestrator
from ..models.generation_models import GenerationInput, GenerationOutput, ValidationResult

logger = logging.getLogger(__name__)

class WorkflowOrchestrator:
    """工作流编排器 - 处理复杂的多步骤生成任务"""

    def __init__(self, generator_orchestrator: Optional[GeneratorOrchestrator] = None):
        self.generator = generator_orchestrator or GeneratorOrchestrator()
        self.workflows = {}
        self.active_workflows = {}

    async def start(self):
        """启动工作流编排器"""
        if self.generator:
            await self.generator.start()
        logger.info("WorkflowOrchestrator started")

    async def stop(self):
        """停止工作流编排器"""
        if self.generator:
            await self.generator.stop()

        # 取消所有活跃的工作流
        for workflow_id, task in self.active_workflows.items():
            if not task.done():
                task.cancel()

        self.active_workflows.clear()
        logger.info("WorkflowOrchestrator stopped")

    async def execute_workflow(self, workflow_name: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """执行预定义工作流"""
        if workflow_name not in self.workflows:
            raise ValueError(f"Workflow '{workflow_name}' not found")

        workflow_func = self.workflows[workflow_name]
        return await workflow_func(self, inputs)

    async def batch_generate(self, inputs: List[GenerationInput],
                           max_concurrent: int = 3) -> List[GenerationOutput]:
        """批量生成多个检测器"""
        logger.info(f"Starting batch generation with {len(inputs)} inputs")

        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async def generate_single(input_data: GenerationInput) -> GenerationOutput:
            async with semaphore:
                try:
                    result = await self.generator.generate_checker(input_data)
                    logger.info(f"Completed generation for {input_data.vulnerability_type}")
                    return result
                except Exception as e:
                    logger.error(f"Generation failed for {input_data.vulnerability_type}: {e}")
                    # 返回失败结果
                    return GenerationOutput(
                        checker_code="",
                        success=False,
                        final_validation=ValidationResult(
                            success=False,
                            errors=[str(e)]
                        )
                    )

        # 并发执行
        tasks = [generate_single(input_data) for input_data in inputs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Task {i} failed with exception: {result}")
                final_results.append(GenerationOutput(
                    checker_code="",
                    success=False,
                    final_validation=ValidationResult(
                        success=False,
                        errors=[str(result)]
                    )
                ))
            else:
                final_results.append(result)

        success_count = sum(1 for r in final_results if r.success)
        logger.info(f"Batch generation completed: {success_count}/{len(final_results)} successful")

        return final_results

    def register_workflow(self, name: str, workflow_func):
        """注册工作流"""
        self.workflows[name] = workflow_func
        logger.info(f"Registered workflow: {name}")

    def list_workflows(self) -> List[str]:
        """列出所有可用工作流"""
        return list(self.workflows.keys())

    async def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """获取工作流状态"""
        if workflow_id not in self.active_workflows:
            return None

        task = self.active_workflows[workflow_id]
        if task.done():
            try:
                return await task
            except Exception as e:
                return {"status": "failed", "error": str(e)}
        else:
            return {"status": "running"}

# 默认工作流定义
async def vulnerability_scan_workflow(orchestrator: 'WorkflowOrchestrator',
                                    inputs: Dict[str, Any]) -> Dict[str, Any]:
    """漏洞扫描工作流 - 为多个漏洞类型生成检测器"""
    vulnerability_types = inputs.get("vulnerability_types", ["buffer_overflow"])
    framework = inputs.get("framework", "clang")

    # 创建多个生成输入
    generation_inputs = [
        GenerationInput(
            patch="",  # 可以从模板生成或从输入获取
            vulnerability_type=vuln_type,
            framework=framework,
            language="cpp"
        )
        for vuln_type in vulnerability_types
    ]

    # 批量生成
    results = await orchestrator.batch_generate(generation_inputs)

    return {
        "workflow_type": "vulnerability_scan",
        "results": results,
        "summary": {
            "total": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success)
        }
    }

async def refinement_workflow(orchestrator: 'WorkflowOrchestrator',
                            inputs: Dict[str, Any]) -> Dict[str, Any]:
    """精炼工作流 - 基于反馈改进生成结果"""
    initial_result = inputs.get("initial_result")
    feedback = inputs.get("feedback", [])

    # 这里可以实现基于反馈的精炼逻辑
    # 例如：重新生成、优化代码、修复问题等

    return {
        "workflow_type": "refinement",
        "original_result": initial_result,
        "feedback": feedback,
        "refined_result": initial_result  # 暂时返回原结果
    }

# 在模块导入时注册默认工作流
def _register_default_workflows(orchestrator: WorkflowOrchestrator):
    """注册默认工作流"""
    orchestrator.register_workflow("vulnerability_scan", vulnerability_scan_workflow)
    orchestrator.register_workflow("refinement", refinement_workflow)

# 在WorkflowOrchestrator初始化时自动注册
original_init = WorkflowOrchestrator.__init__

def new_init(self, *args, **kwargs):
    original_init(self, *args, **kwargs)
    _register_default_workflows(self)

WorkflowOrchestrator.__init__ = new_init
