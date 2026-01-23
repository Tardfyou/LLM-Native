"""
LLM-Native 检查器生成引擎

整合所有组件，实现完整的检查器生成流程。

功能特性：
1. 支持自然语言漏洞描述和代码补丁两种输入模式
2. 五阶段生成流程：模式提取 → 计划生成 → 代码生成 → 语法修复 → 验证
3. 基于RAG的知识库检索增强
4. 多轮自愈修复机制
5. 完整的错误处理和日志记录
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from loguru import logger

from .models.checker_data import CheckerData, GenerationBatch, CheckerStatus, ValidationResult
from .prompts.prompt_manager import EnhancedPromptManager, PromptContext
from .core.repair_engine import RepairEngine, RepairConfig
from .utils.logger_config import setup_logger, GenerationLogger
from .utils.tools import extract_checker_code, compile_checker


class CheckerGenerationEngine:
    """
    检查器生成引擎

    核心类，协调所有组件完成检查器的自动生成。
    """

    def __init__(
        self,
        prompt_manager: EnhancedPromptManager,
        llm_client,
        repair_engine: RepairEngine,
        config: Dict[str, Any]
    ):
        self.prompt_manager = prompt_manager
        self.llm_client = llm_client
        self.repair_engine = repair_engine
        self.config = config

        # 获取配置
        self.llvm_dir = Path(config.get("llvm_dir", "/usr/lib/llvm-18"))
        self.output_dir = Path(config.get("output_dir", "./results"))
        self.max_iterations = config.get("max_iterations", 3)

        # 设置日志
        setup_logger(
            log_dir=self.output_dir / "logs",
            log_level="DEBUG",
            enable_json=True
        )

        logger.info("CheckerGenerationEngine initialized")
        logger.info(f"LLVM directory: {self.llvm_dir}")
        logger.info(f"Output directory: {self.output_dir}")

    async def generate_from_description(
        self,
        vulnerability_desc: str,
        batch_id: Optional[str] = None,
        num_checkers: int = 1
    ) -> GenerationBatch:
        """
        从自然语言漏洞描述生成检查器

        Args:
            vulnerability_desc: 漏洞描述（自然语言）
            batch_id: 批次ID
            num_checkers: 要生成的检查器数量

        Returns:
            生成批次结果
        """
        if batch_id is None:
            batch_id = f"nl_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        batch = GenerationBatch(batch_id, self.output_dir)

        logger.info(f"=" * 60)
        logger.info(f"Starting generation batch: {batch_id}")
        logger.info(f"Input type: Natural Language Description")
        logger.info(f"Description: {vulnerability_desc[:200]}...")
        logger.info(f"Number of checkers to generate: {num_checkers}")
        logger.info(f"=" * 60)

        for i in range(num_checkers):
            checker_id = f"{batch_id}_checker_{i:03d}"
            logger.info(f"\n--- Generating checker {i+1}/{num_checkers}: {checker_id} ---")

            checker_data = CheckerData(
                checker_id=checker_id,
                base_result_dir=self.output_dir,
                vulnerability_desc=vulnerability_desc,
                input_type="natural_language"
            )

            success = await self._generate_single_checker(checker_data)

            batch.add_checker(checker_data)

            if success and checker_data.is_valid:
                logger.success(f"✓ Got valid checker: {checker_id}")
                break
            elif success:
                logger.warning(f"✗ Checker generated but not valid: {checker_id}")

        batch.complete()
        return batch

    async def generate_from_patch(
        self,
        patch: str,
        commit_id: str,
        commit_type: str,
        batch_id: Optional[str] = None
    ) -> Optional[CheckerData]:
        """
        从代码补丁生成检查器

        Args:
            patch: git diff格式的补丁
            commit_id: 提交ID
            commit_type: 提交类型
            batch_id: 批次ID

        Returns:
            检查器数据，如果失败返回None
        """
        if batch_id is None:
            batch_id = f"patch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        checker_id = f"{batch_id}_{commit_type}_{commit_id[:8]}"

        logger.info(f"=" * 60)
        logger.info(f"Generating checker from patch: {checker_id}")
        logger.info(f"Commit ID: {commit_id}")
        logger.info(f"Commit Type: {commit_type}")
        logger.info(f"=" * 60)

        checker_data = CheckerData(
            checker_id=checker_id,
            base_result_dir=self.output_dir,
            vulnerability_desc=patch,
            patch=patch,
            input_type="patch"
        )

        success = await self._generate_single_checker(checker_data)

        if success:
            logger.success(f"✓ Successfully generated: {checker_id}")
        else:
            logger.error(f"✗ Failed to generate: {checker_id}")

        return checker_data if success else None

    async def _generate_single_checker(self, checker_data: CheckerData) -> bool:
        """
        生成单个检查器的完整流程

        五阶段流程：
        1. 模式提取
        2. 计划生成
        3. 代码生成
        4. 语法修复
        5. 验证（可选）

        Args:
            checker_data: 检查器数据

        Returns:
            是否成功生成
        """
        gen_logger = GenerationLogger(checker_data.output_dir, checker_data.checker_id)

        try:
            # 阶段1: 模式提取
            gen_logger.log_stage("PATTERN_EXTRACTION", "Starting pattern extraction")
            pattern = await self._extract_pattern(checker_data, gen_logger)

            if not pattern:
                gen_logger.log_error("PATTERN_EXTRACTION", ValueError("Failed to extract pattern"))
                return False

            checker_data.pattern = pattern
            checker_data.update_status(CheckerStatus.PATTERN_EXTRACTED)
            gen_logger.log_pattern_extraction(pattern)
            logger.info(f"[{checker_data.checker_id}] Pattern extracted ({len(pattern)} chars)")

            # 阶段2: 计划生成
            gen_logger.log_stage("PLAN_GENERATION", "Starting plan generation")
            plan = await self._generate_plan(checker_data, gen_logger)

            if not plan:
                gen_logger.log_error("PLAN_GENERATION", ValueError("Failed to generate plan"))
                return False

            checker_data.plan = plan
            checker_data.update_status(CheckerStatus.PLAN_GENERATED)
            gen_logger.log_plan_generation(plan)
            logger.info(f"[{checker_data.checker_id}] Plan generated ({len(plan)} chars)")

            # 阶段3: 代码生成
            gen_logger.log_stage("CODE_GENERATION", "Starting code generation")
            code = await self._generate_code(checker_data, gen_logger)

            if not code:
                gen_logger.log_error("CODE_GENERATION", ValueError("Failed to generate code"))
                return False

            checker_data.initial_checker_code = code
            checker_data.update_status(CheckerStatus.CODE_GENERATED)
            gen_logger.log_code_generation(code, True)
            logger.info(f"[{checker_data.checker_id}] Code generated ({len(code)} chars)")

            # 阶段4: 语法修复
            gen_logger.log_stage("REPAIR", "Starting automatic repair")
            success, checker_data = await self.repair_engine.repair_checker(
                checker_data, self.llvm_dir
            )

            if not success:
                gen_logger.log_error("REPAIR", RuntimeError("Failed to repair checker"))
                logger.error(f"[{checker_data.checker_id}] Repair failed")
                return False

            logger.info(f"[{checker_data.checker_id}] Repair successful")

            # 阶段5: 保存结果
            checker_data.save_all()

            gen_logger.log_stage("COMPLETE", "Generation completed successfully")
            logger.success(f"[{checker_data.checker_id}] Generation completed successfully")

            return True

        except Exception as e:
            gen_logger.log_error("GENERATION", e)
            logger.error(f"[{checker_data.checker_id}] Error: {e}")
            return False

        finally:
            gen_logger.close()

    async def _extract_pattern(
        self,
        checker_data: CheckerData,
        gen_logger: GenerationLogger
    ) -> Optional[str]:
        """阶段1: 提取漏洞模式"""
        context = PromptContext(
            input_type=checker_data.input_type,
            target_framework="clang",
            clang_version="18",
            enable_rag=self.config.get("enable_rag", True)
        )

        prompt = self.prompt_manager.build_pattern_extraction_prompt(
            vulnerability_desc=checker_data.vulnerability_desc,
            context=context,
            patch=checker_data.patch,
            num_examples=3
        )

        response = await self._call_llm_with_retry(prompt)

        # 保存提示词历史
        self.prompt_manager.save_prompt_history(
            "pattern_extraction",
            prompt,
            response,
            checker_data.output_dir,
            {"stage": "pattern_extraction"}
        )

        # 提取模式
        import re
        pattern_match = re.search(r"```markdown\n(.*?)\n```", response, re.DOTALL)
        if pattern_match:
            return pattern_match.group(1).strip()

        return response.strip()

    async def _generate_plan(
        self,
        checker_data: CheckerData,
        gen_logger: GenerationLogger
    ) -> Optional[str]:
        """阶段2: 生成实现计划"""
        context = PromptContext(
            input_type=checker_data.input_type,
            target_framework="clang",
            clang_version="18",
            enable_rag=True
        )

        prompt = self.prompt_manager.build_plan_generation_prompt(
            bug_pattern=checker_data.pattern,
            context=context,
            original_desc=checker_data.vulnerability_desc,
            patch=checker_data.patch,
            num_examples=2
        )

        response = await self._call_llm_with_retry(prompt)

        # 保存提示词历史
        self.prompt_manager.save_prompt_history(
            "plan_generation",
            prompt,
            response,
            checker_data.output_dir,
            {"stage": "plan_generation"}
        )

        # 提取计划
        import re
        plan_match = re.search(r"```markdown\n(.*?)\n```", response, re.DOTALL)
        if plan_match:
            return plan_match.group(1).strip()

        return response.strip()

    async def _generate_code(
        self,
        checker_data: CheckerData,
        gen_logger: GenerationLogger
    ) -> Optional[str]:
        """阶段3: 生成检查器代码"""
        context = PromptContext(
            input_type=checker_data.input_type,
            target_framework="clang",
            clang_version="18",
            enable_rag=True
        )

        prompt = self.prompt_manager.build_code_generation_prompt(
            bug_pattern=checker_data.pattern,
            implementation_plan=checker_data.plan,
            context=context,
            original_desc=checker_data.vulnerability_desc,
            patch=checker_data.patch,
            num_examples=1
        )

        response = await self._call_llm_with_retry(prompt)

        # 保存提示词历史
        self.prompt_manager.save_prompt_history(
            "code_generation",
            prompt,
            response,
            checker_data.output_dir,
            {"stage": "code_generation"}
        )

        # 提取代码
        code = extract_checker_code(response)

        if not code:
            logger.error("Failed to extract checker code from LLM response")
            return None

        return code

    async def _call_llm_with_retry(
        self,
        prompt: str,
        max_retries: int = 3
    ) -> str:
        """调用LLM并支持重试"""
        for attempt in range(1, max_retries + 1):
            try:
                response = await self.llm_client.generate(prompt)
                return response
            except Exception as e:
                logger.warning(f"LLM call attempt {attempt} failed: {e}")
                if attempt < max_retries:
                    await asyncio.sleep(2 ** attempt)  # 指数退避
                else:
                    raise


def create_generation_engine(config: Dict[str, Any]) -> CheckerGenerationEngine:
    """
    创建生成引擎的工厂函数

    Args:
        config: 配置字典 (应包含 llm 配置节)

    Returns:
        配置好的生成引擎
    """
    # 初始化提示词管理器
    prompt_manager = EnhancedPromptManager(
        template_dir=Path(config.get("template_dir", "./data/prompt_templates")),
        example_dir=Path(config.get("example_dir", "./data/examples"))
    )

    # 初始化LLM客户端 - 使用新的简化接口
    from model import LLMClientWrapper

    llm_client = LLMClientWrapper(config)

    # 初始化修复引擎
    repair_engine = RepairEngine(
        prompt_manager=prompt_manager,
        llm_client=llm_client,
        config=RepairConfig(
            max_syntax_attempts=config.get("max_syntax_attempts", 4),
            max_semantic_attempts=config.get("max_semantic_attempts", 3)
        )
    )

    return CheckerGenerationEngine(
        prompt_manager=prompt_manager,
        llm_client=llm_client,
        repair_engine=repair_engine,
        config=config
    )