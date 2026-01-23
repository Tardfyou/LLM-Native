#!/usr/bin/env python3
"""
LLM-Native Static Analysis Framework - Main Entry Point
面向缺陷检测的大预言模型原生静态分析框架

增强版 - 集成了KNighter的优秀功能:
- 增强的LLM客户端（6次重试，推理模型支持）
- 高级精炼系统
- 报告Triage系统
- 简化版知识库
- 改进的Prompt模板管理器
"""

import asyncio
import sys
import yaml
from pathlib import Path
from typing import Optional
from datetime import datetime

import fire
from loguru import logger

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from generator.core.orchestrator import GeneratorOrchestrator
from generator.models.generation_models import GenerationInput
from generator.models.checker_data import CheckerData
from generator.models.refinement_models import GenerationProgress, ReportData, RefinementResult
from generator.refinement.advanced_refinement import AdvancedRefinement
from generator.refinement.report_triage import ReportTriage
from knowledge_base.manager import KnowledgeBaseManager
from knowledge_base.vector_db import VectorDatabase
from model import LLMClientWrapper  # 新的简化接口，支持多模型
from validator.validator import Validator
from generator.utils.code_utils import extract_checker_code


def load_config(config_file: str = "config/config.yaml") -> dict:
    """加载配置文件"""
    config_path = Path(config_file)
    if not config_path.exists():
        logger.warning(f"Config file not found: {config_file}, using defaults")
        return {}

    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


class LLMAnalysisFramework:
    """Main LLM-Native Static Analysis Framework Class - 增强版"""

    def __init__(self, config_file: str = "config/config.yaml"):
        """Initialize the framework with configuration"""
        self.config_file = config_file
        self.config = None
        self.orchestrator = None
        self.llm_client = None
        self.knowledge_base = None  # 向量数据库知识库
        self.refinement_system = None

    def _initialize_framework(self):
        """Initialize framework components"""
        try:
            # Load configuration
            self.config = load_config(self.config_file)
            logger.info(f"Loaded configuration from {self.config_file}")

            # 初始化新的简化LLM客户端 (支持多模型: GLM-4.7, DeepSeek, OpenAI等)
            self.llm_client = LLMClientWrapper(self.config)
            logger.info(f"LLM client initialized: {self.llm_client.config.model_name}")

            # 初始化向量数据库知识库（保持原有特色）
            # 修复：传递config以使用正确的collection和persist_directory
            self.knowledge_base = KnowledgeBaseManager(self.config)
            logger.info("Vector DB knowledge base initialized")

            # 初始化精炼系统
            self.refinement_system = AdvancedRefinement(llm_client=self.llm_client)
            logger.info("Advanced refinement system initialized")

            # Initialize orchestrator (传递LLM客户端)
            self.config["llm_client"] = self.llm_client
            self.orchestrator = GeneratorOrchestrator(self.config)

            logger.info("Framework initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize framework: {e}")
            raise

    def generate_detector(self,
                         vulnerability_desc: Optional[str] = None,
                         patch_file: Optional[str] = None,
                         target_framework: str = "clang",
                         output_dir: Optional[str] = None,
                         seed: Optional[int] = None,
                         verbose: bool = False):
        """
        Generate a static analysis detector from vulnerability description or patch file

        Args:
            vulnerability_desc: Natural language description of the vulnerability
            patch_file: Path to patch file (.diff or .patch format)
            target_framework: Target analysis framework ('clang' or 'codeql')
            output_dir: Output directory for generated detector
            seed: Random seed for reproducible results (None for random)
            verbose: Enable verbose logging
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        # 设置随机种子（如果提供）
        if seed is not None:
            import random
            random.seed(seed)
            logger.info(f"Using random seed: {seed}")

        # 验证至少提供了一种输入
        if not vulnerability_desc and not patch_file:
            logger.error("必须提供 vulnerability_desc 或 patch_file 参数")
            return 1

        self._initialize_framework()

        try:
            # 读取补丁文件（如果提供）
            patch_content = None
            if patch_file:
                patch_path = Path(patch_file)
                if not patch_path.exists():
                    logger.error(f"Patch file not found: {patch_file}")
                    return 1
                patch_content = patch_path.read_text()
                logger.info(f"Loaded patch file: {patch_file} ({len(patch_content)} bytes)")

            if vulnerability_desc:
                logger.info(f"Generating detector for vulnerability: {vulnerability_desc[:100]}...")
            else:
                logger.info(f"Generating detector from patch file: {patch_file}")

            # 创建生成输入
            input_data = GenerationInput(
                patch=patch_content,
                vulnerability_description=vulnerability_desc,
                vulnerability_type="",  # 将从描述中推断
                framework=target_framework,
                language="cpp"
            )

            # 异步运行生成
            result = asyncio.run(self.orchestrator.generate_checker(input_data))

            # 确定输出目录
            # 使用脚本所在目录的绝对路径作为基准，确保在容器中也能正确映射到宿主机
            project_root = Path(__file__).parent.parent  # LLM-Native目录

            # 生成时间戳，用于创建唯一目录
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            if output_dir is None:
                # 默认：在 results 下创建带时间戳的子目录
                output_path = project_root / "results" / f"run_{timestamp}"
            else:
                # 用户指定了目录：在该目录下创建带时间戳的子目录
                output_path_user = Path(output_dir)
                if not output_path_user.is_absolute():
                    output_path_user = project_root / output_dir
                # 在用户指定的目录下创建唯一的运行目录
                output_path = output_path_user / f"run_{timestamp}"

            output_path.mkdir(parents=True, exist_ok=True)

            # 保存生成的文件
            checker_file = output_path / "checker.cpp"
            checker_file.write_text(result.checker_code, encoding='utf-8')

            # 保存模式
            pattern_file = output_path / "pattern.md"
            pattern_file.write_text(f"# Vulnerability Pattern\n\n{result.pattern}", encoding='utf-8')

            # 保存计划
            plan_file = output_path / "plan.md"
            plan_content = f"""# Detection Plan

## Vulnerability Pattern
{result.plan.vulnerability_pattern}

## Detection Strategy
{result.plan.detection_strategy}

## Generation Details
- Confidence Score: {result.confidence_score:.2f}
- Iterations Used: {result.iterations_used}
- Generation Time: {result.generation_time:.2f}s
- Validation Success: {result.success}
"""
            plan_file.write_text(plan_content, encoding='utf-8')

            if result.success:
                logger.success("Detector generated successfully!")
            else:
                logger.warning("Detector generated with validation issues")

            logger.info(f"Output directory: {output_path.absolute()}")
            logger.info(f"Generated files:")
            logger.info(f"  - {checker_file.name}: {len(result.checker_code)} bytes")
            logger.info(f"  - {pattern_file.name}: Vulnerability pattern")
            logger.info(f"  - {plan_file.name}: Implementation plan")

            return 0

        except Exception as e:
            logger.error(f"Error during detector generation: {e}")
            import traceback
            traceback.print_exc()
            return 1

    def validate_detector(self,
                         detector_path: str,
                         test_cases_dir: Optional[str] = None,
                         verbose: bool = False):
        """
        Validate a generated detector

        Args:
            detector_path: Path to the detector file
            test_cases_dir: Directory containing test cases
            verbose: Enable verbose logging
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        try:
            logger.info(f"Validating detector: {detector_path}")

            validator = Validator()
            result = validator.validate_detector(
                detector_path=detector_path,
                test_cases_dir=test_cases_dir
            )

            if result.success:
                logger.success("Detector validation completed!")
                logger.info(f"Compilation: {'✓' if result.compilation_success else '✗'}")
                logger.info(f"Metrics: {result.metrics}")
                return 0
            else:
                logger.error(f"Detector validation failed: {result.error_message}")
                return 1

        except Exception as e:
            logger.error(f"Error during detector validation: {e}")
            import traceback
            traceback.print_exc()
            return 1

    # 知识库搜索功能 - 使用向量数据库（原有特色）
    def knowledge_search(self,
                        query: str,
                        top_k: int = 5,
                        verbose: bool = False):
        """
        使用向量数据库搜索知识库

        Args:
            query: 搜索查询
            top_k: 返回结果数量
            verbose: 启用详细日志
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        try:
            self._initialize_framework()

            logger.info(f"Searching vector database for: {query}")

            # 使用向量数据库管理器搜索
            results = self.knowledge_base.search(
                query=query,
                top_k=top_k
            )

            if not results:
                logger.warning("No results found")
                return 1

            # 显示结果
            logger.info(f"Found {len(results)} relevant results:")
            for i, result in enumerate(results, 1):
                logger.info(f"\n{i}. Score: {result.get('score', 0):.3f}")
                logger.info(f"   Content: {result.get('content', '')[:200]}...")

            return 0

        except Exception as e:
            logger.error(f"Error during knowledge search: {e}")
            import traceback
            traceback.print_exc()
            return 1

    # 新增：报告分类功能
    def triage_report(self,
                     report_content: str,
                     pattern: str,
                     verbose: bool = False):
        """
        对报告进行分类（TP/FP）

        Args:
            report_content: 报告内容
            pattern: 漏洞模式
            verbose: 启用详细日志
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        try:
            self._initialize_framework()

            logger.info("Triaging report...")

            # 创建报告数据
            from generator.models.refinement_models import ReportData
            report = ReportData(
                report_id="manual_report",
                report_content=report_content,
                report_objects=[]
            )

            # 执行分类
            triage = ReportTriage(self.llm_client)
            result = triage.triage_report(report, pattern)

            # 显示结果
            logger.info(f"Classification: {'False Positive' if result.is_fp else 'True Positive'}")
            logger.info(f"Confidence: {result.confidence:.2f}")
            logger.info(f"Reasoning: {result.reasoning}")

            return 0

        except Exception as e:
            logger.error(f"Error during report triage: {e}")
            import traceback
            traceback.print_exc()
            return 1

    # 新增：检测器精炼功能
    def refine_detector(self,
                      checker_path: str,
                      pattern: str,
                      fp_reports_file: Optional[str] = None,
                      verbose: bool = False):
        """
        精炼检测器以减少误报

        Args:
            checker_path: 检测器文件路径
            pattern: 漏洞模式
            fp_reports_file: FP报告文件（JSON格式）
            verbose: 启用详细日志
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        try:
            self._initialize_framework()

            logger.info(f"Refining detector: {checker_path}")

            # 读取检测器代码
            checker_path_obj = Path(checker_path)
            if not checker_path_obj.exists():
                logger.error(f"Checker file not found: {checker_path}")
                return 1

            checker_code = checker_path_obj.read_text()

            # 加载FP报告
            fp_reports = []
            if fp_reports_file:
                import json
                with open(fp_reports_file) as f:
                    data = json.load(f)
                    fp_reports = [ReportData(**r) for r in data]
            else:
                logger.info("No FP reports provided, refinement will use pattern-based analysis only")

            # 创建进度跟踪
            progress = GenerationProgress(
                step_names=["🔧 Analyzing Checker", "🔍 Processing FP Reports", "✨ Refining", "✅ Validation"]
            )

            # 执行精炼
            result = self.refinement_system.refine_with_feedback(
                checker_code=checker_code,
                pattern=pattern,
                fp_reports=fp_reports,
                output_dir=checker_path_obj.parent,
                progress=progress
            )

            # 显示结果
            logger.info(f"\n{'='*60}")
            logger.info(f"Refinement Result: {result.result}")
            logger.info(f"{'='*60}")
            logger.info(f"Refined: {result.refined}")
            logger.info(f"TP: {result.num_TP}, FP: {result.num_FP}")
            logger.info(f"Total Reports: {result.num_reports}")
            logger.info(f"Precision: {result.precision:.2%}")

            if result.refined:
                # 保存精炼后的代码
                refined_file = checker_path_obj.parent / "checker_refined.cpp"
                refined_file.write_text(result.checker_code)
                logger.info(f"Refined code saved to: {refined_file}")

            return 0

        except Exception as e:
            logger.error(f"Error during detector refinement: {e}")
            import traceback
            traceback.print_exc()
            return 1

    def api_server(self,
                   host: str = "0.0.0.0",
                   port: int = 8000,
                   debug: bool = False):
        """
        Start the API server

        Args:
            host: Server host
            port: Server port
            debug: Enable debug mode
        """
        try:
            from api import app
            import uvicorn

            logger.info(f"Starting API server on {host}:{port}")
            uvicorn.run(app, host=host, port=port, debug=debug)

        except Exception as e:
            logger.error(f"Error starting API server: {e}")
            return 1

        return 0


def main():
    """Main entry point"""
    try:
        fire.Fire(LLMAnalysisFramework)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
