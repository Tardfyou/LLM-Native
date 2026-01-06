#!/usr/bin/env python3
"""
LLM-Native Static Analysis Framework - Main Entry Point
面向缺陷检测的大预言模型原生静态分析框架
"""

import sys
from pathlib import Path
from typing import Optional

import fire
from loguru import logger

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.orchestrator import Orchestrator
from knowledge_base.manager import KnowledgeBaseManager
from generator.engine import GeneratorEngine
from validator.validator import Validator
from evaluator.evaluator import Evaluator


class LLMAnalysisFramework:
    """Main LLM-Native Static Analysis Framework Class"""

    def __init__(self, config_file: str = "config/config.yaml"):
        """Initialize the framework with configuration"""
        self.config_file = config_file
        self.config = None
        self.orchestrator = None

    def _initialize_framework(self):
        """Initialize framework components"""
        try:
            # Load configuration
            self.config = Config.load_from_file(self.config_file)
            logger.info(f"Loaded configuration from {self.config_file}")

            # Initialize orchestrator
            self.orchestrator = Orchestrator(self.config)

            logger.info("Framework initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize framework: {e}")
            raise

    def generate_detector(self,
                         vulnerability_desc: str,
                         target_framework: str = "clang",
                         output_dir: Optional[str] = None,
                         verbose: bool = False):
        """
        Generate a static analysis detector from vulnerability description

        Args:
            vulnerability_desc: Natural language description of the vulnerability
            target_framework: Target analysis framework ('clang' or 'codeql')
            output_dir: Output directory for generated detector
            verbose: Enable verbose logging
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        self._initialize_framework()

        try:
            logger.info(f"Generating detector for vulnerability: {vulnerability_desc[:100]}...")

            result = self.orchestrator.generate_detector(
                vulnerability_desc=vulnerability_desc,
                target_framework=target_framework,
                output_dir=output_dir
            )

            if result.success:
                logger.success("Detector generated successfully!")
                logger.info(f"Output directory: {result.output_dir}")
                logger.info(f"Generated files: {result.generated_files}")
            else:
                logger.error(f"Detector generation failed: {result.error}")
                return 1

        except Exception as e:
            logger.error(f"Error during detector generation: {e}")
            return 1

        return 0

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

        self._initialize_framework()

        try:
            logger.info(f"Validating detector: {detector_path}")

            result = self.orchestrator.validate_detector(
                detector_path=detector_path,
                test_cases_dir=test_cases_dir
            )

            if result.success:
                logger.success("Detector validation completed!")
                logger.info(f"Compilation: {'✓' if result.compilation_success else '✗'}")
                logger.info(f"Functional tests: {result.test_results}")
            else:
                logger.error(f"Detector validation failed: {result.error}")
                return 1

        except Exception as e:
            logger.error(f"Error during detector validation: {e}")
            return 1

        return 0

    def evaluate_framework(self,
                          benchmark_name: str = "juliet_suite",
                          output_dir: Optional[str] = None,
                          verbose: bool = False):
        """
        Evaluate framework performance on benchmark datasets

        Args:
            benchmark_name: Name of the benchmark dataset
            output_dir: Output directory for evaluation results
            verbose: Enable verbose logging
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        self._initialize_framework()

        try:
            logger.info(f"Running evaluation on benchmark: {benchmark_name}")

            result = self.orchestrator.evaluate_framework(
                benchmark_name=benchmark_name,
                output_dir=output_dir
            )

            if result.success:
                logger.success("Framework evaluation completed!")
                logger.info("Results:")
                for metric, value in result.metrics.items():
                    logger.info(f"  {metric}: {value}")
            else:
                logger.error(f"Framework evaluation failed: {result.error}")
                return 1

        except Exception as e:
            logger.error(f"Error during framework evaluation: {e}")
            return 1

        return 0

    def knowledge_search(self,
                        query: str,
                        top_k: int = 5,
                        verbose: bool = False):
        """
        Search the knowledge base for relevant API information

        Args:
            query: Search query
            top_k: Number of top results to return
            verbose: Enable verbose logging
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        self._initialize_framework()

        try:
            logger.info(f"Searching knowledge base for: {query}")

            results = self.orchestrator.knowledge_search(
                query=query,
                top_k=top_k
            )

            logger.success("Knowledge search completed!")
            for i, result in enumerate(results, 1):
                logger.info(f"{i}. {result.title}")
                logger.info(f"   Relevance: {result.score:.3f}")
                logger.info(f"   Content: {result.content[:200]}...")
                logger.info("")

        except Exception as e:
            logger.error(f"Error during knowledge search: {e}")
            return 1

        return 0

    def setup_knowledge_base(self,
                           force_rebuild: bool = False,
                           verbose: bool = False):
        """
        Set up and initialize the knowledge base

        Args:
            force_rebuild: Force rebuild of the knowledge base
            verbose: Enable verbose logging
        """
        if verbose:
            logger.info("Enabling verbose logging")
            logger.remove()
            logger.add(sys.stderr, level="DEBUG")

        self._initialize_framework()

        try:
            logger.info("Setting up knowledge base...")

            success = self.orchestrator.setup_knowledge_base(force_rebuild=force_rebuild)

            if success:
                logger.success("Knowledge base setup completed!")
            else:
                logger.error("Knowledge base setup failed")
                return 1

        except Exception as e:
            logger.error(f"Error during knowledge base setup: {e}")
            return 1

        return 0

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
