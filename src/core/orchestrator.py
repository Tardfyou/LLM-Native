"""
Orchestrator Module - Core coordination logic for the LLM-Native Framework
协同编排引擎，管理整个框架的运行流程
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

from loguru import logger

from core.config import Config
from knowledge_base.manager import KnowledgeBaseManager
from generator.engine import GeneratorEngine
from validator.validator import Validator
from evaluator.evaluator import Evaluator


@dataclass
class GenerationResult:
    """Result of detector generation"""
    success: bool
    output_dir: Optional[Path] = None
    generated_files: List[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.generated_files is None:
            self.generated_files = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ValidationResult:
    """Result of detector validation"""
    success: bool
    compilation_success: bool = False
    test_results: Dict[str, Any] = None
    error: Optional[str] = None
    metrics: Dict[str, Any] = None

    def __post_init__(self):
        if self.test_results is None:
            self.test_results = {}
        if self.metrics is None:
            self.metrics = {}


@dataclass
class EvaluationResult:
    """Result of framework evaluation"""
    success: bool
    metrics: Dict[str, Any] = None
    benchmark_results: Dict[str, Any] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.metrics is None:
            self.metrics = {}
        if self.benchmark_results is None:
            self.benchmark_results = {}


@dataclass
class KnowledgeSearchResult:
    """Result of knowledge base search"""
    title: str
    content: str
    score: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class Orchestrator:
    """
    Main orchestrator for the LLM-Native Static Analysis Framework

    Manages the coordination between:
    - Knowledge Base Manager (RAG system)
    - Generator Engine (LLM-powered code generation)
    - Validator (compilation and semantic validation)
    - Evaluator (benchmark testing and metrics)
    """

    def __init__(self, config: Config):
        """
        Initialize the orchestrator

        Args:
            config: Framework configuration
        """
        self.config = config
        self.knowledge_manager = None
        self.generator = None
        self.validator = None
        self.evaluator = None

        self._initialize_components()

    def _initialize_components(self):
        """Initialize all framework components"""
        try:
            logger.info("Initializing orchestrator components...")

            # Initialize Knowledge Base Manager
            self.knowledge_manager = KnowledgeBaseManager(self.config)
            logger.info("Knowledge Base Manager initialized")

            # Initialize Generator Engine
            self.generator = GeneratorEngine(self.config, self.knowledge_manager)
            logger.info("Generator Engine initialized")

            # Initialize Validator
            self.validator = Validator(self.config)
            logger.info("Validator initialized")

            # Initialize Evaluator
            self.evaluator = Evaluator(self.config)
            logger.info("Evaluator initialized")

            logger.success("All orchestrator components initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize orchestrator components: {e}")
            raise

    def generate_detector(self,
                         vulnerability_desc: str,
                         target_framework: str = "clang",
                         output_dir: Optional[str] = None) -> GenerationResult:
        """
        Generate a static analysis detector from vulnerability description

        Args:
            vulnerability_desc: Natural language description of vulnerability
            target_framework: Target framework ('clang' or 'codeql')
            output_dir: Output directory for generated detector

        Returns:
            GenerationResult: Result of the generation process
        """
        try:
            logger.info(f"Starting detector generation for: {vulnerability_desc[:100]}...")

            # Set default output directory
            if output_dir is None:
                timestamp = self._get_timestamp()
                output_dir = self.config.results_dir / f"detector_{timestamp}"
            else:
                output_dir = Path(output_dir)

            output_dir.mkdir(parents=True, exist_ok=True)

            # Generate detector using the generator engine
            result = self.generator.generate_detector(
                vulnerability_desc=vulnerability_desc,
                target_framework=target_framework,
                output_dir=output_dir
            )

            if result.success:
                logger.success("Detector generation completed successfully")
                return GenerationResult(
                    success=True,
                    output_dir=output_dir,
                    generated_files=result.generated_files,
                    metadata=result.metadata
                )
            else:
                logger.error(f"Detector generation failed: {result.error}")
                return GenerationResult(
                    success=False,
                    error=result.error,
                    metadata=result.metadata
                )

        except Exception as e:
            error_msg = f"Error during detector generation: {e}"
            logger.error(error_msg)
            return GenerationResult(success=False, error=error_msg)

    def validate_detector(self,
                         detector_path: str,
                         test_cases_dir: Optional[str] = None) -> ValidationResult:
        """
        Validate a generated detector

        Args:
            detector_path: Path to the detector file
            test_cases_dir: Directory containing test cases

        Returns:
            ValidationResult: Result of the validation process
        """
        try:
            logger.info(f"Starting detector validation for: {detector_path}")

            # Validate detector using the validator
            result = self.validator.validate_detector(
                detector_path=detector_path,
                test_cases_dir=test_cases_dir
            )

            if result.success:
                logger.success("Detector validation completed successfully")
                return ValidationResult(
                    success=True,
                    compilation_success=result.compilation_success,
                    test_results=result.test_results,
                    metrics=result.metrics
                )
            else:
                logger.error(f"Detector validation failed: {result.error}")
                return ValidationResult(
                    success=False,
                    error=result.error,
                    metrics=result.metrics
                )

        except Exception as e:
            error_msg = f"Error during detector validation: {e}"
            logger.error(error_msg)
            return ValidationResult(success=False, error=error_msg)

    def evaluate_framework(self,
                          benchmark_name: str = "juliet_suite",
                          output_dir: Optional[str] = None) -> EvaluationResult:
        """
        Evaluate framework performance on benchmark datasets

        Args:
            benchmark_name: Name of the benchmark dataset
            output_dir: Output directory for evaluation results

        Returns:
            EvaluationResult: Result of the evaluation process
        """
        try:
            logger.info(f"Starting framework evaluation on benchmark: {benchmark_name}")

            # Set default output directory
            if output_dir is None:
                timestamp = self._get_timestamp()
                output_dir = self.config.results_dir / f"evaluation_{timestamp}"
            else:
                output_dir = Path(output_dir)

            output_dir.mkdir(parents=True, exist_ok=True)

            # Evaluate framework using the evaluator
            result = self.evaluator.evaluate_framework(
                benchmark_name=benchmark_name,
                output_dir=output_dir
            )

            if result.success:
                logger.success("Framework evaluation completed successfully")
                return EvaluationResult(
                    success=True,
                    metrics=result.metrics,
                    benchmark_results=result.benchmark_results
                )
            else:
                logger.error(f"Framework evaluation failed: {result.error}")
                return EvaluationResult(
                    success=False,
                    error=result.error,
                    metrics=result.metrics
                )

        except Exception as e:
            error_msg = f"Error during framework evaluation: {e}"
            logger.error(error_msg)
            return EvaluationResult(success=False, error=error_msg)

    def knowledge_search(self, query: str, top_k: int = 5) -> List[KnowledgeSearchResult]:
        """
        Search the knowledge base for relevant information

        Args:
            query: Search query
            top_k: Number of top results to return

        Returns:
            List of knowledge search results
        """
        try:
            logger.info(f"Searching knowledge base for: {query}")

            results = self.knowledge_manager.search(query, top_k=top_k)

            search_results = []
            for result in results:
                search_results.append(KnowledgeSearchResult(
                    title=result.get('title', ''),
                    content=result.get('content', ''),
                    score=result.get('score', 0.0),
                    metadata=result.get('metadata', {})
                ))

            logger.success(f"Knowledge search completed, found {len(search_results)} results")
            return search_results

        except Exception as e:
            logger.error(f"Error during knowledge search: {e}")
            return []

    def setup_knowledge_base(self, force_rebuild: bool = False) -> bool:
        """
        Set up and initialize the knowledge base

        Args:
            force_rebuild: Force rebuild of the knowledge base

        Returns:
            True if setup successful, False otherwise
        """
        try:
            logger.info("Setting up knowledge base...")

            success = self.knowledge_manager.setup(force_rebuild=force_rebuild)

            if success:
                logger.success("Knowledge base setup completed successfully")
            else:
                logger.error("Knowledge base setup failed")

            return success

        except Exception as e:
            logger.error(f"Error during knowledge base setup: {e}")
            return False

    def _get_timestamp(self) -> str:
        """Get current timestamp for file naming"""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    # Additional orchestration methods can be added here for more complex workflows
    def generate_and_validate_detector(self,
                                     vulnerability_desc: str,
                                     target_framework: str = "clang",
                                     output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate and validate a detector in one workflow

        Args:
            vulnerability_desc: Vulnerability description
            target_framework: Target framework
            output_dir: Output directory

        Returns:
            Combined results of generation and validation
        """
        # Generate detector
        gen_result = self.generate_detector(
            vulnerability_desc=vulnerability_desc,
            target_framework=target_framework,
            output_dir=output_dir
        )

        if not gen_result.success:
            return {
                'success': False,
                'generation': gen_result.__dict__,
                'validation': None
            }

        # Validate detector (assuming the main detector file is generated)
        detector_path = gen_result.output_dir / "detector.cpp"  # Adjust based on actual file naming
        if not detector_path.exists():
            # Try to find the detector file
            cpp_files = list(gen_result.output_dir.glob("*.cpp"))
            if cpp_files:
                detector_path = cpp_files[0]

        if detector_path.exists():
            val_result = self.validate_detector(str(detector_path))
        else:
            val_result = ValidationResult(
                success=False,
                error="Detector file not found for validation"
            )

        return {
            'success': gen_result.success and val_result.success,
            'generation': gen_result.__dict__,
            'validation': val_result.__dict__
        }
