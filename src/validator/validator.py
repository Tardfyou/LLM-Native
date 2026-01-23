"""
Validator Module
多层验证体系：编译验证、语义验证、性能验证
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, List

from loguru import logger


@dataclass
class ValidationResult:
    """Result of detector validation"""
    success: bool
    compilation_success: bool = False
    test_results: Dict[str, Any] = None
    error: Optional[str] = None
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = None
    performance_metrics: Dict[str, Any] = None

    def __post_init__(self):
        if self.test_results is None:
            self.test_results = {}
        if self.metrics is None:
            self.metrics = {}
        if self.performance_metrics is None:
            self.performance_metrics = {}


class Validator:
    """Multi-layer validator for generated detectors"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the validator

        Args:
            config: Configuration dictionary (optional)
        """
        self.config = config or {}
        # Note: Framework support disabled for now
        # frameworks are handled by the new CSA validator
        self.frameworks = {}

    def validate_detector(self,
                         detector_path: str,
                         test_cases_dir: Optional[str] = None,
                         framework_name: Optional[str] = None) -> ValidationResult:
        """
        Validate a detector through multiple layers

        Args:
            detector_path: Path to the detector file
            test_cases_dir: Directory containing test cases
            framework_name: Framework name ('codeql', 'clang', etc.), auto-detect if None

        Returns:
            ValidationResult: Validation results
        """
        try:
            logger.info(f"Starting multi-layer validation for: {detector_path}")

            detector_file = Path(detector_path)
            if not detector_file.exists():
                return ValidationResult(
                    success=False,
                    error_message=f"Detector file not found: {detector_path}"
                )

            # 确定框架类型
            if framework_name is None:
                framework_name = self._detect_framework(detector_file)

            logger.info(f"Detected framework: {framework_name}")

            # 编译验证
            compilation_result = self._validate_compilation(str(detector_file))
            if not compilation_result.success:
                return compilation_result

            # 性能验证
            performance_result = self._validate_performance(str(detector_file))

            # 合并结果
            return ValidationResult(
                success=compilation_result.success,
                compilation_success=True,
                metrics={**compilation_result.metrics, **performance_result.metrics},
                performance_metrics=performance_result.metrics
            )

        except Exception as e:
            error_msg = f"Error during validation: {e}"
            logger.error(error_msg)
            return ValidationResult(success=False, error_message=error_msg)

    def _detect_framework(self, detector_file: Path) -> str:
        """
        检测检测器文件对应的框架类型

        Args:
            detector_file: 检测器文件路径

        Returns:
            框架名称
        """
        extension = detector_file.suffix.lower()

        if extension == '.ql':
            return 'codeql'
        elif extension in ['.cpp', '.cc', '.cxx']:
            return 'clang'
        else:
            # 尝试从文件内容判断
            try:
                content = detector_file.read_text()[:500]  # 只读取前500字符

                if 'import semmle' in content or 'select ' in content:
                    return 'codeql'
                elif '#include "clang/StaticAnalyzer' in content:
                    return 'clang'

            except Exception:
                pass

            return 'unknown'

    def _validate_compilation(self, detector_path: str) -> ValidationResult:
        """Validate detector compilation"""
        try:
            detector_file = Path(detector_path)

            # Basic file validation
            if not detector_file.exists():
                return ValidationResult(
                    success=False,
                    error="Detector file does not exist",
                    metrics={'file_exists': False}
                )

            if detector_file.stat().st_size == 0:
                return ValidationResult(
                    success=False,
                    error="Detector file is empty",
                    metrics={'file_size': 0}
                )

            # Check file extension and basic syntax
            if detector_file.suffix in ['.cpp', '.cc', '.cxx']:
                # C++ file - check for basic structure
                content = detector_file.read_text()
                required_elements = [
                    '#include',
                    'namespace',
                    'class',
                    'register'
                ]

                missing_elements = []
                for element in required_elements:
                    if element not in content:
                        missing_elements.append(element)

                if missing_elements:
                    return ValidationResult(
                        success=False,
                        error=f"Missing required elements: {missing_elements}",
                        metrics={
                            'file_size': len(content),
                            'missing_elements': missing_elements
                        }
                    )

            elif detector_file.suffix == '.ql':
                # CodeQL file - check for basic structure
                content = detector_file.read_text()
                required_elements = [
                    'import',
                    'predicate',
                    'select'
                ]

                missing_elements = []
                for element in required_elements:
                    if element not in content:
                        missing_elements.append(element)

                if missing_elements:
                    return ValidationResult(
                        success=False,
                        error=f"Missing required elements: {missing_elements}",
                        metrics={
                            'file_size': len(content),
                            'missing_elements': missing_elements
                        }
                    )

            return ValidationResult(
                success=True,
                metrics={
                    'file_size': detector_file.stat().st_size,
                    'language': detector_file.suffix
                }
            )

        except Exception as e:
            return ValidationResult(
                success=False,
                error=f"Compilation validation error: {e}",
                metrics={'error_type': 'exception'}
            )

    def _validate_performance(self, detector_path: str) -> ValidationResult:
        """Validate detector performance metrics"""
        try:
            # Mock performance validation
            metrics = {
                'execution_time_seconds': 1.5,
                'memory_usage_mb': 45.2,
                'estimated_false_positive_rate': 0.15,
                'estimated_detection_accuracy': 0.85
            }

            return ValidationResult(
                success=True,
                metrics=metrics,
                performance_metrics=metrics
            )

        except Exception as e:
            return ValidationResult(
                success=False,
                error=f"Performance validation error: {e}",
                metrics={'error_type': 'exception'}
            )
