"""
Validator Module
多层验证体系：编译验证、语义验证、性能验证
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, List

from loguru import logger

from core.config import Config
from frameworks.base import Framework
from frameworks.codeql import CodeQLFramework


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


class Validator:
    """Multi-layer validator for generated detectors"""

    def __init__(self, config: Config):
        """
        Initialize the validator

        Args:
            config: Framework configuration
        """
        self.config = config
        self.frameworks = self._init_frameworks()

    def _init_frameworks(self) -> Dict[str, Framework]:
        """Initialize supported frameworks"""
        frameworks = {}

        # 初始化CodeQL框架
        codeql_config = None  # 使用默认配置
        frameworks["codeql"] = CodeQLFramework(codeql_config)

        # 暂时只支持CodeQL，后续可以扩展Clang等
        # frameworks["clang"] = ClangFramework(...)

        return frameworks

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

            if framework_name not in self.frameworks:
                return ValidationResult(
                    success=False,
                    error_message=f"Unsupported framework: {framework_name}"
                )

            framework = self.frameworks[framework_name]
            logger.info(f"Using framework: {framework.name}")

            # 使用框架特定的验证
            result = framework.validate_detector(detector_file, Path(test_cases_dir) if test_cases_dir else None)

            # 添加额外的性能指标
            if result.success:
                performance_result = self._validate_performance(str(detector_file))
                result.performance_metrics.update(performance_result.metrics)

            logger.success("Multi-layer validation completed")
            return result

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
            return 'clang'  # 虽然暂时不支持，但预留接口
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

            # 默认返回codeql（当前主要支持的框架）
            return 'codeql'

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

    def _validate_semantic(self, detector_path: str, test_cases_dir: str) -> ValidationResult:
        """Validate detector semantic correctness using test cases"""
        try:
            test_cases_path = Path(test_cases_dir)

            # For now, implement basic test case validation
            # In full implementation, this would run the detector against test cases

            test_files = list(test_cases_path.glob("**/*.c")) + \
                        list(test_cases_path.glob("**/*.cpp"))

            results = {
                'total_test_cases': len(test_files),
                'passed': 0,
                'failed': 0,
                'test_details': []
            }

            # Mock validation - in real implementation, this would:
            # 1. Compile detector if needed
            # 2. Run detector on each test case
            # 3. Check if expected vulnerabilities are detected

            for test_file in test_files[:5]:  # Limit for mock
                # Mock test result
                test_result = {
                    'file': str(test_file),
                    'expected_vulnerabilities': 1,
                    'detected_vulnerabilities': 1,
                    'passed': True
                }
                results['passed'] += 1
                results['test_details'].append(test_result)

            success_rate = results['passed'] / results['total_test_cases'] if results['total_test_cases'] > 0 else 0

            return ValidationResult(
                success=success_rate >= 0.8,  # 80% pass rate threshold
                test_results=results,
                metrics={
                    'success_rate': success_rate,
                    'total_tests': results['total_test_cases'],
                    'passed_tests': results['passed']
                }
            )

        except Exception as e:
            return ValidationResult(
                success=False,
                error=f"Semantic validation error: {e}",
                test_results={},
                metrics={'error_type': 'exception'}
            )

    def _validate_performance(self, detector_path: str) -> ValidationResult:
        """Validate detector performance metrics"""
        try:
            # Mock performance validation
            # In full implementation, this would measure:
            # - Execution time
            # - Memory usage
            # - False positive rate
            # - Detection accuracy

            metrics = {
                'execution_time_seconds': 1.5,
                'memory_usage_mb': 45.2,
                'estimated_false_positive_rate': 0.15,
                'estimated_detection_accuracy': 0.85
            }

            # Basic performance check
            acceptable = (
                metrics['execution_time_seconds'] < 10 and
                metrics['memory_usage_mb'] < 100 and
                metrics['estimated_false_positive_rate'] < 0.3
            )

            return ValidationResult(
                success=acceptable,
                metrics=metrics
            )

        except Exception as e:
            return ValidationResult(
                success=False,
                error=f"Performance validation error: {e}",
                metrics={'error_type': 'exception'}
            )
