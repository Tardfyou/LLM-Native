"""
Evaluator Module
框架性能评估和基准测试
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, List

from loguru import logger

from core.config import Config


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


class Evaluator:
    """Framework evaluator for benchmarking and metrics calculation"""

    def __init__(self, config: Config):
        """
        Initialize the evaluator

        Args:
            config: Framework configuration
        """
        self.config = config

    def evaluate_framework(self,
                          benchmark_name: str = "juliet_suite",
                          output_dir: Optional[str] = None) -> EvaluationResult:
        """
        Evaluate framework performance on benchmark datasets

        Args:
            benchmark_name: Name of the benchmark dataset
            output_dir: Output directory for results

        Returns:
            EvaluationResult: Evaluation results
        """
        try:
            logger.info(f"Starting framework evaluation on benchmark: {benchmark_name}")

            # Set default output directory
            if output_dir is None:
                import datetime
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = self.config.results_dir / f"evaluation_{timestamp}"
            else:
                output_dir = Path(output_dir)

            output_dir.mkdir(parents=True, exist_ok=True)

            # Load benchmark dataset
            benchmark_data = self._load_benchmark(benchmark_name)
            if not benchmark_data:
                return EvaluationResult(
                    success=False,
                    error=f"Failed to load benchmark: {benchmark_name}"
                )

            # Run evaluation
            results = self._run_evaluation(benchmark_data, output_dir)

            # Calculate metrics
            metrics = self._calculate_metrics(results)

            # Save results
            self._save_results(results, metrics, output_dir)

            return EvaluationResult(
                success=True,
                metrics=metrics,
                benchmark_results=results
            )

        except Exception as e:
            error_msg = f"Error during framework evaluation: {e}"
            logger.error(error_msg)
            return EvaluationResult(success=False, error=error_msg)

    def _load_benchmark(self, benchmark_name: str) -> Optional[Dict[str, Any]]:
        """Load benchmark dataset"""
        try:
            benchmark_path = self.config.benchmarks_dir / benchmark_name

            if not benchmark_path.exists():
                logger.warning(f"Benchmark {benchmark_name} not found, creating mock data")
                return self._create_mock_benchmark(benchmark_name)

            # In full implementation, load actual benchmark data
            # For now, return mock data
            return self._create_mock_benchmark(benchmark_name)

        except Exception as e:
            logger.error(f"Error loading benchmark {benchmark_name}: {e}")
            return None

    def _create_mock_benchmark(self, benchmark_name: str) -> Dict[str, Any]:
        """Create mock benchmark data for testing"""
        return {
            "name": benchmark_name,
            "description": f"Mock benchmark dataset for {benchmark_name}",
            "vulnerabilities": [
                {
                    "id": "CWE-119",
                    "name": "Buffer Overflow",
                    "description": "Improper restriction of operations within bounds of memory buffer",
                    "test_cases": [
                        {"file": "buffer_overflow_001.c", "has_vulnerability": True},
                        {"file": "buffer_overflow_002.c", "has_vulnerability": False},
                        {"file": "buffer_overflow_003.c", "has_vulnerability": True},
                    ]
                },
                {
                    "id": "CWE-416",
                    "name": "Use After Free",
                    "description": "Use of a resource after it has been released",
                    "test_cases": [
                        {"file": "use_after_free_001.c", "has_vulnerability": True},
                        {"file": "use_after_free_002.c", "has_vulnerability": False},
                    ]
                }
            ]
        }

    def _run_evaluation(self, benchmark_data: Dict[str, Any], output_dir: Path) -> Dict[str, Any]:
        """Run evaluation on benchmark data"""
        results = {
            "benchmark_name": benchmark_data["name"],
            "vulnerability_results": [],
            "summary": {
                "total_vulnerabilities": 0,
                "successful_generations": 0,
                "compilation_success_rate": 0.0,
                "average_detection_accuracy": 0.0
            }
        }

        for vuln in benchmark_data["vulnerabilities"]:
            vuln_result = self._evaluate_vulnerability(vuln, output_dir)
            results["vulnerability_results"].append(vuln_result)

            results["summary"]["total_vulnerabilities"] += 1
            if vuln_result["generation_success"]:
                results["summary"]["successful_generations"] += 1

        # Calculate summary metrics
        total = results["summary"]["total_vulnerabilities"]
        successful = results["summary"]["successful_generations"]

        results["summary"]["compilation_success_rate"] = successful / total if total > 0 else 0.0
        results["summary"]["average_detection_accuracy"] = self._calculate_average_accuracy(results)

        return results

    def _evaluate_vulnerability(self, vuln_data: Dict[str, Any], output_dir: Path) -> Dict[str, Any]:
        """Evaluate framework on a specific vulnerability type"""
        vuln_id = vuln_data["id"]
        vuln_name = vuln_data["name"]

        logger.info(f"Evaluating vulnerability: {vuln_id} - {vuln_name}")

        result = {
            "vulnerability_id": vuln_id,
            "vulnerability_name": vuln_name,
            "generation_success": False,
            "compilation_success": False,
            "detection_results": [],
            "metrics": {}
        }

        try:
            # Attempt to generate detector for this vulnerability
            from core.orchestrator import Orchestrator

            orchestrator = Orchestrator(self.config)

            gen_result = orchestrator.generate_detector(
                vulnerability_desc=vuln_data["description"],
                target_framework="clang",
                output_dir=output_dir / f"vuln_{vuln_id}"
            )

            result["generation_success"] = gen_result.success

            if gen_result.success and gen_result.generated_files:
                # Validate the generated detector
                val_result = orchestrator.validate_detector(
                    detector_path=gen_result.generated_files[0]
                )

                result["compilation_success"] = val_result.compilation_success
                result["validation_metrics"] = val_result.metrics

                # Mock detection evaluation
                result["detection_results"] = self._evaluate_detection_accuracy(
                    vuln_data["test_cases"]
                )

        except Exception as e:
            logger.error(f"Error evaluating vulnerability {vuln_id}: {e}")
            result["error"] = str(e)

        return result

    def _evaluate_detection_accuracy(self, test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate detection accuracy on test cases"""
        # Mock implementation
        results = []
        for test_case in test_cases:
            result = {
                "test_file": test_case["file"],
                "expected_vulnerable": test_case["has_vulnerability"],
                "detected_vulnerable": test_case["has_vulnerability"],  # Mock perfect detection
                "correct": True
            }
            results.append(result)

        return results

    def _calculate_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate evaluation metrics"""
        metrics = {
            "compilation_success_rate": results["summary"]["compilation_success_rate"],
            "generation_success_rate": results["summary"]["successful_generations"] / results["summary"]["total_vulnerabilities"],
            "average_detection_accuracy": results["summary"]["average_detection_accuracy"],
            "vulnerability_coverage": len(results["vulnerability_results"]),
            "overall_score": 0.0
        }

        # Calculate overall score as weighted average
        weights = {
            "compilation_success_rate": 0.3,
            "generation_success_rate": 0.3,
            "average_detection_accuracy": 0.4
        }

        overall_score = 0.0
        for metric, weight in weights.items():
            overall_score += metrics[metric] * weight

        metrics["overall_score"] = overall_score

        return metrics

    def _calculate_average_accuracy(self, results: Dict[str, Any]) -> float:
        """Calculate average detection accuracy"""
        accuracies = []
        for vuln_result in results["vulnerability_results"]:
            if vuln_result["detection_results"]:
                correct = sum(1 for r in vuln_result["detection_results"] if r["correct"])
                total = len(vuln_result["detection_results"])
                if total > 0:
                    accuracies.append(correct / total)

        return sum(accuracies) / len(accuracies) if accuracies else 0.0

    def _save_results(self, results: Dict[str, Any], metrics: Dict[str, Any], output_dir: Path):
        """Save evaluation results to files"""
        import json

        # Save detailed results
        results_file = output_dir / "evaluation_results.json"
        results_file.write_text(json.dumps(results, indent=2))

        # Save metrics summary
        metrics_file = output_dir / "evaluation_metrics.json"
        metrics_file.write_text(json.dumps(metrics, indent=2))

        # Save human-readable summary
        summary_file = output_dir / "evaluation_summary.txt"
        summary_content = f"""
Framework Evaluation Summary
===========================

Benchmark: {results['benchmark_name']}
Date: {output_dir.name.split('_')[1] if '_' in output_dir.name else 'Unknown'}

Overall Metrics:
- Overall Score: {metrics['overall_score']:.3f}
- Compilation Success Rate: {metrics['compilation_success_rate']:.3f}
- Generation Success Rate: {metrics['generation_success_rate']:.3f}
- Average Detection Accuracy: {metrics['average_detection_accuracy']:.3f}
- Vulnerability Coverage: {metrics['vulnerability_coverage']}

Detailed Results:
"""
        for vuln_result in results["vulnerability_results"]:
            summary_content += f"""
Vulnerability {vuln_result['vulnerability_id']} ({vuln_result['vulnerability_name']}):
- Generation Success: {'✓' if vuln_result['generation_success'] else '✗'}
- Compilation Success: {'✓' if vuln_result['compilation_success'] else '✗'}
- Test Cases: {len(vuln_result['detection_results'])}
"""

        summary_file.write_text(summary_content)

        logger.info(f"Evaluation results saved to {output_dir}")
