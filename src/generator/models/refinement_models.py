"""
Refinement Models
数据模型定义 - 用于高级精炼系统
"""

from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict, Any
from datetime import datetime
from pathlib import Path


@dataclass
class ReportData:
    """报告数据模型"""
    report_id: str
    report_content: str
    report_triage: str = ""  # LLM分类结果
    report_objects: List[str] = field(default_factory=list)  # 涉及的目标文件

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "report_content": self.report_content,
            "report_triage": self.report_triage,
            "report_objects": self.report_objects
        }


@dataclass
class RefineAttempt:
    """单次精炼尝试"""
    refine_id: str
    report_data: Optional[ReportData] = None
    original_code: str = ""
    initial_refine_code: str = ""
    syntax_correct_refine_code: str = ""
    semantic_correct_refine_code: str = ""
    reasoning_process: str = ""
    killed_objects: Set[str] = field(default_factory=set)  # 成功消除的FP对象

    def dump_dir(self, output_dir: Path):
        """保存精炼尝试到文件"""
        refine_dir = output_dir / "refinements"
        refine_dir.mkdir(parents=True, exist_ok=True)

        # 保存精炼代码
        if self.semantic_correct_refine_code:
            code_file = refine_dir / f"refined_{self.refine_id}.cpp"
            code_file.write_text(self.semantic_correct_refine_code)

        # 保存推理过程
        if self.reasoning_process:
            reasoning_file = refine_dir / f"refined_{self.refine_id}_reasoning.md"
            reasoning_file.write_text(self.reasoning_process)

        # 保存metadata
        metadata = {
            "refine_id": self.refine_id,
            "report_id": self.report_data.report_id if self.report_data else None,
            "killed_objects": list(self.killed_objects),
            "has_semantic_correct": bool(self.semantic_correct_refine_code)
        }
        import json
        metadata_file = refine_dir / f"refined_{self.refine_id}_metadata.json"
        metadata_file.write_text(json.dumps(metadata, indent=2))


@dataclass
class RefinementResult:
    """精炼结果"""
    refined: bool = False
    checker_code: str = ""
    result: str = "Failed"  # Failed, Perfect, No-FP, High-TP, Refined, Uncompilable, Unscannable
    num_TP: int = 0
    num_FP: int = 0
    num_reports: int = 0
    attempt_id: int = 0
    refine_attempt_list: List[RefineAttempt] = field(default_factory=list)
    error_objects: Set[str] = field(default_factory=set)
    original_checker_code: str = ""

    def save_refined_code(self, output_dir: Path, checker_id: str):
        """保存精炼后的代码"""
        if not self.refined:
            return

        refine_dir = output_dir / "refinements"
        refine_dir.mkdir(parents=True, exist_ok=True)

        # 保存最新精炼代码
        latest_file = refine_dir / "latest_refined.cpp"
        latest_file.write_text(self.checker_code)

        # 保存当前尝试的代码
        attempt_file = refine_dir / f"attempt_{self.attempt_id}.cpp"
        attempt_file.write_text(self.checker_code)

        if self.original_checker_code:
            original_file = refine_dir / f"attempt_{self.attempt_id}_original.cpp"
            original_file.write_text(self.original_checker_code)

    @property
    def precision(self) -> float:
        """计算精确率"""
        total = self.num_TP + self.num_FP
        return self.num_TP / total if total > 0 else 0.0


@dataclass
class GenerationProgress:
    """生成进度跟踪"""
    total_steps: int = 6
    current_step: int = 0
    step_names: List[str] = field(
        default_factory=lambda: [
            "🔍 Pattern Extraction",
            "📋 Plan Generation",
            "💻 Code Generation",
            "🔧 Syntax Repair",
            "✅ Validation",
            "📊 Summary",
        ]
    )
    start_time: datetime = field(default_factory=datetime.now)
    step_times: Dict[str, float] = field(default_factory=dict)

    def start_step(self, step_name: str = None) -> str:
        """开始一个新步骤"""
        if step_name is None:
            step_name = self.step_names[min(self.current_step, len(self.step_names) - 1)]

        self.current_step += 1
        progress = (self.current_step / self.total_steps) * 100

        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"[{progress:5.1f}%] {step_name}")
        print(f"⏳ [{progress:5.1f}%] {step_name}...")

        self.step_times[step_name] = __import__('time').time()
        return step_name

    def complete_step(self, step_name: str, details: str = ""):
        """完成当前步骤"""
        import time
        if step_name in self.step_times:
            duration = time.time() - self.step_times[step_name]
            self.step_times[step_name] = duration
        else:
            duration = 0

        print(f"✅ {step_name} ({duration:.1f}s)")
        if details:
            print(f"   └── {details}")

        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Completed: {step_name} in {duration:.1f}s - {details}")

    def fail_step(self, step_name: str, error: str):
        """标记步骤失败"""
        import time
        if step_name in self.step_times:
            duration = time.time() - self.step_times[step_name]
        else:
            duration = 0

        print(f"❌ {step_name} ({duration:.1f}s)")
        print(f"   └── Error: {error}")

        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed: {step_name} in {duration:.1f}s - {error}")

    def get_total_time(self) -> float:
        """获取总耗时"""
        return (datetime.now() - self.start_time).total_seconds()


@dataclass
class TriageResult:
    """报告分类结果"""
    is_fp: bool
    reasoning: str
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_fp": self.is_fp,
            "reasoning": self.reasoning,
            "confidence": self.confidence
        }
