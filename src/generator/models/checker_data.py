"""
检查器生成数据模型

定义了检查器生成过程中的所有数据结构和持久化逻辑。
参考Knighter的checker_data.py设计，但支持自然语言漏洞描述作为输入。
"""

import difflib
import enum
import json
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple


class CheckerStatus(enum.Enum):
    """检查器生成状态枚举"""
    INIT = "init"
    PATTERN_EXTRACTED = "pattern_extracted"
    PLAN_GENERATED = "plan_generated"
    CODE_GENERATED = "code_generated"
    SYNTAX_REPAIRED = "syntax_repaired"
    SEMANTIC_REPAIRED = "semantic_repaired"
    NON_COMPILABLE = "non_compilable"
    VALID = "valid"
    INVALID = "invalid"


@dataclass
class RepairResult:
    """修复尝试结果"""
    attempt_id: int
    repair_type: str  # "syntax" or "semantic"
    original_code: str
    repaired_code: str
    error_message: Optional[str] = None
    success: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "repair_type": self.repair_type,
            "error_message": self.error_message,
            "success": self.success,
            "timestamp": self.timestamp
        }


@dataclass
class ValidationResult:
    """验证结果"""
    tp_score: int = -10  # True Positives - 检测到的真实漏洞数量
    tn_score: int = -10  # True Negatives - 正确识别的安全代码数量
    fp_count: int = 0    # False Positives - 误报数量
    fn_count: int = 0    # False Negatives - 漏报数量
    total_reports: int = 0
    validation_details: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_perfect(self) -> bool:
        """是否是完美的检查器（TP > 0 且 TN > 0）"""
        return self.tp_score > 0 and self.tn_score > 0

    @property
    def precision(self) -> float:
        """精确率 = TP / (TP + FP)"""
        if self.tp_score + self.fp_count == 0:
            return 0.0
        return self.tp_score / (self.tp_score + self.fp_count)

    @property
    def recall(self) -> float:
        """召回率 = TP / (TP + FN)"""
        if self.tp_score + self.fn_count == 0:
            return 0.0
        return self.tp_score / (self.tp_score + self.fn_count)

    @property
    def f1_score(self) -> float:
        """F1分数"""
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tp_score": self.tp_score,
            "tn_score": self.tn_score,
            "fp_count": self.fp_count,
            "fn_count": self.fn_count,
            "total_reports": self.total_reports,
            "is_perfect": self.is_perfect,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "validation_details": self.validation_details
        }


def generate_diff_patch(
    original_code: str,
    refined_code: str,
    original_filename: str = "original.cpp",
    refined_filename: str = "refined.cpp"
) -> str:
    """生成统一diff补丁"""
    original_lines = original_code.splitlines(keepends=True)
    refined_lines = refined_code.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        refined_lines,
        fromfile=original_filename,
        tofile=refined_filename,
        lineterm=""
    )

    return "".join(diff)


class CheckerData:
    """
    检查器数据类

    跟踪单个检查器从生成到验证的完整生命周期。
    支持两种输入模式：自然语言漏洞描述和代码补丁。
    """

    CHECKER_ID_PREFIX = "LLM-"

    def __init__(
        self,
        checker_id: str,
        base_result_dir: Path,
        vulnerability_desc: Optional[str] = None,
        patch: Optional[str] = None,
        input_type: str = "natural_language"  # "natural_language" or "patch"
    ):
        # 基本信息
        self.checker_id = checker_id
        self.input_type = input_type
        self.base_result_dir = Path(base_result_dir)
        self.creation_time = datetime.now()

        # 输入数据
        self.vulnerability_desc = vulnerability_desc
        self.patch = patch

        # 生成阶段数据
        self.status = CheckerStatus.INIT
        self.pattern: Optional[str] = None
        self.plan: Optional[str] = None
        self.initial_checker_code: Optional[str] = None

        # 修复阶段数据
        self.syntax_repair_log: List[RepairResult] = []
        self.semantic_repair_log: List[RepairResult] = []
        self.repaired_checker_code: Optional[str] = None

        # 验证结果
        self.validation_result = ValidationResult()

    @property
    def output_dir(self) -> Path:
        """获取输出目录"""
        return self.base_result_dir / self.checker_id

    @property
    def intermediate_dir(self) -> Path:
        """获取中间结果目录"""
        return self.output_dir / "intermediate"

    @property
    def is_valid(self) -> bool:
        """检查器是否有效（通过验证）"""
        return self.validation_result.is_perfect

    @property
    def is_compilable(self) -> bool:
        """检查器是否可编译"""
        return self.status in [
            CheckerStatus.SYNTAX_REPAIRED,
            CheckerStatus.SEMANTIC_REPAIRED,
            CheckerStatus.VALID
        ]

    def update_status(self, new_status: CheckerStatus):
        """更新状态"""
        self.status = new_status

    def add_syntax_repair(self, result: RepairResult):
        """添加语法修复记录"""
        self.syntax_repair_log.append(result)
        if result.success:
            self.repaired_checker_code = result.repaired_code
            self.update_status(CheckerStatus.SYNTAX_REPAIRED)

    def add_semantic_repair(self, result: RepairResult):
        """添加语义修复记录"""
        self.semantic_repair_log.append(result)
        if result.success:
            self.repaired_checker_code = result.repaired_code
            self.update_status(CheckerStatus.SEMANTIC_REPAIRED)

    def set_validation_result(self, result: ValidationResult):
        """设置验证结果"""
        self.validation_result = result
        if result.is_perfect:
            self.update_status(CheckerStatus.VALID)
        else:
            self.update_status(CheckerStatus.INVALID)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "checker_id": self.checker_id,
            "input_type": self.input_type,
            "creation_time": self.creation_time.isoformat(),
            "status": self.status.value,
            "vulnerability_desc": self.vulnerability_desc,
            "has_patch": self.patch is not None,
            "pattern_length": len(self.pattern) if self.pattern else 0,
            "plan_length": len(self.plan) if self.plan else 0,
            "has_initial_code": self.initial_checker_code is not None,
            "syntax_repairs": len(self.syntax_repair_log),
            "semantic_repairs": len(self.semantic_repair_log),
            "has_repaired_code": self.repaired_checker_code is not None,
            "validation": self.validation_result.to_dict()
        }

    def save_metadata(self):
        """保存元数据"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        metadata_file = self.output_dir / "metadata.json"
        metadata_file.write_text(json.dumps(self.to_dict(), indent=2))

    def save_intermediate_files(self):
        """保存中间文件"""
        intermediate_dir = self.intermediate_dir
        intermediate_dir.mkdir(parents=True, exist_ok=True)

        # 保存输入
        if self.vulnerability_desc:
            (intermediate_dir / "01_vulnerability_description.md").write_text(
                self.vulnerability_desc
            )

        if self.patch:
            (intermediate_dir / "01_patch.diff").write_text(self.patch)

        # 保存模式
        if self.pattern:
            (intermediate_dir / "02_pattern.md").write_text(self.pattern)

        # 保存计划
        if self.plan:
            (intermediate_dir / "03_plan.md").write_text(self.plan)

        # 保存初始代码
        if self.initial_checker_code:
            (intermediate_dir / "04_initial_code.cpp").write_text(
                self.initial_checker_code
            )

        # 保存修复后的代码
        if self.repaired_checker_code:
            (intermediate_dir / "05_repaired_code.cpp").write_text(
                self.repaired_checker_code
            )

            # 保存diff
            if self.initial_checker_code:
                diff = generate_diff_patch(
                    self.initial_checker_code,
                    self.repaired_checker_code
                )
                (intermediate_dir / "05_repair_diff.patch").write_text(diff)

        # 保存验证结果
        validation_file = intermediate_dir / "06_validation.json"
        validation_file.write_text(
            json.dumps(self.validation_result.to_dict(), indent=2)
        )

        # 保存修复历史
        if self.syntax_repair_log:
            repair_file = intermediate_dir / "07_syntax_repairs.json"
            repair_data = [r.to_dict() for r in self.syntax_repair_log]
            repair_file.write_text(json.dumps(repair_data, indent=2))

        if self.semantic_repair_log:
            repair_file = intermediate_dir / "08_semantic_repairs.json"
            repair_data = [r.to_dict() for r in self.semantic_repair_log]
            repair_file.write_text(json.dumps(repair_data, indent=2))

    def save_final_checker(self, output_dir: Optional[Path] = None):
        """保存最终检查器代码"""
        target_dir = output_dir or self.output_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        final_code = self.repaired_checker_code or self.initial_checker_code
        if final_code:
            (target_dir / f"{self.checker_id}.cpp").write_text(final_code)

            # 保存简化版的元数据
            metadata = {
                "checker_id": self.checker_id,
                "status": self.status.value,
                "validation": self.validation_result.to_dict(),
                "creation_time": self.creation_time.isoformat()
            }
            (target_dir / f"{self.checker_id}.meta.json").write_text(
                json.dumps(metadata, indent=2)
            )

    def save_all(self):
        """保存所有数据"""
        self.save_metadata()
        self.save_intermediate_files()
        self.save_final_checker()

    @classmethod
    def load_from_dir(cls, checker_dir: Path) -> 'CheckerData':
        """从目录加载检查器数据"""
        metadata_file = checker_dir / "metadata.json"
        if not metadata_file.exists():
            raise FileNotFoundError(f"Metadata file not found in {checker_dir}")

        metadata = json.loads(metadata_file.read_text())

        # 创建实例
        checker = cls(
            checker_id=metadata["checker_id"],
            base_result_dir=checker_dir.parent,
            vulnerability_desc=metadata.get("vulnerability_desc"),
            patch=None,  # 需要从文件加载
            input_type=metadata.get("input_type", "natural_language")
        )

        # 恢复状态
        checker.status = CheckerStatus(metadata["status"])

        # 加载中间文件
        intermediate_dir = checker_dir / "intermediate"
        if intermediate_dir.exists():
            # 模式
            pattern_file = intermediate_dir / "02_pattern.md"
            if pattern_file.exists():
                checker.pattern = pattern_file.read_text()

            # 计划
            plan_file = intermediate_dir / "03_plan.md"
            if plan_file.exists():
                checker.plan = plan_file.read_text()

            # 初始代码
            initial_file = intermediate_dir / "04_initial_code.cpp"
            if initial_file.exists():
                checker.initial_checker_code = initial_file.read_text()

            # 修复后的代码
            repaired_file = intermediate_dir / "05_repaired_code.cpp"
            if repaired_file.exists():
                checker.repaired_checker_code = repaired_file.read_text()

            # 验证结果
            validation_file = intermediate_dir / "06_validation.json"
            if validation_file.exists():
                val_data = json.loads(validation_file.read_text())
                checker.validation_result = ValidationResult(**val_data)

            # 修复历史
            syntax_file = intermediate_dir / "07_syntax_repairs.json"
            if syntax_file.exists():
                for r_data in json.loads(syntax_file.read_text()):
                    checker.syntax_repair_log.append(RepairResult(**r_data))

            semantic_file = intermediate_dir / "08_semantic_repairs.json"
            if semantic_file.exists():
                for r_data in json.loads(semantic_file.read_text()):
                    checker.semantic_repair_log.append(RepairResult(**r_data))

        return checker


class GenerationBatch:
    """批量生成任务的数据集合"""

    def __init__(self, batch_id: str, output_dir: Path):
        self.batch_id = batch_id
        self.output_dir = Path(output_dir)
        self.checkers: Dict[str, CheckerData] = {}
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None

    def add_checker(self, checker: CheckerData):
        """添加检查器"""
        self.checkers[checker.checker_id] = checker

    def get_checker(self, checker_id: str) -> Optional[CheckerData]:
        """获取检查器"""
        return self.checkers.get(checker_id)

    def complete(self):
        """标记批次完成"""
        self.end_time = datetime.now()
        self.save_summary()

    @property
    def total_checkers(self) -> int:
        """总检查器数量"""
        return len(self.checkers)

    @property
    def successful_checkers(self) -> int:
        """成功的检查器数量（编译通过）"""
        return sum(1 for c in self.checkers.values() if c.is_compilable)

    @property
    def valid_checkers(self) -> int:
        """有效的检查器数量（通过验证）"""
        return sum(1 for c in self.checkers.values() if c.is_valid)

    @property
    def duration_seconds(self) -> float:
        """持续时间（秒）"""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    def get_best_checker(self) -> Optional[CheckerData]:
        """获取最佳检查器（最高F1分数）"""
        valid_checkers = [c for c in self.checkers.values() if c.is_valid]
        if not valid_checkers:
            return None
        return max(valid_checkers, key=lambda c: c.validation_result.f1_score)

    def save_summary(self):
        """保存批次摘要"""
        summary = {
            "batch_id": self.batch_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "total_checkers": self.total_checkers,
            "successful_checkers": self.successful_checkers,
            "valid_checkers": self.valid_checkers,
            "success_rate": self.successful_checkers / max(self.total_checkers, 1),
            "valid_rate": self.valid_checkers / max(self.total_checkers, 1),
            "checkers": {
                cid: c.to_dict() for cid, c in self.checkers.items()
            }
        }

        summary_file = self.output_dir / f"{self.batch_id}_summary.json"
        summary_file.write_text(json.dumps(summary, indent=2))

        # 也保存CSV格式的简化摘要
        self.save_csv_summary()

    def save_csv_summary(self):
        """保存CSV格式的摘要"""
        import csv

        csv_file = self.output_dir / f"{self.batch_id}_summary.csv"
        with csv_file.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "checker_id", "status", "tp_score", "tn_score",
                "precision", "recall", "f1_score", "is_perfect"
            ])

            for checker in self.checkers.values():
                v = checker.validation_result
                writer.writerow([
                    checker.checker_id,
                    checker.status.value,
                    v.tp_score,
                    v.tn_score,
                    f"{v.precision:.3f}",
                    f"{v.recall:.3f}",
                    f"{v.f1_score:.3f}",
                    v.is_perfect
                ])
