"""
日志系统配置

为LLM-Native框架配置完整的日志系统，支持：
1. 多级别日志输出
2. 文件和控制台双输出
3. 彩色输出支持
4. 按时间自动轮转
5. 结构化日志支持
"""

import sys
from pathlib import Path
from typing import Optional
from loguru import logger


def setup_logger(
    log_dir: Path,
    log_level: str = "INFO",
    rotation: str = "100 MB",
    retention: str = "7 days",
    enable_json: bool = False
):
    """
    配置日志系统

    Args:
        log_dir: 日志目录
        log_level: 日志级别
        rotation: 日志轮转大小
        retention: 日志保留时间
        enable_json: 是否启用JSON格式日志
    """
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    # 移除默认处理器
    logger.remove()

    # 控制台输出 - 带颜色
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
               "<level>{message}</level>",
        level=log_level,
        colorize=True,
        backtrace=True,
        diagnose=True
    )

    # 通用日志文件
    logger.add(
        log_dir / "llm_native_{time:YYYY-MM-DD}.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
        level="DEBUG",
        rotation=rotation,
        retention=retention,
        compression="zip",
        backtrace=True,
        diagnose=True
    )

    # 错误日志文件
    logger.add(
        log_dir / "errors_{time:YYYY-MM-DD}.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
        level="ERROR",
        rotation=rotation,
        retention=retention,
        compression="zip",
        backtrace=True,
        diagnose=True
    )

    # JSON格式日志（可选）
    if enable_json:
        logger.add(
            log_dir / "llm_native_json_{time:YYYY-MM-DD}.log",
            format="{message}",
            level="DEBUG",
            rotation=rotation,
            retention=retention,
            compression="zip",
            serialize=True  # JSON格式
        )

    logger.info(f"Logger initialized. Log directory: {log_dir}")
    return logger


class GenerationLogger:
    """生成过程专用日志记录器"""

    def __init__(self, output_dir: Path, task_id: str):
        self.output_dir = Path(output_dir)
        self.task_id = task_id
        self.log_file = self.output_dir / f"{task_id}_generation.log"

        # 创建独立的文件处理器
        self.handler_id = logger.add(
            self.log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
            level="DEBUG",
            filter=lambda record: record["extra"].get("task_id") == task_id
        )

    def log_stage(self, stage: str, message: str, level: str = "INFO"):
        """记录生成阶段"""
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{stage}] {message}", task_id=self.task_id)

    def log_pattern_extraction(self, pattern: str):
        """记录模式提取结果"""
        logger.info(f"Pattern extracted ({len(pattern)} chars)", task_id=self.task_id)
        (self.output_dir / "pattern.md").write_text(pattern)

    def log_plan_generation(self, plan: str):
        """记录计划生成结果"""
        logger.info(f"Plan generated ({len(plan)} chars)", task_id=self.task_id)
        (self.output_dir / "plan.md").write_text(plan)

    def log_code_generation(self, code: str, success: bool):
        """记录代码生成结果"""
        status = "SUCCESS" if success else "FAILED"
        logger.info(f"Code generation {status} ({len(code)} chars)", task_id=self.task_id)

        if success:
            (self.output_dir / "generated_code.cpp").write_text(code)

    def log_repair_attempt(
        self,
        attempt_id: int,
        repair_type: str,
        success: bool,
        error_msg: Optional[str] = None
    ):
        """记录修复尝试"""
        status = "SUCCESS" if success else "FAILED"
        msg = f"Repair attempt {attempt_id} ({repair_type}): {status}"

        if error_msg:
            msg += f" - {error_msg}"

        logger.info(msg, task_id=self.task_id)

    def log_validation_result(self, tp: int, tn: int, is_perfect: bool):
        """记录验证结果"""
        status = "PERFECT" if is_perfect else "NEEDS_IMPROVEMENT"
        logger.info(
            f"Validation: {status} - TP={tp}, TN={tn}",
            task_id=self.task_id
        )

    def log_error(self, stage: str, error: Exception):
        """记录错误"""
        logger.error(
            f"Error in {stage}: {type(error).__name__}: {str(error)}",
            task_id=self.task_id,
            exc_info=True
        )

    def close(self):
        """关闭日志记录器"""
        logger.remove(self.handler_id)
