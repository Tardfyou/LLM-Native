"""
数据模型定义
"""

from .generation_models import (
    GenerationInput,
    GenerationOutput,
    GenerationState,
    ValidationResult,
    DetectionPlan
)

__all__ = [
    'GenerationInput',
    'GenerationOutput',
    'GenerationState',
    'ValidationResult',
    'DetectionPlan'
]
