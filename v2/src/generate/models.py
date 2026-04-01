from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class GenerationRequest:
    analyzer: str
    patch_path: str
    work_dir: str
    validate_path: str = ""
    extra_context: str = ""
    max_iterations: int = 12


@dataclass
class GenerationResult:
    success: bool = False
    checker_name: str = ""
    checker_code: str = ""
    output_path: str = ""
    iterations: int = 0
    compile_attempts: int = 0
    error_message: str = ""
    final_message: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
