from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RefinementRequest:
    analyzer: str
    patch_path: str
    work_dir: str
    target_path: str
    source_path: str = ""
    validate_path: str = ""
    evidence_dir: str = ""
    evidence_bundle_raw: Dict[str, Any] = field(default_factory=dict)
    baseline_validation_summary: str = ""
    checker_name: str = ""
    max_iterations: int = 12


@dataclass
class RefinementResult:
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
