"""
Generate agent compatibility layer.

旧版 CheckerAgent 已被基于 LangGraph 的 generate agent 取代。
保留该模块仅用于兼容仍然引用 `src.agent.core.CheckerAgent` 的调用点。
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Dict, Optional

from ..generate import GenerationRequest, GenerationResult, LangChainGenerateAgent


class AgentState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


AgentResult = GenerationResult


class CheckerAgent:
    def __init__(
        self,
        llm_client=None,
        tool_registry=None,
        config: Dict[str, Any] = None,
        prompt_config: Dict[str, Any] = None,
        analyzer: str = "csa",
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        merged_config = dict(config or {})
        if prompt_config:
            merged_config.update(prompt_config)
        self._agent = LangChainGenerateAgent(
            config=merged_config,
            tool_registry=tool_registry,
            analyzer=analyzer,
            progress_callback=progress_callback,
            llm_override=llm_client,
        )
        self.state = AgentState.IDLE

    def run(
        self,
        patch_path: str,
        output_dir: str = None,
        extra_context: str = None,
        validate_path: str = None,
        task_mode: str = "generate",
        refinement_target_path: str = None,
        refinement_source_path: str = None,
        initial_artifact_code: str = None,
        initial_artifact_name: str = None,
    ) -> AgentResult:
        if str(task_mode or "").strip().lower() == "refine":
            raise RuntimeError("CheckerAgent refine 模式已下线；请改用 LangChainRefinementAgent。")

        self.state = AgentState.RUNNING
        result = self._agent.run(
            GenerationRequest(
                analyzer=self._agent.analyzer,
                patch_path=patch_path,
                work_dir=output_dir or "./output",
                validate_path=validate_path or "",
                extra_context=extra_context or "",
                max_iterations=int(self._agent.max_iterations),
            )
        )
        self.state = AgentState.COMPLETED if result.success else AgentState.FAILED
        return result
