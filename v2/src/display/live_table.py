"""
实时进度表格

使用 rich.Live 实现类似 htop 的实时更新表格，
支持多分析器并行执行时的状态显示。
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum
from pathlib import Path

from loguru import logger

# 延迟导入 rich 组件
_rich_available = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    _rich_available = True
except ImportError:
    logger.warning("rich 库未安装，实时表格功能不可用，使用简单文本输出")


class AnalyzerStatus(Enum):
    """分析器状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AnalyzerProgress:
    """分析器进度信息"""
    analyzer: str
    display_name: str = ""
    status: AnalyzerStatus = AnalyzerStatus.PENDING
    phase: str = ""
    iteration: int = 0
    max_iterations: int = 30
    message: str = ""
    message_history: List[str] = field(default_factory=list)
    message_iteration: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    success: bool = False
    current_tool: str = ""
    last_result: str = ""
    last_error: str = ""
    checker_name: str = ""
    output_path: str = ""
    validation_summary: str = ""
    recent_events: List[str] = field(default_factory=list)
    last_update: float = 0.0

    @property
    def elapsed_time(self) -> float:
        """已用时间"""
        if self.end_time > 0:
            return self.end_time - self.start_time
        if self.start_time > 0:
            return time.time() - self.start_time
        return 0.0

    @property
    def progress_percent(self) -> float:
        """进度百分比"""
        if self.status == AnalyzerStatus.COMPLETED:
            return 100.0
        if self.status == AnalyzerStatus.PENDING:
            return 0.0
        if self.max_iterations > 0:
            return min(100.0, (self.iteration / self.max_iterations) * 100)
        return 0.0


class LiveProgressTable:
    """
    实时进度表格

    使用 rich.Live 实现类似 htop 的实时更新显示。
    每行显示一个分析器的状态。
    """

    STATUS_ICONS = {
        AnalyzerStatus.PENDING: "⏳",
        AnalyzerStatus.RUNNING: "🔄",
        AnalyzerStatus.COMPLETED: "✅",
        AnalyzerStatus.FAILED: "❌"
    }

    STATUS_COLORS = {
        AnalyzerStatus.PENDING: "dim",
        AnalyzerStatus.RUNNING: "cyan",
        AnalyzerStatus.COMPLETED: "green",
        AnalyzerStatus.FAILED: "red"
    }

    DISPLAY_NAMES = {
        "csa": "CSA (Clang Static Analyzer)",
        "codeql": "CodeQL",
        "patchweaver": "PATCHWEAVER",
    }
    SIMPLE_DEBUG_TOOLS = {
        "apply_patch",
        "lsp_validate",
        "compile_checker",
        "codeql_analyze",
        "review_artifact",
        "search_knowledge",
    }

    def __init__(
        self,
        verbose: bool = True,
        refresh_rate: int = 4,
        use_rich: bool = True
    ):
        """
        初始化实时进度表格

        Args:
            verbose: 是否显示详细信息
            refresh_rate: 刷新率 (Hz)
            use_rich: 是否使用 rich 库
        """
        self.verbose = verbose
        self.refresh_rate = refresh_rate
        self.use_rich = use_rich and _rich_available

        # 分析器进度状态
        self.analyzers: Dict[str, AnalyzerProgress] = {}
        self._lock = threading.RLock()

        # Rich 组件
        self._console: Optional[Console] = None
        self._live: Optional[Live] = None
        self._start_time = 0.0
        self._focused_analyzer: Optional[str] = None

        # 消息历史（用于简单模式）
        self._messages: List[str] = []

    def start(self):
        """启动实时显示"""
        self._start_time = time.time()

        if not self.verbose:
            return

        if self.use_rich:
            self._start_rich()
        else:
            self._print_header_simple()

    def _start_rich(self):
        """启动 Rich 实时显示"""
        self._console = Console()

        # 创建 Live 显示
        self._live = Live(
            self,
            console=self._console,
            refresh_per_second=self.refresh_rate,
            screen=False,  # 非全屏模式
            transient=False  # 保留最终显示
        )
        self._live.start()

    def __rich__(self):
        """供 rich.Live 自动刷新时调用"""
        return self._generate_display()

    def stop(self):
        """停止实时显示"""
        if self._live:
            self._live.stop()
            self._live = None

    def update(self, event: Dict[str, Any]):
        """
        更新进度

        Args:
            event: 事件数据，包含 analyzer, event, 等字段
        """
        analyzer = event.get("analyzer", "")
        event_type = event.get("event", "")

        if not analyzer:
            return

        # 过滤掉内部事件（如 "parallel"）
        if analyzer in ("parallel", "system"):
            return

        with self._lock:
            # 确保分析器存在
            if analyzer not in self.analyzers:
                self.analyzers[analyzer] = AnalyzerProgress(
                    analyzer=analyzer,
                    display_name=event.get("analyzer_name", self.DISPLAY_NAMES.get(analyzer, analyzer))
                )

            progress = self.analyzers[analyzer]

            # 更新状态
            self._update_progress(progress, event_type, event)
            self._focused_analyzer = analyzer

        # 简单模式下立即打印
        if not self._live and self.verbose:
            self._print_update_simple(progress, event_type, event)

    def _update_progress(
        self,
        progress: AnalyzerProgress,
        event_type: str,
        event: Dict[str, Any]
    ):
        """更新进度状态"""
        # 只保留当前迭代消息：当事件携带 iteration 且发生变化时，清空历史
        event_iteration = event.get("iteration")
        if isinstance(event_iteration, int) and event_iteration > 0:
            if progress.message_iteration != event_iteration:
                progress.message_history.clear()
                progress.message = ""
                progress.message_iteration = event_iteration

        if event_type == "submitted":
            progress.status = AnalyzerStatus.PENDING
            progress.phase = "等待中"
            progress.last_update = time.time()

        elif event_type == "preflight_started":
            progress.status = AnalyzerStatus.RUNNING
            progress.phase = "补丁预分析"
            if progress.start_time <= 0:
                progress.start_time = time.time()
            progress.last_result = "正在构建 PATCHWEAVER 预分析"
            progress.last_update = time.time()

        elif event_type == "preflight_completed":
            progress.status = AnalyzerStatus.COMPLETED
            progress.phase = "预分析完成"
            planned = int(event.get("planned_evidence", 0) or 0)
            summary = str(event.get("summary", "") or "").strip()
            progress.last_result = f"planned_evidence={planned}" if planned > 0 else "预分析完成"
            if summary:
                self._append_recent_event(progress, summary[:180])
            progress.end_time = time.time()
            progress.last_update = time.time()

        elif event_type == "started":
            progress.status = AnalyzerStatus.RUNNING
            progress.phase = "初始化"
            if progress.start_time <= 0:
                progress.start_time = time.time()
            progress.last_update = time.time()

        elif event_type == "pipeline_started":
            progress.status = AnalyzerStatus.RUNNING
            progress.phase = "初始化"
            progress.start_time = time.time()
            progress.last_update = time.time()

        elif event_type == "generation_started":
            progress.status = AnalyzerStatus.RUNNING
            if progress.start_time <= 0:
                progress.start_time = time.time()
            progress.phase = "生成中"
            progress.last_update = time.time()

        elif event_type == "evidence_collection_started":
            progress.status = AnalyzerStatus.RUNNING
            if progress.start_time <= 0:
                progress.start_time = time.time()
            progress.phase = "证据收集中"
            progress.current_tool = "PATCHWEAVER evidence"
            progress.last_result = "正在收集 analyzer/runtime 证据"
            progress.last_update = time.time()

        elif event_type == "evidence_collection_completed":
            progress.phase = "证据收集完成"
            records = int(event.get("records", 0) or 0)
            missing = int(event.get("missing", 0) or 0)
            progress.last_result = f"records={records}, missing={missing}"
            self._append_recent_event(progress, progress.last_result)
            progress.last_update = time.time()

        elif event_type == "synthesis_input_prepared":
            progress.phase = "合成输入已准备"
            selected = int(event.get("selected_evidence", 0) or 0)
            progress.last_result = f"selected_evidence={selected}"
            self._append_recent_event(progress, progress.last_result)
            progress.last_update = time.time()

        elif event_type == "agent_run_started":
            progress.phase = "基于证据合成"
            progress.current_tool = "-"
            extra = []
            if event.get("vuln_type"):
                extra.append(f"vuln={event.get('vuln_type')}")
            if extra:
                progress.last_result = ", ".join(extra)
            progress.last_update = time.time()

        elif event_type == "agent_run_completed":
            progress.phase = "智能体合成完成"
            iterations = int(event.get("iterations", 0) or 0)
            if iterations > 0:
                progress.last_result = f"agent_iterations={iterations}"
            progress.last_update = time.time()

        elif event_type == "generation_completed":
            progress.phase = "生成完成"
            progress.iteration = event.get("iterations", progress.iteration)
            progress.checker_name = event.get("checker_name", progress.checker_name)
            progress.output_path = event.get("output_path", progress.output_path)
            progress.last_result = "生成成功" if event.get("success") else "生成失败"
            progress.last_update = time.time()

        elif event_type == "validation_started":
            progress.phase = "验证中"
            progress.last_update = time.time()

        elif event_type == "validation_completed":
            progress.phase = "验证完成"
            bugs_found = event.get("bugs_found")
            success = event.get("success", False)
            if bugs_found is not None:
                progress.validation_summary = (
                    f"{'通过' if success else '失败'} | 漏洞数 {bugs_found}"
                )
            else:
                progress.validation_summary = "通过" if success else "失败"
            progress.output_path = event.get("output_path", progress.output_path)
            progress.last_update = time.time()

        elif event_type == "validation_feedback_attached":
            progress.phase = "反馈归一化"
            records = event.get("records", 0)
            summary = str(event.get("summary", "") or "").strip()
            progress.last_result = f"feedback={records}"
            if summary:
                first_line = summary.splitlines()[0].strip()
                if first_line:
                    self._append_recent_event(progress, first_line)
            progress.last_update = time.time()

        elif event_type == "refinement_iteration_started":
            progress.status = AnalyzerStatus.RUNNING
            progress.iteration = int(event.get("iteration", progress.iteration) or progress.iteration)
            progress.phase = f"精炼轮 {progress.iteration} 开始"
            progress.last_result = "准备进入 refine 工作流"
            self._append_recent_event(progress, progress.last_result)
            progress.last_update = time.time()

        elif event_type == "refinement_iteration_completed":
            progress.phase = "精炼轮完成"
            adopted = bool(event.get("adopted", False))
            success = bool(event.get("success", False))
            progress.last_result = (
                f"{'采用候选' if adopted else '保留基线'} | "
                f"{'候选通过' if success else '候选未通过'}"
            )
            self._append_recent_event(progress, progress.last_result)
            progress.last_update = time.time()

        elif event_type == "refinement_iteration_skipped":
            progress.phase = "跳过精炼"
            reason = str(event.get("reason", "") or "").strip()
            progress.last_result = reason or "基线已满足严格精炼质量门"
            self._append_recent_event(progress, progress.last_result[:180])
            progress.last_update = time.time()

        elif event_type == "portfolio_resolved":
            preferred = event.get("preferred_analyzer", "")
            progress.phase = "组合决策完成"
            progress.last_result = preferred or progress.last_result
            summary = event.get("summary", "")
            if summary:
                self._append_recent_event(progress, summary)
            progress.last_update = time.time()

        elif event_type == "pipeline_completed":
            progress.status = AnalyzerStatus.COMPLETED if event.get("success") else AnalyzerStatus.FAILED
            progress.end_time = time.time()
            progress.success = event.get("success", False)
            progress.output_path = event.get("output_path", progress.output_path)
            progress.last_result = "完成" if progress.success else "失败"
            progress.last_update = time.time()

        elif event_type == "pipeline_failed":
            progress.status = AnalyzerStatus.FAILED
            progress.end_time = time.time()
            progress.last_error = event.get("error", "")
            self._push_message(progress, event.get("error", ""))
            self._append_recent_event(progress, f"失败: {event.get('error', '')[:180]}")
            progress.last_update = time.time()

        elif event_type == "iteration_started":
            progress.iteration = event.get("iteration", progress.iteration)
            progress.max_iterations = event.get("max_iterations", progress.max_iterations)
            progress.phase = f"迭代 {progress.iteration}/{progress.max_iterations}"
            if not progress.message:
                progress.message = "工具: 等待中"
            progress.last_update = time.time()

        elif event_type == "tool_called":
            tool_name = event.get("tool_name", "") or event.get("name", "")
            if tool_name:
                progress.current_tool = tool_name
                args_preview = event.get("args_preview", "")
                msg = f"调用工具: {tool_name}"
                if args_preview:
                    msg += f" | {args_preview}"
                self._push_message(progress, msg)
                self._append_recent_event(progress, msg)
                progress.last_update = time.time()

        elif event_type == "tool_result":
            success = event.get("success", True)
            summary = event.get("summary", "")
            progress.last_result = summary or ("成功" if success else "失败")
            if summary:
                self._push_message(progress, summary)
                self._append_recent_event(progress, summary)
            elif not success:
                error = event.get("error", "")
                if error:
                    progress.last_error = error
                    self._push_message(progress, f"错误: {error[:180]}")
                    self._append_recent_event(progress, f"错误: {error[:180]}")
            elif success:
                progress.last_error = ""
            progress.last_update = time.time()

        # Agent 事件
        elif event_type.startswith("agent_"):
            agent_event = event_type[len("agent_"):]

            if agent_event == "run_started":
                progress.status = AnalyzerStatus.RUNNING
                if progress.start_time <= 0:
                    progress.start_time = time.time()
                progress.phase = "智能体启动"
                progress.last_update = time.time()
            elif agent_event == "run_completed":
                progress.phase = "智能体完成"
                progress.output_path = event.get("output_path", progress.output_path)
                error_message = str(event.get("error_message", "") or "").strip()
                if error_message:
                    progress.last_error = error_message
                    self._append_recent_event(progress, f"agent_error: {error_message[:180]}")
                final_message = str(event.get("final_message", "") or "").strip()
                if final_message:
                    progress.last_result = final_message[:180]
                progress.last_update = time.time()
            elif agent_event == "iteration_started":
                progress.iteration = event.get("iteration", progress.iteration)
                progress.max_iterations = event.get("max_iterations", progress.max_iterations)
                progress.phase = f"迭代 {progress.iteration}/{progress.max_iterations}"
                if not progress.message:
                    progress.message = "工具: 等待中"
                progress.last_update = time.time()
            elif agent_event == "decision_started":
                progress.phase = "模型决策中"
                progress.current_tool = "-"
                progress.last_update = time.time()
            elif agent_event == "decision_completed":
                progress.phase = "模型决策完成"
                action = str(event.get("action", "") or "").strip()
                summary = str(event.get("summary", "") or "").strip()
                parts = []
                if action:
                    parts.append(f"action={action}")
                if summary:
                    parts.append(summary)
                progress.last_result = " | ".join(parts) or "模型返回决策"
                self._append_recent_event(progress, progress.last_result[:180])
                progress.last_update = time.time()
            elif agent_event == "decision_parse_failed":
                progress.phase = "模型决策解析失败"
                error = str(event.get("error", "") or "").strip()
                raw_preview = str(event.get("raw_preview", "") or "").strip()
                if error:
                    progress.last_error = error
                if raw_preview:
                    progress.last_result = raw_preview[:180]
                    self._append_recent_event(progress, f"raw: {raw_preview[:180]}")
                progress.last_update = time.time()
            elif agent_event == "think_started":
                progress.phase = "思考中"
                if not progress.message:
                    progress.message = "工具: 等待中"
                progress.last_update = time.time()
            elif agent_event == "llm_call_started":
                # 消息列简化：不展示 LLM 调用流
                pass
            elif agent_event == "think_completed":
                # 消息列简化：不展示思考内容
                pass
            elif agent_event == "tool_called":
                tool_name = event.get("tool_name", "") or event.get("name", "")
                progress.phase = "执行工具"
                if tool_name:
                    progress.current_tool = tool_name
                    args_preview = event.get("args_preview", "")
                    msg = f"调用工具: {tool_name}"
                    if args_preview:
                        msg += f" | {args_preview}"
                    self._push_message(progress, msg)
                    self._append_recent_event(progress, msg)
                    progress.last_update = time.time()
            elif agent_event == "tool_result":
                success = event.get("success", True)
                summary = event.get("summary", "")
                progress.last_result = summary or ("成功" if success else "失败")
                if summary:
                    self._push_message(progress, summary)
                    self._append_recent_event(progress, summary)
                elif not success:
                    error = event.get("error", "")
                    if error:
                        progress.last_error = error
                        self._push_message(progress, f"错误: {error[:180]}")
                        self._append_recent_event(progress, f"错误: {error[:180]}")
                elif success:
                    progress.last_error = ""
                progress.last_update = time.time()
            elif "think" in agent_event:
                progress.phase = "思考中"
            elif "act" in agent_event:
                progress.phase = "执行工具"

    def _generate_display(self):
        """生成 Rich 显示"""
        if not self._console:
            return ""

        layout = Layout()

        layout.split(
            Layout(name="header", size=3),
            Layout(name="table", size=min(18, 8 + len(self.analyzers) * 2)),
            Layout(name="detail", size=14),
            Layout(name="footer", size=3)
        )

        # 头部
        elapsed = time.time() - self._start_time
        header_text = Text()
        header_text.append("检测器生成", style="bold blue")
        header_text.append(f"  |  总耗时: {self._format_time(elapsed)}", style="dim")

        layout["header"].update(Panel(
            header_text,
            title="LLVM Checker Generator v2",
            border_style="blue"
        ))

        # 分析器表格
        table = self._generate_table()
        layout["table"].update(table)

        detail_panel = self._generate_detail_panel()
        layout["detail"].update(detail_panel)

        # 底部状态
        footer_text = self._generate_footer()
        layout["footer"].update(Panel(
            footer_text,
            border_style="dim"
        ))

        return layout

    def _generate_table(self) -> Table:
        """生成分析器状态表格"""
        table = Table(
            title="分析器状态",
            show_header=True,
            header_style="bold",
            border_style="blue",
            expand=True,
            padding=(0, 1)
        )

        table.add_column("分析器", style="bold", width=20)
        table.add_column("状态", width=6)
        table.add_column("阶段", width=15)
        table.add_column("当前工具", width=18)
        table.add_column("最近结果", width=24, overflow="fold")
        table.add_column("最近错误", width=24, overflow="fold")
        table.add_column("迭代", width=10)
        table.add_column("耗时", width=8)

        with self._lock:
            analyzer_items = list(self.analyzers.items())

        for analyzer_id, progress in analyzer_items:
            icon = self.STATUS_ICONS[progress.status]
            color = self.STATUS_COLORS[progress.status]

            status_text = Text(icon, style=color)

            # 迭代显示
            iter_text = ""
            if progress.status == AnalyzerStatus.RUNNING:
                iter_text = f"{progress.iteration}/{progress.max_iterations}"
            elif progress.status in [AnalyzerStatus.COMPLETED, AnalyzerStatus.FAILED]:
                iter_text = str(progress.iteration) if progress.iteration > 0 else "-"

            current_tool = progress.current_tool or "-"
            last_result = (progress.last_result or self._fallback_message(progress))[:120]
            last_error = ((progress.last_error or "").replace("\n", " "))[:120] or "-"

            table.add_row(
                progress.display_name or analyzer_id,
                status_text,
                progress.phase,
                current_tool,
                last_result,
                last_error,
                iter_text,
                self._format_time(progress.elapsed_time),
            )

        return table

    def _generate_detail_panel(self):
        """生成焦点分析器详情面板。"""
        analyzer_id, progress = self._get_focus_progress()
        if progress is None:
            return Panel("暂无详情", title="分析器详情", border_style="dim")

        detail_lines = [
            f"分析器: {progress.display_name or analyzer_id}",
            f"状态: {progress.status.value} | 阶段: {progress.phase or '-'} | 当前工具: {progress.current_tool or '-'}",
            f"Checker: {progress.checker_name or '-'}",
            f"输出: {progress.output_path or '-'}",
            f"验证: {progress.validation_summary or '-'}",
            f"最近结果: {progress.last_result or '-'}",
            f"最近错误: {(progress.last_error or '-').replace(chr(10), ' ')}",
            "",
            "最近事件:",
        ]

        events = progress.recent_events[-5:] if progress.recent_events else ["-"]
        for item in events:
            detail_lines.append(f"- {item}")

        return Panel(
            "\n".join(detail_lines),
            title="分析器详情",
            border_style="cyan" if progress.status == AnalyzerStatus.RUNNING else "dim",
        )

    def _get_focus_progress(self):
        """获取当前焦点分析器，优先最近活跃的分析器。"""
        with self._lock:
            if self._focused_analyzer and self._focused_analyzer in self.analyzers:
                return self._focused_analyzer, self.analyzers[self._focused_analyzer]

            if not self.analyzers:
                return None, None

            analyzer_id, progress = max(
                self.analyzers.items(),
                key=lambda item: item[1].last_update,
            )
            return analyzer_id, progress

    def _fallback_message(self, progress: AnalyzerProgress) -> str:
        """消息兜底，防止并行阶段出现空白消息列。"""
        if progress.status == AnalyzerStatus.PENDING:
            return "工具: 等待中"
        if progress.status == AnalyzerStatus.RUNNING:
            if progress.phase == "执行工具":
                return "工具: 执行中"
            return "工具: 等待中"
        if progress.status == AnalyzerStatus.COMPLETED:
            return "工具: 已完成"
        if progress.status == AnalyzerStatus.FAILED:
            return "工具: 失败"
        return ""

    def _push_message(self, progress: AnalyzerProgress, message: str):
        """追加消息并保留最近多条，供表格多行展示。"""
        msg = (message or "").strip()
        if not msg:
            return

        # 阶段占位消息不进入历史，避免挤占可见空间
        # （阶段状态已在“阶段”列体现）
        if msg.startswith("🤔 思考中") or msg.startswith("LLM调用(工具):"):
            return

        # 迭代内标记类消息去重：仅保留一条“思考中”与一条“LLM调用”
        if msg.startswith("🤔 思考中"):
            progress.message_history = [
                m for m in progress.message_history
                if not m.startswith("🤔 思考中")
            ]
        elif msg.startswith("LLM调用(工具):"):
            progress.message_history = [
                m for m in progress.message_history
                if not m.startswith("LLM调用(工具):")
            ]

        # 避免连续重复刷屏
        if progress.message_history and progress.message_history[-1] == msg:
            progress.message = "\n".join(progress.message_history[-8:])
            return

        progress.message_history.append(msg)
        if len(progress.message_history) > 24:
            progress.message_history = progress.message_history[-24:]

        progress.message = "\n".join(progress.message_history[-10:])

    def _append_recent_event(self, progress: AnalyzerProgress, message: str):
        """记录最近关键事件，供详情面板展示。"""
        msg = (message or "").strip()
        if not msg:
            return
        if progress.recent_events and progress.recent_events[-1] == msg:
            return
        progress.recent_events.append(msg)
        if len(progress.recent_events) > 12:
            progress.recent_events = progress.recent_events[-12:]

    def _generate_footer(self) -> Text:
        """生成底部状态"""
        text = Text()

        with self._lock:
            progresses = list(self.analyzers.values())

        completed = sum(
            1 for p in progresses
            if p.status == AnalyzerStatus.COMPLETED
        )
        failed = sum(
            1 for p in progresses
            if p.status == AnalyzerStatus.FAILED
        )
        running = sum(
            1 for p in progresses
            if p.status == AnalyzerStatus.RUNNING
        )

        parts = []
        if running > 0:
            parts.append(f"[cyan]运行中: {running}[/cyan]")
        if completed > 0:
            parts.append(f"[green]完成: {completed}[/green]")
        if failed > 0:
            parts.append(f"[red]失败: {failed}[/red]")

        if parts:
            text.append(" | ".join(parts))
        else:
            text.append("等待开始...", style="dim")

        return text

    def _print_header_simple(self):
        """简单模式打印头部"""
        self._simple_print("\n" + "=" * 60)
        self._simple_print("检测器生成")
        self._simple_print("=" * 60)

    def _print_update_simple(
        self,
        progress: AnalyzerProgress,
        event_type: str,
        event: Dict[str, Any]
    ):
        """简单模式打印更新"""
        icon = self.STATUS_ICONS[progress.status]
        elapsed = self._format_time(progress.elapsed_time)

        if not self._should_print_simple_event(event_type, event):
            return

        self._simple_print(f"\n{icon} [{progress.display_name}] {progress.phase} ({elapsed})")

        if event_type == "pipeline_completed":
            if progress.success:
                self._simple_print(f"   ✅ 生成成功: {event.get('checker_name', '')}")
            else:
                self._simple_print("   ❌ 生成失败")
        elif event_type == "pipeline_failed":
            self._simple_print(f"   错误: {event.get('error', '')}")
        elif event_type == "validation_completed":
            summary = progress.validation_summary or progress.last_result or "-"
            self._simple_print(f"   验证: {summary}")
        elif event_type == "validation_feedback_attached":
            feedback_summary = str(event.get("summary", "") or "").strip()
            if not feedback_summary:
                feedback_summary = f"records={event.get('records', 0)}"
            self._simple_print(f"   反馈: {feedback_summary}")
        elif event_type == "portfolio_resolved":
            self._simple_print(f"   首选: {event.get('preferred_analyzer', '')} | {event.get('summary', '')}")
        elif event_type == "refinement_iteration_started":
            self._simple_print(f"   轮次: {event.get('iteration', 0)}")
        elif event_type == "refinement_iteration_completed":
            verdict = "采用候选" if event.get("adopted") else "保留基线"
            self._simple_print(f"   轮次: {event.get('iteration', 0)} | {verdict} | success={bool(event.get('success', False))}")
        elif event_type == "refinement_iteration_skipped":
            self._simple_print(f"   跳过: {str(event.get('reason', '') or '基线已满足严格精炼质量门')}")
        elif event_type == "agent_run_started":
            patch_path = str(event.get("patch_path", "") or "").strip()
            target_path = str(event.get("target_path", "") or "").strip()
            if patch_path:
                self._simple_print(f"   patch: {patch_path}")
            if target_path:
                self._simple_print(f"   target: {target_path}")
        elif event_type == "agent_run_completed":
            error_message = str(event.get("error_message", "") or "").strip()
            self._simple_print(
                "   智能体: "
                f"success={bool(event.get('success', False))} | "
                f"iterations={int(event.get('iterations', 0) or 0)} | "
                f"compile_attempts={int(event.get('compile_attempts', 0) or 0)}"
            )
            if error_message:
                self._simple_print(f"   错误: {error_message}")
        elif event_type == "agent_decision_completed":
            action = str(event.get("action", "") or "").strip()
            summary = str(event.get("summary", "") or "").strip()
            self._simple_print(f"   决策: {action or '-'} | {summary or '-'}")
        elif event_type == "agent_decision_parse_failed":
            error = str(event.get("error", "") or "").strip()
            raw_preview = str(event.get("raw_preview", "") or "").strip()
            self._simple_print(f"   决策解析失败: {error or '-'}")
            if raw_preview:
                self._simple_print(f"   原始预览: {raw_preview[:180]}")
        elif event_type == "agent_tool_called":
            tool_name = str(event.get("tool_name", "") or "").strip()
            args_preview = str(event.get("args_preview", "") or "").strip()
            self._simple_print(f"   调用: {tool_name or '-'}")
            if args_preview:
                self._simple_print(f"   参数: {args_preview}")
        elif event_type == "agent_tool_result":
            tool_name = str(event.get("tool_name", "") or "").strip()
            success = bool(event.get("success", False))
            summary = str(event.get("summary", "") or "").strip()
            error = str(event.get("error", "") or "").strip()
            self._simple_print(f"   结果: {tool_name or '-'} | {'OK' if success else 'FAIL'}")
            if summary:
                self._simple_print(f"   摘要: {summary}")
            elif error:
                self._simple_print(f"   错误: {error}")

    def _should_print_simple_event(self, event_type: str, event: Dict[str, Any]) -> bool:
        important_events = {
            "pipeline_started",
            "pipeline_completed",
            "pipeline_failed",
            "generation_completed",
            "validation_completed",
            "validation_feedback_attached",
            "portfolio_resolved",
            "refinement_iteration_started",
            "refinement_iteration_completed",
            "refinement_iteration_skipped",
            "agent_run_started",
            "agent_run_completed",
            "agent_decision_completed",
            "agent_decision_parse_failed",
        }
        if event_type in important_events:
            return True
        if event_type == "agent_tool_called":
            tool_name = str(event.get("tool_name", "") or "").strip()
            return tool_name in self.SIMPLE_DEBUG_TOOLS
        if event_type == "agent_tool_result":
            tool_name = str(event.get("tool_name", "") or "").strip()
            success = bool(event.get("success", True))
            return (not success) or tool_name in self.SIMPLE_DEBUG_TOOLS
        return False

    def _format_time(self, seconds: float) -> str:
        """格式化时间"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return f"{m}m{s}s"
        else:
            h, m = divmod(int(seconds) // 60, 60)
            return f"{h}h{m}m"

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def print_summary(self):
        """打印总结"""
        if self._live:
            # Rich 模式：停止 Live 并打印总结
            self.stop()

        self._simple_print("\n" + "=" * 60)
        self._simple_print("执行总结")
        self._simple_print("=" * 60)

        total_time = time.time() - self._start_time
        self._simple_print(f"总耗时: {self._format_time(total_time)}")

        with self._lock:
            analyzer_items = list(self.analyzers.items())

        for analyzer_id, progress in analyzer_items:
            icon = self.STATUS_ICONS[progress.status]
            status = "成功" if progress.success else "失败"
            self._simple_print(f"\n{icon} {progress.display_name}:")
            self._simple_print(f"   状态: {status}")
            self._simple_print(f"   迭代: {progress.iteration}")
            self._simple_print(f"   耗时: {self._format_time(progress.elapsed_time)}")

            if progress.message and progress.status == AnalyzerStatus.FAILED:
                self._simple_print(f"   错误: {progress.message}")

    def _simple_print(self, text: str):
        print(text, flush=True)
