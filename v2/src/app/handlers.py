"""
CLI 命令处理器
"""

import json
import subprocess
import sys
import time
from pathlib import Path

from loguru import logger

from .runtime import print_banner, resolve_config_path
from ..utils.cli_generate_helpers import (
    build_failure_context_lines,
    build_generate_followup_lines,
    build_generation_summary_lines,
    should_use_live_table,
    print_validation_result,
)
from ..validation import infer_analyzer_from_artifact


def _normalize_validate_path(validate_path):
    if validate_path and not Path(validate_path).exists():
        logger.warning(f"验证路径不存在，将跳过验证: {validate_path}")
        return None
    if validate_path:
        return str(Path(validate_path).expanduser().resolve())
    return None


def _normalize_existing_dir(path_value, label: str):
    if not path_value:
        return None
    candidate = Path(path_value).expanduser().resolve()
    if not candidate.exists():
        logger.warning(f"{label}不存在，将忽略: {path_value}")
        return None
    if not candidate.is_dir():
        logger.warning(f"{label}不是目录，将忽略: {path_value}")
        return None
    return str(candidate)


def _configure_generation_logging(args, analyzer: str):
    auto_selected = analyzer == "auto"
    use_live_table = should_use_live_table(
        analyzer_choice=analyzer,
        auto_selected=auto_selected,
        verbose=args.verbose,
        no_live=getattr(args, "no_live", False),
    )
    if use_live_table:
        logger.remove()
        logger.add(
            sys.stderr,
            level="ERROR",
            format="<red>{level}: {message}</red>",
            colorize=True,
        )
    elif auto_selected:
        logger.info("智能选择分析器: 运行时由模型决策")
    return use_live_table


def cmd_generate(args):
    """生成检测器命令。"""
    from ..core import Orchestrator
    from ..display import LiveProgressTable
    from ..utils.error_formatters import ErrorMessageFormatter

    print_banner()

    if not Path(args.patch).exists():
        logger.error(f"补丁文件不存在: {args.patch}")
        return 1
    patch_path = str(Path(args.patch).expanduser().resolve())

    analyzer = getattr(args, "analyzer", "auto")
    validate_path = _normalize_validate_path(getattr(args, "validate_path", None))
    use_live_table = _configure_generation_logging(args, analyzer)

    config_path = resolve_config_path(args.config, __file__)
    if config_path:
        logger.info(f"使用配置文件: {config_path}")
    else:
        logger.warning("未找到配置文件，使用默认配置")

    orchestrator = Orchestrator(
        config_path=config_path,
        analyzer=analyzer,
    )
    live_progress = LiveProgressTable(verbose=args.verbose, use_rich=use_live_table)
    output_root = Path(args.output or "./output").expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    event_log_path = output_root / "run_events.jsonl"

    def on_progress(event_or_task_id, status_or_event=None, **kwargs):
        event_payload = None
        if isinstance(event_or_task_id, dict):
            event_payload = dict(event_or_task_id)
            live_progress.update(event_payload)
        elif isinstance(status_or_event, str):
            analyzer_name = kwargs.get("analyzer", "unknown")
            event_type = kwargs.get("event", status_or_event)
            event_payload = {
                "analyzer": analyzer_name,
                "event": event_type,
                **kwargs,
            }
            live_progress.update(event_payload)
        else:
            event_payload = {
                "analyzer": event_or_task_id,
                "event": status_or_event,
                **kwargs,
            }
            live_progress.update(event_payload)

        if event_payload is None:
            return
        if "timestamp" not in event_payload:
            event_payload["timestamp"] = time.time()
        try:
            with event_log_path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(event_payload, ensure_ascii=False) + "\n")
        except Exception:
            pass

    live_progress.start()
    start_time = time.time()
    try:
        result = orchestrator.generate(
            patch_path,
            args.output,
            validate_path,
            on_progress=on_progress,
        )
    finally:
        live_progress.stop()
        if args.verbose and not use_live_table:
            live_progress.print_summary()

    try:
        orchestrator.save_result(result, args.output or "./output")
    except Exception as exc:
        logger.warning(f"保存结果报告失败: {exc}")

    elapsed = time.time() - start_time
    report_path = output_root / "final_report.json"

    if result.success:
        print(f"\n{'=' * 60}")
        print("✅ 检测器已生成并通过功能验证")
        print(f"{'=' * 60}")
        print(f"  耗时: {elapsed:.2f}秒")
        for line in build_generation_summary_lines(result, args.output or "./output"):
            print(line)
        for line in build_generate_followup_lines(result, args.output or "./output"):
            print(line)

        print_validation_result(getattr(result, "validation_result", None), analyzer)
        return 0

    print(f"\n{'=' * 60}")
    if getattr(result, "generation_success", False):
        print("⚠️ 检测器已生成，但未通过功能验证")
    else:
        print("❌ 检测器生成失败!")
    print(f"{'=' * 60}")
    error_msg = ErrorMessageFormatter.format_error(
        result.error_message,
        context={
            "补丁文件": args.patch,
            "迭代次数": result.total_iterations,
            "耗时": f"{elapsed:.2f}秒",
        },
    )
    print(error_msg)
    for line in build_failure_context_lines(result):
        print(line)
    print_validation_result(getattr(result, "validation_result", None), analyzer)
    print(f"\n  整合报告: {report_path}")
    return 1


def cmd_evidence(args):
    """独立证据收集命令。"""
    from ..core import Orchestrator
    from ..display import LiveProgressTable

    print_banner()

    if not Path(args.patch).exists():
        logger.error(f"补丁文件不存在: {args.patch}")
        return 1
    if not Path(args.evidence_dir).exists():
        logger.error(f"证据收集目录不存在: {args.evidence_dir}")
        return 1

    patch_path = str(Path(args.patch).expanduser().resolve())
    evidence_dir = str(Path(args.evidence_dir).expanduser().resolve())
    analyzer = getattr(args, "analyzer", "auto")
    use_live_table = _configure_generation_logging(args, analyzer)

    config_path = resolve_config_path(args.config, __file__)
    if config_path:
        logger.info(f"使用配置文件: {config_path}")
    else:
        logger.warning("未找到配置文件，使用默认配置")

    orchestrator = Orchestrator(
        config_path=config_path,
        analyzer=analyzer,
    )
    live_progress = LiveProgressTable(verbose=args.verbose, use_rich=use_live_table)
    output_root = Path(args.output or "./evidence_output").expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    event_log_path = output_root / "run_events.jsonl"

    def on_progress(event_or_task_id, status_or_event=None, **kwargs):
        event_payload = None
        if isinstance(event_or_task_id, dict):
            event_payload = dict(event_or_task_id)
            live_progress.update(event_payload)
        elif isinstance(status_or_event, str):
            analyzer_name = kwargs.get("analyzer", "unknown")
            event_type = kwargs.get("event", status_or_event)
            event_payload = {
                "analyzer": analyzer_name,
                "event": event_type,
                **kwargs,
            }
            live_progress.update(event_payload)
        else:
            event_payload = {
                "analyzer": event_or_task_id,
                "event": status_or_event,
                **kwargs,
            }
            live_progress.update(event_payload)

        if event_payload is None:
            return
        if "timestamp" not in event_payload:
            event_payload["timestamp"] = time.time()
        try:
            with event_log_path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(event_payload, ensure_ascii=False) + "\n")
        except Exception:
            pass

    live_progress.start()
    start_time = time.time()
    try:
        result = orchestrator.collect_evidence(
            patch_path=patch_path,
            evidence_dir=evidence_dir,
            output_dir=str(output_root),
            analyzer=analyzer,
            on_progress=on_progress,
        )
    finally:
        live_progress.stop()
        if args.verbose and not use_live_table:
            live_progress.print_summary()

    elapsed = time.time() - start_time
    manifest_path = Path(result.artifacts.get("manifest", "") or output_root / "evidence_manifest.json")

    if result.success:
        print(f"\n{'=' * 60}")
        print("✅ 证据收集完成")
        print(f"{'=' * 60}")
        print(f"  耗时: {elapsed:.2f}秒")
        print(f"  Patch: {patch_path}")
        print(f"  证据源码目录: {evidence_dir}")
        print(f"  输出目录: {output_root}")
        print(f"  分析器: {result.analyzer_type or analyzer}")
        for analyzer_id, payload in (result.analyzer_results or {}).items():
            if not isinstance(payload, dict):
                continue
            print(
                f"  - {analyzer_id}: records={payload.get('evidence_records', 0)}, "
                f"missing={len(payload.get('missing_evidence', []) or [])}, "
                f"bundle={payload.get('evidence_bundle_path', '')}"
            )
        print(f"  Manifest: {manifest_path}")
        print(f"  事件日志: {event_log_path}")
        return 0

    print(f"\n{'=' * 60}")
    print("❌ 证据收集失败!")
    print(f"{'=' * 60}")
    print(f"错误: {result.error_message}")
    print(f"  Patch: {patch_path}")
    print(f"  证据源码目录: {evidence_dir}")
    print(f"  输出目录: {output_root}")
    return 1


def cmd_refine(args):
    """基于已有输出执行纯精炼。"""
    from ..core import Orchestrator
    from ..display import LiveProgressTable
    from ..utils.error_formatters import ErrorMessageFormatter

    print_banner()

    if not Path(args.input).exists():
        logger.error(f"输入目录不存在: {args.input}")
        return 1

    analyzer = getattr(args, "analyzer", None)
    use_live_table = _configure_generation_logging(args, analyzer or "")

    config_path = resolve_config_path(args.config, __file__)
    if config_path:
        logger.info(f"使用配置文件: {config_path}")
    else:
        logger.warning("未找到配置文件，使用默认配置")

    orchestrator = Orchestrator(
        config_path=config_path,
        analyzer=analyzer or "auto",
    )
    live_progress = LiveProgressTable(verbose=args.verbose, use_rich=use_live_table)
    run_id = time.strftime("%Y%m%d_%H%M%S")
    output_root = Path(args.input).expanduser().resolve() / "refinements" / run_id
    output_root.mkdir(parents=True, exist_ok=True)
    event_log_path = output_root / "run_events.jsonl"
    normalized_validate_path = _normalize_validate_path(getattr(args, "validate_path", None))
    evidence_input = _normalize_existing_dir(getattr(args, "evidence_input", None), "证据输出目录")
    auto_evidence_manifest = Path(args.input).expanduser().resolve() / "evidence_manifest.json"
    if not evidence_input and auto_evidence_manifest.exists():
        evidence_input = str(Path(args.input).expanduser().resolve())

    print(f"输入目录: {Path(args.input).expanduser().resolve()}", flush=True)
    print(f"分析器: {analyzer or 'auto-from-session'}", flush=True)
    print(f"验证路径: {normalized_validate_path or '沿用会话中的验证路径'}", flush=True)
    print(f"证据输入目录: {evidence_input or '未提供'}", flush=True)
    print(f"精炼输出目录: {output_root}", flush=True)
    print(f"事件日志: {event_log_path}", flush=True)

    def on_progress(event_or_task_id, status_or_event=None, **kwargs):
        event_payload = None
        if isinstance(event_or_task_id, dict):
            event_payload = dict(event_or_task_id)
            live_progress.update(event_payload)
        elif isinstance(status_or_event, str):
            analyzer_name = kwargs.get("analyzer", "unknown")
            event_type = kwargs.get("event", status_or_event)
            event_payload = {
                "analyzer": analyzer_name,
                "event": event_type,
                **kwargs,
            }
            live_progress.update(event_payload)
        else:
            event_payload = {
                "analyzer": event_or_task_id,
                "event": status_or_event,
                **kwargs,
            }
            live_progress.update(event_payload)

        if event_payload is None:
            return
        if "timestamp" not in event_payload:
            event_payload["timestamp"] = time.time()
        try:
            with event_log_path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(event_payload, ensure_ascii=False) + "\n")
        except Exception:
            pass

    live_progress.start()
    start_time = time.time()
    try:
        result = orchestrator.refine(
            input_dir=args.input,
            validate_path=normalized_validate_path,
            patch_path=getattr(args, "patch", None),
            evidence_input_dir=evidence_input,
            analyzer=analyzer,
            on_progress=on_progress,
            run_id=run_id,
        )
    finally:
        live_progress.stop()
        if args.verbose and not use_live_table:
            live_progress.print_summary()

    try:
        orchestrator.save_result(result, args.input)
    except Exception as exc:
        logger.warning(f"保存结果报告失败: {exc}")

    elapsed = time.time() - start_time
    report_root = Path(getattr(result, "report_output_dir", "") or output_root)
    report_path = report_root / "final_report.json"

    if result.success:
        print(f"\n{'=' * 60}")
        print("✅ 检测器精炼完成")
        print(f"{'=' * 60}")
        print(f"  耗时: {elapsed:.2f}秒")
        for line in build_generation_summary_lines(result, str(report_root)):
            print(line)
        print_validation_result(getattr(result, "validation_result", None), analyzer or "")
        print(f"  事件日志: {event_log_path}")
        print(f"  整合报告: {report_path}")
        return 0

    print(f"\n{'=' * 60}")
    if getattr(result, "generation_success", False):
        print("⚠️ 精炼已执行，但结果未优于当前基线或未通过功能验证")
    else:
        print("❌ 精炼失败!")
    print(f"{'=' * 60}")
    error_msg = ErrorMessageFormatter.format_error(
        result.error_message,
        context={
            "输入目录": args.input,
            "验证路径": getattr(result, "validate_path", "") or "未提供",
            "迭代次数": result.total_iterations,
            "耗时": f"{elapsed:.2f}秒",
        },
    )
    print(error_msg)
    for line in build_failure_context_lines(result):
        print(line)
    print_validation_result(getattr(result, "validation_result", None), analyzer or "")
    print(f"  事件日志: {event_log_path}")
    print(f"\n  整合报告: {report_path}")
    return 1


def cmd_experiment(args):
    """实验管理命令。"""
    from ..experiments import (
        audit_manifest,
        default_experiment_root,
        init_experiment_root,
        rebuild_table_exports,
        run_experiments,
    )

    print_banner()

    root = getattr(args, "root", None)
    action = getattr(args, "action", "")
    config_path = resolve_config_path(args.config, __file__)

    if action == "init":
        layout = init_experiment_root(root=root, force=bool(getattr(args, "force", False)))
        print("✅ 实验目录已初始化")
        print(f"  根目录: {layout.root}")
        print(f"  样本清单: {layout.manifest_path}")
        print(f"  结果表格: {layout.tables_dir}")
        return 0

    if action == "audit":
        result = audit_manifest(
            root=root,
            manifest_path=getattr(args, "manifest", None),
            sample_id=getattr(args, "sample_id", None),
        )
        print("✅ 样本审查完成")
        print(f"  根目录: {result['root']}")
        print(f"  审查样本数: {result['audited']}")
        return 0

    if action == "run":
        result = run_experiments(
            root=root,
            manifest_path=getattr(args, "manifest", None),
            config_path=config_path,
            sample_id=getattr(args, "sample_id", None),
            run_all=bool(getattr(args, "all", False)),
            generate_only=bool(getattr(args, "generate_only", False)),
        )
        print("✅ 实验运行完成")
        print(f"  根目录: {result['root']}")
        print(f"  选中样本数: {result['selected']}")
        print(f"  执行生成次数: {result['executed']}")
        return 0

    if action == "summarize":
        result = rebuild_table_exports(root=root or str(default_experiment_root()))
        print("✅ 实验表格已重建 Markdown 导出")
        print(f"  根目录: {result['root']}")
        return 0

    logger.error(f"未知实验操作: {action}")
    return 1


def cmd_validate(args):
    """验证检测器命令。"""
    from ..validation.unified_validator import UnifiedValidator, AnalyzerType

    print_banner()

    if not Path(args.checker).exists():
        logger.error(f"检测器文件不存在: {args.checker}")
        return 1
    if not Path(args.target).exists():
        logger.error(f"目标路径不存在: {args.target}")
        return 1

    analyzer = infer_analyzer_from_artifact(args.checker, args.analyzer)

    print(f"检测器: {args.checker}")
    print(f"目标路径: {args.target}")
    print(f"分析器类型: {analyzer.value}")
    print()

    validator = UnifiedValidator({
        "lsp": {"timeout": 30},
        "semantic": {"timeout": 120},
    })

    if analyzer == AnalyzerType.CSA:
        result = validator.semantic_validator.validate_csa_checker(
            checker_so_path=args.checker,
            checker_name=args.checker_name or "custom.Checker",
            target_path=args.target,
        )
    else:
        result = validator.semantic_validator.validate_codeql_query(
            query_path=args.checker,
            database_path=args.database or "./codeql_db",
            target_path=args.target,
        )

    print(f"\n{'=' * 50}")
    if result.success:
        print("✅ 验证成功")
    else:
        print("❌ 验证失败")
        print(f"错误: {result.error_message}")

    if result.diagnostics:
        print(f"\n发现 {len(result.diagnostics)} 个问题:")
        for diagnostic in result.diagnostics[:10]:
            print(f"  - {diagnostic.file_path}:{diagnostic.line}: [{diagnostic.severity}] {diagnostic.message}")

    print(f"执行时间: {result.execution_time:.2f}秒")
    return 0 if result.success else 1


def cmd_knowledge(args):
    """知识库命令。"""
    from ..knowledge import get_knowledge_base

    kb = get_knowledge_base()

    if args.action == "status":
        if kb.initialize():
            logger.info("知识库连接成功")
            logger.info(f"文档数: {kb.collection.count()}")
            return 0
        logger.error("知识库连接失败")
        return 1

    if args.action == "search":
        if not kb.initialize():
            logger.error("知识库初始化失败")
            return 1
        results = kb.search(args.query, top_k=args.top_k)
        for index, result in enumerate(results, start=1):
            print(f"\n--- 结果 {index} ---")
            print(result["content"][:500])
        return 0

    script_path = Path(__file__).parent.parent.parent / "scripts" / "import_knowledge.py"
    if not script_path.exists():
        logger.error(f"导入脚本不存在: {script_path}")
        return 1

    command = [sys.executable, str(script_path)]
    if args.clear:
        command.append("--clear-only")
    if args.csa_only:
        command.append("--csa-only")
    if args.codeql_only:
        command.append("--codeql-only")
    return subprocess.run(command).returncode


def cmd_test(args):
    """测试命令。"""
    logger.info("运行测试...")

    if getattr(args, "all", False):
        args.test_llm = True
        args.test_kb = True
        args.test_validator = True

    if args.test_llm:
        from ..llm import get_llm_client
        from ..utils import load_config

        config = load_config("config/config.yaml")
        client = get_llm_client(config.get("llm", {}))
        response = client.generate("你好，请简单回复")
        if response:
            logger.success(f"LLM测试成功: {response[:100]}")
        else:
            logger.error("LLM测试失败")

    if args.test_kb:
        from ..knowledge import get_knowledge_base
        from ..utils import load_config

        config = load_config("config/config.yaml")
        kb = get_knowledge_base(config.get("knowledge_base", {}))
        if kb.initialize():
            logger.success("知识库连接成功")
        else:
            logger.error("知识库连接失败")

    if args.test_validator:
        from ..validation.unified_validator import UnifiedValidator

        logger.info("测试验证器...")
        UnifiedValidator()
        logger.success("验证器初始化成功")

    return 0


def cmd_mcp(args):
    """MCP 标准化工具命令。"""
    from ..mcp_adapter import build_default_mcp_service

    service = build_default_mcp_service(config_path=args.config)

    if args.action == "list-tools":
        print(json.dumps({"tools": service.list_tools()}, indent=2, ensure_ascii=False))
        return 0

    if args.action == "call":
        if not args.tool:
            logger.error("请通过 --tool 指定工具名称")
            return 1
        arguments = {}
        if args.args_json:
            try:
                arguments = json.loads(args.args_json)
            except json.JSONDecodeError as exc:
                logger.error(f"--args-json 不是合法JSON: {exc}")
                return 1
        response = service.call_tool(args.tool, arguments)
        print(json.dumps(response, indent=2, ensure_ascii=False))
        return 0 if not response.get("isError", False) else 2

    manifest = service.export_manifest()
    output_path = Path(args.output or "./output/mcp_tools_manifest.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.success(f"MCP工具清单已导出: {output_path}")
    return 0
