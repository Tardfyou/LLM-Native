"""
统一 diff/patch 编辑工具。

优先使用成熟库处理单文件 unified diff：
- `unidiff` 负责解析和校验 patch 结构
- `patch-ng` 可用时负责标准补丁应用
- `diff-match-patch` 在提供 `resulting_content` 时做最终一致性回退

同时保留轻量的 hunk relocation 兜底，覆盖行号漂移和空白字符轻微漂移场景。
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from diff_match_patch import diff_match_patch
from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from ..agent.tools import Tool, ToolResult

try:
    import patch_ng
except ModuleNotFoundError:  # pragma: no cover - exercised via fallback tests
    patch_ng = None


@dataclass(frozen=True)
class _AppliedPatch:
    content: str
    hunk_count: int
    engine: str
    note: str = ""


@dataclass(frozen=True)
class _ParsedUnifiedHunk:
    preferred_index: Optional[int]
    lines: List[str]


class ApplyPatchTool(Tool):
    """将 unified diff 应用到单个文本文件。"""

    _WORKSPACE_FILE = "__artifact__"
    _HUNK_HEADER_RE = re.compile(
        r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
    )
    _STRICT_HUNK_HEADER_RE = re.compile(
        r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<suffix>.*)$"
    )
    _LOOSE_UNIFIED_HUNK_HEADER_RE = re.compile(r"^@@(?:\s.*)?$")
    _CODEX_HUNK_HEADER_RE = re.compile(r"^@@(?:\s.*)?$")

    def __init__(self, work_dir: str = None, save_versions: bool = True):
        self.work_dir = work_dir
        self.save_versions = save_versions
        self._version_count = 0

    @property
    def name(self) -> str:
        return "apply_patch"

    @property
    def description(self) -> str:
        return """将 unified diff / git diff 形式的补丁应用到单个文本文件。
适用于 refine 阶段的最小增量编辑，而不是整文件重写。
可以从 source_path 读取基线内容，并将补丁结果写入 target_path。"""

    @property
    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "补丁应用后的输出文件路径"
                },
                "patch": {
                    "type": "string",
                    "description": "单文件 unified diff / git diff 文本，必须包含 @@ hunk"
                },
                "source_path": {
                    "type": "string",
                    "description": "可选，补丁的基线文件路径；未提供时默认对 target_path 原地打补丁"
                },
                "resulting_content": {
                    "type": "string",
                    "description": "可选，调用方预期的补丁结果文本；提供后会做一致性校验"
                },
                "is_final": {
                    "type": "boolean",
                    "default": False,
                    "description": "是否是最终版本（如果是，不保存版本备份）"
                }
            },
            "required": ["target_path", "patch"]
        }

    def set_work_dir(self, work_dir: str):
        self.work_dir = work_dir

    def execute(
        self,
        target_path: str,
        patch: str = "",
        source_path: str = None,
        resulting_content: str = None,
        is_final: bool = False,
    ) -> ToolResult:
        try:
            resolved_target = self._resolve_path(target_path)
            resolved_source = self._resolve_path(source_path or target_path)

            if not os.path.exists(resolved_source):
                return ToolResult(
                    success=False,
                    output="",
                    error=f"补丁基线文件不存在: {resolved_source}",
                )

            with open(resolved_source, "r", encoding="utf-8") as handle:
                original = handle.read()

            applied, attempt_errors = self._apply_best_effort(
                original=original,
                patch_text=patch or "",
                resulting_content=resulting_content,
            )

            patched = applied.content
            hunk_count = applied.hunk_count

            if patched == original:
                desired_text = resulting_content if isinstance(resulting_content, str) else ""
                if desired_text and desired_text != original:
                    patch_change_count = self._rough_patch_change_count(patch or "")
                    if self._resulting_content_within_patch_budget(original, desired_text, patch_change_count):
                        applied = self._apply_with_resulting_content(
                            original=original,
                            resulting_content=desired_text,
                            note=(
                                "主补丁虽成功解析，但未对当前文件产生实际修改；"
                                "已回退到 resulting_content 精确重建最终文本。"
                            ),
                        )
                        patched = applied.content
                        hunk_count = applied.hunk_count
                    else:
                        return ToolResult(
                            success=False,
                            output="",
                            error=(
                                "补丁未对文件产生任何实际修改，且 resulting_content 的改动范围显著超出原始 patch。"
                                " 请缩小 hunk、修正上下文，或提交更一致的 resulting_content。"
                            ),
                            metadata={
                                "engine": applied.engine,
                                "attempt_errors": attempt_errors,
                            },
                        )

            if patched == original:
                return ToolResult(
                    success=False,
                    output="",
                    error=(
                        "补丁未对文件产生任何实际修改。"
                        " 请缩小 hunk、修正上下文，或提供真正变化后的 resulting_content。"
                    ),
                    metadata={
                        "engine": applied.engine,
                        "attempt_errors": attempt_errors,
                    },
                )

            target_dir = os.path.dirname(resolved_target)
            if target_dir and not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)

            version_path = None
            if self.save_versions and not is_final:
                version_path = self._save_version(resolved_target, patched)

            with open(resolved_target, "w", encoding="utf-8") as handle:
                handle.write(patched)

            added_lines, removed_lines = self._count_diff_stats(original, patched)
            output = (
                f"补丁已应用: {resolved_target}\n"
                f"engine={applied.engine}, hunks={hunk_count}, +{added_lines}/-{removed_lines}"
            )
            if applied.note:
                output += f"\n说明: {applied.note}"
            if source_path and resolved_source != resolved_target:
                output += f"\n基线文件: {resolved_source}"
            if version_path:
                output += f"\n版本备份: {version_path}"

            return ToolResult(
                success=True,
                output=output,
                metadata={
                    "path": resolved_target,
                    "target_path": resolved_target,
                    "source_path": resolved_source,
                    "patched_content": patched,
                    "length": len(patched),
                    "lines": patched.count("\n") + (1 if patched else 0),
                    "hunks": hunk_count,
                    "added_lines": added_lines,
                    "removed_lines": removed_lines,
                    "engine": applied.engine,
                    "engine_note": applied.note,
                    "attempt_errors": attempt_errors,
                    "version_path": version_path,
                },
            )
        except Exception as exc:
            return ToolResult(
                success=False,
                output="",
                error=f"应用补丁失败: {exc}",
            )

    def _resolve_path(self, path: Optional[str]) -> str:
        token = str(path or "").strip()
        if not token:
            return ""
        if os.path.isabs(token) or not self.work_dir:
            return os.path.abspath(token)
        return os.path.abspath(os.path.join(self.work_dir, token))

    def _save_version(self, path: str, content: str) -> str:
        self._version_count += 1

        dir_path = os.path.dirname(path)
        versions_dir = os.path.join(dir_path, "versions")
        os.makedirs(versions_dir, exist_ok=True)

        base_name = os.path.basename(path)
        name, ext = os.path.splitext(base_name)
        version_name = f"{name}_patch_v{self._version_count:03d}{ext}"
        version_path = os.path.join(versions_dir, version_name)

        with open(version_path, "w", encoding="utf-8") as handle:
            handle.write(content)

        return version_path

    def _apply_best_effort(
        self,
        original: str,
        patch_text: str,
        resulting_content: Optional[str],
    ) -> Tuple[_AppliedPatch, List[str]]:
        attempt_errors: List[str] = []
        patch_text = str(patch_text or "")
        desired_text = resulting_content if isinstance(resulting_content, str) else ""
        patch_change_count = self._rough_patch_change_count(patch_text)

        applied: Optional[_AppliedPatch] = None
        prepared_patch: Optional[PatchSet] = None

        if patch_text.strip():
            if self._looks_like_codex_patch(patch_text):
                try:
                    patched, hunk_count = self._apply_codex_patch(original, patch_text)
                    applied = _AppliedPatch(
                        content=patched,
                        hunk_count=hunk_count,
                        engine="codex_patch",
                        note="检测到 Codex 风格补丁块，已按结构化 hunk 直接应用。",
                    )
                except Exception as exc:
                    attempt_errors.append(f"Codex 风格补丁应用失败: {exc}")

            try:
                if applied is None:
                    prepared_patch = self._parse_patch_with_unidiff(
                        patch_text=patch_text,
                        fallback_name=self._WORKSPACE_FILE,
                    )
            except Exception as exc:
                attempt_errors.append(str(exc))

            if prepared_patch is not None:
                if patch_ng is not None:
                    try:
                        applied = self._apply_with_patch_ng(original=original, patch_set=prepared_patch)
                    except Exception as exc:
                        attempt_errors.append(f"patch-ng 标准应用失败: {exc}")
                else:
                    attempt_errors.append("patch-ng 未安装，跳过标准补丁引擎")

            if applied is None:
                try:
                    patched, hunk_count = self._apply_unified_diff(original, patch_text)
                    applied = _AppliedPatch(
                        content=patched,
                        hunk_count=hunk_count,
                        engine="relocated_unified_diff",
                        note="patch-ng 失败后，使用行号漂移容忍模式完成补丁应用。",
                    )
                except Exception as exc:
                    attempt_errors.append(f"行号漂移容忍回退失败: {exc}")

            if applied is None:
                try:
                    patched, hunk_count = self._apply_unified_diff_sequential(original, patch_text)
                    applied = _AppliedPatch(
                        content=patched,
                        hunk_count=hunk_count,
                        engine="sequential_unified_diff",
                        note="标准补丁失败后，使用顺序上下文容忍模式完成补丁应用。",
                    )
                except Exception as exc:
                    attempt_errors.append(f"顺序上下文容忍回退失败: {exc}")
        else:
            attempt_errors.append("补丁内容为空")

        if desired_text and applied is None:
            if self._resulting_content_within_patch_budget(original, desired_text, patch_change_count):
                try:
                    applied = self._apply_with_resulting_content(
                        original=original,
                        resulting_content=desired_text,
                        note=(
                            "主补丁无法稳定应用，已基于 resulting_content 使用 "
                            "diff-match-patch 生成精确变更。"
                        ),
                    )
                except Exception as exc:
                    attempt_errors.append(f"diff-match-patch 回退失败: {exc}")
            else:
                attempt_errors.append(
                    "resulting_content 变更范围明显超出原始 patch，拒绝使用全文回退。"
                )

        if applied is None:
            raise ValueError(self._format_attempt_errors(attempt_errors))

        if desired_text and applied.content != desired_text:
            if self._resulting_content_within_patch_budget(original, desired_text, patch_change_count):
                try:
                    applied = self._apply_with_resulting_content(
                        original=original,
                        resulting_content=desired_text,
                        note=(
                            "标准补丁结果与 resulting_content 不一致，"
                            "已回退到 resulting_content 精确重建最终文本。"
                        ),
                    )
                except Exception as exc:
                    attempt_errors.append(f"resulting_content 一致性回退失败: {exc}")
                    raise ValueError(
                        "补丁结果与 resulting_content 不一致。"
                        " 请先基于同一版完整内容完成预检，再提交对应的 unified diff。"
                    )
            else:
                raise ValueError(
                    "补丁结果与 resulting_content 不一致，且 resulting_content 的改动范围显著超出原始 patch；"
                    "拒绝使用全文回退。"
                )
        return applied, attempt_errors

    def _looks_like_codex_patch(self, patch_text: str) -> bool:
        normalized = str(patch_text or "").lstrip()
        return normalized.startswith("*** Begin Patch")

    def _apply_codex_patch(self, original: str, patch_text: str) -> Tuple[str, int]:
        patch_lines = str(patch_text or "").replace("\r\n", "\n").replace("\r", "\n").splitlines()
        if not patch_lines:
            raise ValueError("补丁内容为空")
        if not patch_lines[0].startswith("*** Begin Patch"):
            raise ValueError("不是合法的 Codex 风格补丁块")

        hunks = self._parse_codex_hunks(patch_lines)
        if not hunks:
            raise ValueError("Codex 风格补丁中未找到有效的 @@ hunk")

        original_has_trailing_newline = original.endswith("\n")
        working_lines = original.splitlines()
        cursor = 0

        for hunk_lines in hunks:
            expected_old_lines = [
                raw_line[1:]
                for raw_line in hunk_lines
                if raw_line and raw_line[0] in {" ", "-"}
            ]
            old_index = self._locate_hunk_start(
                original_lines=working_lines,
                cursor=0,
                preferred_index=cursor,
                expected_old_lines=expected_old_lines,
            )

            replacement: List[str] = []
            consume_index = old_index

            for raw_line in hunk_lines:
                prefix = raw_line[0] if raw_line else " "
                payload = raw_line[1:] if raw_line else ""

                if prefix == " ":
                    actual_line = working_lines[consume_index] if consume_index < len(working_lines) else payload
                    consume_index = self._consume_expected_line(working_lines, consume_index, payload, "context")
                    replacement.append(actual_line)
                    continue
                if prefix == "-":
                    consume_index = self._consume_expected_line(working_lines, consume_index, payload, "deletion")
                    continue
                if prefix == "+":
                    replacement.append(payload)
                    continue
                raise ValueError(f"Codex 风格补丁包含不支持的行前缀: {prefix!r}")

            working_lines[old_index:consume_index] = replacement
            cursor = max(cursor, old_index + len(replacement))

        patched = "\n".join(working_lines)
        if working_lines and original_has_trailing_newline:
            patched += "\n"
        elif not working_lines and original_has_trailing_newline:
            patched = ""
        return patched, len(hunks)

    def _parse_codex_hunks(self, patch_lines: List[str]) -> List[List[str]]:
        hunks: List[List[str]] = []
        current: List[str] = []
        saw_update = False

        for line in patch_lines[1:]:
            if line.startswith("*** End Patch"):
                break
            if line.startswith("*** Update File: "):
                saw_update = True
                continue
            if line.startswith("*** Add File: ") or line.startswith("*** Delete File: "):
                raise ValueError("当前 apply_patch 仅支持单文件 Update File 补丁")
            if line.startswith("*** Move to: "):
                raise ValueError("当前 apply_patch 不支持 Move to 补丁")
            if line.startswith("*** End of File"):
                continue
            if self._CODEX_HUNK_HEADER_RE.match(line):
                if current:
                    hunks.append(current)
                    current = []
                continue
            if not line:
                raise ValueError("Codex 风格补丁 hunk 行缺少前缀")
            if line[0] not in {" ", "+", "-"}:
                raise ValueError(f"Codex 风格补丁 hunk 行缺少有效前缀: {line[:40]!r}")
            current.append(line)

        if current:
            hunks.append(current)
        if not saw_update:
            raise ValueError("Codex 风格补丁缺少 `*** Update File:` 头")
        return hunks

    def _parse_patch_with_unidiff(self, patch_text: str, fallback_name: str) -> PatchSet:
        normalized = self._normalize_patch_text(patch_text, fallback_name=fallback_name)
        try:
            patch_set = PatchSet(normalized)
        except UnidiffParseError as exc:
            raise ValueError(f"unidiff 解析失败: {exc}") from exc

        if len(patch_set) != 1:
            raise ValueError("apply_patch 仅支持单文件 unified diff。")

        patch_file = patch_set[0]
        if len(patch_file) <= 0:
            raise ValueError("补丁中未找到有效的 @@ hunk。")
        return patch_set

    def _normalize_patch_text(self, patch_text: str, fallback_name: str) -> str:
        normalized = str(patch_text or "").replace("\r\n", "\n").replace("\r", "\n")
        if not normalized.strip():
            raise ValueError("补丁内容为空")
        if "@@" not in normalized:
            raise ValueError("补丁中未找到有效的 @@ hunk。")

        has_headers = bool(
            re.search(r"^---\s+.+$", normalized, flags=re.MULTILINE)
            and re.search(r"^\+\+\+\s+.+$", normalized, flags=re.MULTILINE)
        )
        safe_name = Path(str(fallback_name or self._WORKSPACE_FILE)).name or self._WORKSPACE_FILE
        if not has_headers:
            normalized = f"--- a/{safe_name}\n+++ b/{safe_name}\n{normalized}"
        normalized = self._repair_hunk_header_counts(normalized)
        if not normalized.endswith("\n"):
            normalized += "\n"
        return normalized

    def _repair_hunk_header_counts(self, patch_text: str) -> str:
        lines = str(patch_text or "").splitlines()
        if not lines:
            return str(patch_text or "")

        repaired: List[str] = []
        index = 0

        while index < len(lines):
            line = lines[index]
            match = self._STRICT_HUNK_HEADER_RE.match(line)
            if not match:
                repaired.append(line)
                index += 1
                continue

            next_index = index + 1
            old_count = 0
            new_count = 0
            while next_index < len(lines):
                candidate = lines[next_index]
                if self._STRICT_HUNK_HEADER_RE.match(candidate) or self._LOOSE_UNIFIED_HUNK_HEADER_RE.match(candidate):
                    break
                if candidate.startswith(("diff --git ", "index ", "--- ", "+++ ")):
                    break

                prefix = candidate[:1]
                if prefix == "\\":
                    next_index += 1
                    continue
                if prefix in {" ", "-"}:
                    old_count += 1
                if prefix in {" ", "+"}:
                    new_count += 1
                next_index += 1

            old_start = int(match.group("old_start"))
            new_start = int(match.group("new_start"))
            suffix = str(match.group("suffix") or "")
            repaired.append(f"@@ -{old_start},{old_count} +{new_start},{new_count} @@{suffix}")
            repaired.extend(lines[index + 1:next_index])
            index = next_index

        return "\n".join(repaired)

    def _apply_with_patch_ng(self, original: str, patch_set: PatchSet) -> _AppliedPatch:
        if patch_ng is None:
            raise ValueError("patch-ng 未安装")
        rendered_patch = self._render_workspace_patch(patch_set)
        patch_obj = patch_ng.fromstring(rendered_patch.encode("utf-8"))
        if not patch_obj:
            raise ValueError("patch-ng 无法解析标准化后的补丁")

        with tempfile.TemporaryDirectory(prefix="apply_patch_") as tmpdir:
            workspace_file = Path(tmpdir) / self._WORKSPACE_FILE
            workspace_file.write_text(original, encoding="utf-8")
            applied = patch_obj.apply(root=tmpdir)
            if not applied:
                raise ValueError("patch-ng 未能匹配当前文件内容")
            patched = workspace_file.read_text(encoding="utf-8") if workspace_file.exists() else ""

        return _AppliedPatch(
            content=patched,
            hunk_count=len(patch_set[0]),
            engine="patch_ng",
        )

    def _render_workspace_patch(self, patch_set: PatchSet) -> str:
        rendered = str(patch_set[0]).replace("\r\n", "\n").replace("\r", "\n")
        lines = rendered.splitlines()
        if len(lines) < 3:
            raise ValueError("标准化补丁内容过短")
        lines[0] = f"--- a/{self._WORKSPACE_FILE}"
        lines[1] = f"+++ b/{self._WORKSPACE_FILE}"
        return "\n".join(lines) + "\n"

    def _apply_with_resulting_content(
        self,
        original: str,
        resulting_content: str,
        note: str = "",
    ) -> _AppliedPatch:
        dmp = diff_match_patch()
        dmp.Diff_Timeout = 0
        patches = dmp.patch_make(original, resulting_content)
        patched, applied = dmp.patch_apply(patches, original)
        if not all(applied):
            raise ValueError("diff-match-patch 未能完整应用生成的文本补丁")
        if patched != resulting_content:
            raise ValueError("diff-match-patch 输出与 resulting_content 不一致")
        return _AppliedPatch(
            content=patched,
            hunk_count=max(1, len(patches)),
            engine="diff_match_patch",
            note=note,
        )

    def _format_attempt_errors(self, errors: List[str]) -> str:
        details = [str(item).strip() for item in errors if str(item).strip()]
        if not details:
            return "未能将补丁应用到当前文件。"
        return "未能将补丁应用到当前文件: " + " | ".join(details)

    def _rough_patch_change_count(self, patch_text: str) -> int:
        count = 0
        for line in str(patch_text or "").splitlines():
            if line.startswith(("diff --git ", "index ", "--- ", "+++ ", "@@ ")):
                continue
            if line.startswith("@@"):
                continue
            if line[:1] in {"+", "-"}:
                count += 1
        return count

    def _resulting_content_within_patch_budget(
        self,
        original: str,
        resulting_content: str,
        patch_change_count: int,
    ) -> bool:
        if patch_change_count <= 0:
            return True
        added, removed = self._count_diff_stats(original, resulting_content)
        desired_change_count = added + removed
        if desired_change_count == 0:
            return True
        return desired_change_count <= max(24, patch_change_count * 3)

    def _apply_unified_diff(self, original: str, patch_text: str) -> Tuple[str, int]:
        patch_lines = (patch_text or "").splitlines()
        if not patch_lines:
            raise ValueError("补丁内容为空")

        original_has_trailing_newline = original.endswith("\n")
        original_lines = original.splitlines()

        hunks = self._parse_hunks(patch_lines)
        if not hunks:
            raise ValueError("补丁中未找到有效的 @@ hunk")

        result: List[str] = []
        cursor = 0

        for hunk in hunks:
            expected_old_lines = [
                raw_line[1:]
                for raw_line in hunk.lines
                if raw_line and raw_line[0] in {" ", "-"}
            ]
            old_index = self._locate_hunk_start(
                original_lines=original_lines,
                cursor=cursor,
                preferred_index=hunk.preferred_index if hunk.preferred_index is not None else cursor,
                expected_old_lines=expected_old_lines,
            )
            if old_index < cursor:
                raise ValueError("补丁 hunk 顺序非法或发生重叠")

            result.extend(original_lines[cursor:old_index])
            cursor = old_index

            for raw_line in hunk.lines:
                prefix = raw_line[0] if raw_line else " "
                payload = raw_line[1:] if raw_line else ""

                if prefix == "\\":
                    continue
                if prefix == " ":
                    cursor = self._consume_expected_line(original_lines, cursor, payload, "context")
                    result.append(payload)
                    continue
                if prefix == "-":
                    cursor = self._consume_expected_line(original_lines, cursor, payload, "deletion")
                    continue
                if prefix == "+":
                    result.append(payload)
                    continue
                raise ValueError(f"不支持的补丁行前缀: {prefix!r}")

        result.extend(original_lines[cursor:])
        patched = "\n".join(result)
        if result and original_has_trailing_newline:
            patched += "\n"
        elif not result and original_has_trailing_newline:
            patched = ""
        return patched, len(hunks)

    def _apply_unified_diff_sequential(self, original: str, patch_text: str) -> Tuple[str, int]:
        patch_lines = (patch_text or "").splitlines()
        if not patch_lines:
            raise ValueError("补丁内容为空")

        original_has_trailing_newline = original.endswith("\n")
        working_lines = original.splitlines()

        hunks = self._parse_hunks(patch_lines)
        if not hunks:
            raise ValueError("补丁中未找到有效的 @@ hunk")

        cursor = 0
        for hunk in hunks:
            expected_old_lines = [
                raw_line[1:]
                for raw_line in hunk.lines
                if raw_line and raw_line[0] in {" ", "-"}
            ]
            old_index = self._locate_hunk_start(
                original_lines=working_lines,
                cursor=0,
                preferred_index=hunk.preferred_index if hunk.preferred_index is not None else cursor,
                expected_old_lines=expected_old_lines,
            )

            replacement: List[str] = []
            consume_index = old_index

            for raw_line in hunk.lines:
                prefix = raw_line[0] if raw_line else " "
                payload = raw_line[1:] if raw_line else ""

                if prefix == "\\":
                    continue
                if prefix == " ":
                    actual_line = (
                        working_lines[consume_index]
                        if consume_index < len(working_lines)
                        else payload
                    )
                    consume_index = self._consume_expected_line(
                        working_lines,
                        consume_index,
                        payload,
                        "context",
                    )
                    replacement.append(actual_line)
                    continue
                if prefix == "-":
                    consume_index = self._consume_expected_line(
                        working_lines,
                        consume_index,
                        payload,
                        "deletion",
                    )
                    continue
                if prefix == "+":
                    replacement.append(payload)
                    continue
                raise ValueError(f"不支持的补丁行前缀: {prefix!r}")

            working_lines[old_index:consume_index] = replacement
            cursor = max(cursor, old_index + len(replacement))

        patched = "\n".join(working_lines)
        if working_lines and original_has_trailing_newline:
            patched += "\n"
        elif not working_lines and original_has_trailing_newline:
            patched = ""
        return patched, len(hunks)

    def _locate_hunk_start(
        self,
        original_lines: List[str],
        cursor: int,
        preferred_index: int,
        expected_old_lines: List[str],
    ) -> int:
        start_index = max(cursor, preferred_index)
        if self._matches_sequence(original_lines, start_index, expected_old_lines):
            return start_index

        exact_matches = self._find_sequence_matches(
            original_lines=original_lines,
            cursor=cursor,
            expected_old_lines=expected_old_lines,
            normalize_whitespace=False,
        )
        if exact_matches:
            if len(exact_matches) > 1 and start_index not in exact_matches:
                raise ValueError(
                    "hunk 上下文在文件中存在多个完全匹配位置，无法安全重定位；"
                    "请提供更具体的上下文行或更准确的行号。"
                )
            return min(exact_matches, key=lambda idx: (abs(idx - preferred_index), idx))

        normalized_matches = self._find_sequence_matches(
            original_lines=original_lines,
            cursor=cursor,
            expected_old_lines=expected_old_lines,
            normalize_whitespace=True,
        )
        if normalized_matches:
            if len(normalized_matches) > 1 and start_index not in normalized_matches:
                raise ValueError(
                    "hunk 上下文仅在忽略空白后出现多个候选位置，无法安全重定位；"
                    "请补充更稳定的上下文行。"
                )
            return min(normalized_matches, key=lambda idx: (abs(idx - preferred_index), idx))

        return start_index

    def _parse_hunks(self, patch_lines: List[str]) -> List[_ParsedUnifiedHunk]:
        hunks: List[_ParsedUnifiedHunk] = []
        current_preferred_index: Optional[int] = None
        current_lines: List[str] = []
        in_hunk = False

        for line in patch_lines:
            match = self._HUNK_HEADER_RE.match(line)
            if match:
                if in_hunk:
                    hunks.append(
                        _ParsedUnifiedHunk(
                            preferred_index=current_preferred_index,
                            lines=current_lines,
                        )
                    )
                current_preferred_index = max(0, int(match.group("old_start")) - 1)
                current_lines = []
                in_hunk = True
                continue

            if self._LOOSE_UNIFIED_HUNK_HEADER_RE.match(line):
                if in_hunk:
                    hunks.append(
                        _ParsedUnifiedHunk(
                            preferred_index=current_preferred_index,
                            lines=current_lines,
                        )
                    )
                current_preferred_index = None
                current_lines = []
                in_hunk = True
                continue

            if not in_hunk:
                continue

            if line.startswith(("diff --git ", "index ", "--- ", "+++ ")):
                continue

            current_lines.append(line)

        if in_hunk:
            hunks.append(
                _ParsedUnifiedHunk(
                    preferred_index=current_preferred_index,
                    lines=current_lines,
                )
            )
        return hunks

    def _consume_expected_line(
        self,
        original_lines: List[str],
        index: int,
        expected: str,
        label: str,
    ) -> int:
        if index >= len(original_lines):
            raise ValueError(f"hunk {label} 越界，原文件已结束")
        actual = original_lines[index]
        if actual != expected:
            if self._normalize_line(actual) == self._normalize_line(expected):
                return index + 1
            hint = self._nearest_line_hint(actual=actual, expected=expected)
            raise ValueError(
                f"hunk {label} 不匹配: 期望 {expected!r}，实际 {actual!r}{hint}"
            )
        return index + 1

    def _matches_sequence(
        self,
        original_lines: List[str],
        start_index: int,
        expected_old_lines: List[str],
        normalize_whitespace: bool = False,
    ) -> bool:
        if not expected_old_lines:
            return True
        if start_index < 0 or start_index + len(expected_old_lines) > len(original_lines):
            return False

        for offset, expected in enumerate(expected_old_lines):
            actual = original_lines[start_index + offset]
            if normalize_whitespace:
                if self._normalize_line(actual) != self._normalize_line(expected):
                    return False
                continue
            if actual != expected:
                return False
        return True

    def _find_sequence_matches(
        self,
        original_lines: List[str],
        cursor: int,
        expected_old_lines: List[str],
        normalize_whitespace: bool = False,
    ) -> List[int]:
        if not expected_old_lines:
            return [max(0, cursor)]

        max_start = len(original_lines) - len(expected_old_lines)
        if max_start < cursor:
            return []

        matches: List[int] = []
        for start_index in range(max(0, cursor), max_start + 1):
            if self._matches_sequence(
                original_lines=original_lines,
                start_index=start_index,
                expected_old_lines=expected_old_lines,
                normalize_whitespace=normalize_whitespace,
            ):
                matches.append(start_index)
        return matches

    def _normalize_line(self, text: str) -> str:
        return " ".join(str(text).split())

    def _nearest_line_hint(self, actual: str, expected: str) -> str:
        ratio = SequenceMatcher(a=actual, b=expected).ratio()
        if ratio <= 0.35:
            return ""
        return f"（相似度 {ratio:.2f}，可能是上下文行或空白字符不一致）"

    def _count_diff_stats(self, original: str, patched: str) -> Tuple[int, int]:
        matcher = SequenceMatcher(a=original.splitlines(), b=patched.splitlines())
        added = 0
        removed = 0
        for opcode, a0, a1, b0, b1 in matcher.get_opcodes():
            if opcode in {"replace", "delete"}:
                removed += max(0, a1 - a0)
            if opcode in {"replace", "insert"}:
                added += max(0, b1 - b0)
        return added, removed
