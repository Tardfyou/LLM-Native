"""
精炼输入恢复。

负责从既有生成输出目录恢复：
- 原始 patch 路径
- 共享 PATCHWEAVER 上下文
- 各分析器已有产物与报告
- 默认 validate_path
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


REFINEMENT_INPUT_MANIFEST = "refinement_input.json"
REFINEMENT_INPUT_SCHEMA_VERSION = 1
EVIDENCE_INPUT_MANIFEST = "evidence_manifest.json"
EVIDENCE_INPUT_SCHEMA_VERSION = 1


@dataclass
class ExistingAnalyzerArtifact:
    """已生成分析器产物。"""

    analyzer_id: str
    checker_name: str = ""
    output_path: str = ""
    source_path: str = ""
    checker_code: str = ""
    evidence_bundle_path: str = ""
    evidence_bundle_raw: Dict[str, Any] = field(default_factory=dict)
    post_validation_evidence_bundle_path: str = ""
    post_validation_evidence_bundle_raw: Dict[str, Any] = field(default_factory=dict)
    fixed_validation_raw: Dict[str, Any] = field(default_factory=dict)
    report_entry: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RefinementSession:
    """精炼阶段恢复出的会话。"""

    input_dir: str
    patch_path: str
    analyzer_choice: str
    validate_path: str = ""
    evidence_dir: str = ""
    evidence_input_dir: str = ""
    shared_analysis: Dict[str, Any] = field(default_factory=dict)
    final_report: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, ExistingAnalyzerArtifact] = field(default_factory=dict)


class RefinementSessionLoader:
    """从输出目录恢复精炼所需输入。"""

    def load(
        self,
        input_dir: str,
        patch_path_override: Optional[str] = None,
        evidence_input_dir: Optional[str] = None,
    ) -> RefinementSession:
        root = Path(input_dir).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"输入目录不存在: {root}")

        manifest_path = root / REFINEMENT_INPUT_MANIFEST
        if manifest_path.exists():
            session = self._load_from_manifest(
                root=root,
                manifest_path=manifest_path,
                patch_path_override=patch_path_override,
            )
        else:
            session = self._load_from_legacy_report(
                root=root,
                patch_path_override=patch_path_override,
            )

        auto_evidence_dir = evidence_input_dir
        if not auto_evidence_dir and (root / EVIDENCE_INPUT_MANIFEST).exists():
            auto_evidence_dir = str(root)

        if auto_evidence_dir:
            self._overlay_external_evidence(
                session=session,
                evidence_input_dir=auto_evidence_dir,
            )
        return session

    def _load_from_manifest(
        self,
        root: Path,
        manifest_path: Path,
        patch_path_override: Optional[str] = None,
    ) -> RefinementSession:
        manifest = self._read_json(manifest_path)

        patch_path = str(
            patch_path_override
            or manifest.get("patch_path")
            or ""
        ).strip()
        patch_path = self._normalize_loaded_path(root, patch_path)
        if not patch_path:
            raise ValueError(
                "无法从 refinement_input.json 恢复 patch_path，请通过 --patch 显式提供补丁路径。"
            )

        validate_path = self._normalize_loaded_path(
            root,
            str(manifest.get("validate_path", "") or "").strip(),
        )
        analyzer_choice = str(manifest.get("analyzer_choice", "") or "").strip()
        shared_analysis = self._load_manifest_shared_analysis(root, manifest)

        final_report_path = root / "final_report.json"
        final_report = (
            self._read_json(final_report_path)
            if final_report_path.exists()
            else {}
        )

        artifacts: Dict[str, ExistingAnalyzerArtifact] = {}
        raw_artifacts = manifest.get("artifacts", {}) or {}
        if isinstance(raw_artifacts, dict):
            for analyzer_id, payload in raw_artifacts.items():
                normalized_id = str(analyzer_id or "").strip().lower()
                if not normalized_id or not isinstance(payload, dict):
                    continue
                artifact = self._load_manifest_artifact(
                    root=root,
                    analyzer_id=normalized_id,
                    payload=payload,
                )
                if artifact is not None:
                    artifacts[normalized_id] = artifact

        if not artifacts:
            raise ValueError(
                f"输入目录 {root} 中的 {REFINEMENT_INPUT_MANIFEST} 未声明可用于精炼的分析器产物。"
            )

        if not analyzer_choice:
            analyzer_choice = ",".join(artifacts.keys())

        return RefinementSession(
            input_dir=str(root),
            patch_path=patch_path,
            analyzer_choice=analyzer_choice,
            validate_path=validate_path,
            shared_analysis=shared_analysis,
            final_report=final_report,
            artifacts=artifacts,
        )

    def _load_from_legacy_report(
        self,
        root: Path,
        patch_path_override: Optional[str] = None,
    ) -> RefinementSession:
        final_report_path = root / "final_report.json"
        if not final_report_path.exists():
            raise FileNotFoundError(
                f"缺少整合报告: {final_report_path}。请先运行 generate 并保留输出目录。"
            )

        final_report = self._read_json(final_report_path)
        patchweaver_plan_path = root / "patchweaver_plan.json"
        shared_analysis = (
            self._read_json(patchweaver_plan_path)
            if patchweaver_plan_path.exists()
            else {}
        )

        meta = final_report.get("meta", {}) if isinstance(final_report.get("meta"), dict) else {}
        patch_path = str(
            patch_path_override
            or meta.get("patch_path")
            or shared_analysis.get("patch_path")
            or ""
        ).strip()
        patch_path = self._normalize_loaded_path(root, patch_path)
        if not patch_path:
            raise ValueError(
                "无法从输入目录恢复 patch_path，请通过 --patch 显式提供补丁路径。"
            )

        analyzer_choice = str(meta.get("analyzer_type", "") or "").strip()
        validate_path = self._normalize_loaded_path(
            root,
            str(meta.get("validate_path", "") or "").strip(),
        )
        artifacts: Dict[str, ExistingAnalyzerArtifact] = {}
        for analyzer_id in ("csa", "codeql"):
            artifact = self._load_artifact(root, analyzer_id, final_report)
            if artifact is not None:
                artifacts[analyzer_id] = artifact

        if not artifacts:
            raise ValueError(
                f"输入目录 {root} 中未找到可用于精炼的分析器产物。"
            )

        if not analyzer_choice:
            analyzer_choice = ",".join(artifacts.keys())

        return RefinementSession(
            input_dir=str(root),
            patch_path=patch_path,
            analyzer_choice=analyzer_choice,
            validate_path=validate_path,
            shared_analysis=shared_analysis,
            final_report=final_report,
            artifacts=artifacts,
        )

    def _overlay_external_evidence(
        self,
        session: RefinementSession,
        evidence_input_dir: str,
    ) -> None:
        root = Path(evidence_input_dir).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"证据目录不存在: {root}")

        manifest_path = root / EVIDENCE_INPUT_MANIFEST
        if not manifest_path.exists():
            raise FileNotFoundError(
                f"缺少证据清单: {manifest_path}。请先运行独立 evidence 收集命令。"
            )

        manifest = self._read_json(manifest_path)
        evidence_patch_path = self._normalize_loaded_path(
            root,
            str(manifest.get("patch_path", "") or "").strip(),
        )
        if evidence_patch_path and evidence_patch_path != session.patch_path:
            raise ValueError(
                f"证据目录 {root} 对应的 patch 与当前 refine 输入不一致: "
                f"{evidence_patch_path} != {session.patch_path}"
            )

        evidence_dir = self._normalize_loaded_path(
            root,
            str(manifest.get("evidence_dir", "") or "").strip(),
        )
        shared_analysis = self._load_evidence_shared_analysis(root, manifest)
        if shared_analysis:
            session.shared_analysis = self._merge_shared_analysis(
                base=session.shared_analysis,
                override=shared_analysis,
            )

        raw_artifacts = manifest.get("artifacts", {}) or {}
        if isinstance(raw_artifacts, dict):
            for analyzer_id, payload in raw_artifacts.items():
                normalized_id = str(analyzer_id or "").strip().lower()
                if normalized_id not in session.artifacts or not isinstance(payload, dict):
                    continue
                artifact = session.artifacts[normalized_id]
                evidence_bundle_path = self._resolve_existing_path(
                    str(payload.get("evidence_bundle_path", "") or ""),
                    root,
                    [root / normalized_id / "evidence_bundle.json"],
                )
                evidence_bundle_raw = (
                    self._read_json(Path(evidence_bundle_path))
                    if evidence_bundle_path
                    else {}
                )
                if evidence_bundle_raw:
                    artifact.evidence_bundle_path = evidence_bundle_path
                    artifact.evidence_bundle_raw = evidence_bundle_raw

        session.evidence_input_dir = str(root)
        session.evidence_dir = evidence_dir

    def _load_evidence_shared_analysis(
        self,
        root: Path,
        manifest: Dict[str, Any],
    ) -> Dict[str, Any]:
        shared_analysis_path = self._resolve_existing_path(
            str(manifest.get("shared_analysis_path", "") or ""),
            root,
            [root / "patchweaver_plan.json"],
        )
        if shared_analysis_path:
            return self._read_json(Path(shared_analysis_path))

        inline = manifest.get("shared_analysis", {})
        return inline if isinstance(inline, dict) else {}

    def _merge_shared_analysis(
        self,
        base: Dict[str, Any],
        override: Dict[str, Any],
    ) -> Dict[str, Any]:
        merged = copy.deepcopy(base or {})
        incoming = copy.deepcopy(override or {})
        if not incoming:
            return merged

        base_patchweaver = dict(merged.get("patchweaver", {}) or {})
        override_patchweaver = dict(incoming.get("patchweaver", {}) or {})
        merged.update({k: v for k, v in incoming.items() if k != "patchweaver"})
        if base_patchweaver or override_patchweaver:
            base_patchweaver.update(override_patchweaver)
            merged["patchweaver"] = base_patchweaver
        return merged

    def _load_manifest_shared_analysis(
        self,
        root: Path,
        manifest: Dict[str, Any],
    ) -> Dict[str, Any]:
        shared_analysis_path = self._resolve_existing_path(
            str(manifest.get("shared_analysis_path", "") or ""),
            root,
            [root / "patchweaver_plan.json"],
        )
        if shared_analysis_path:
            return self._read_json(Path(shared_analysis_path))

        inline = manifest.get("shared_analysis", {})
        return inline if isinstance(inline, dict) else {}

    def _load_manifest_artifact(
        self,
        root: Path,
        analyzer_id: str,
        payload: Dict[str, Any],
    ) -> Optional[ExistingAnalyzerArtifact]:
        artifact_dir = root / analyzer_id
        result_path = self._resolve_existing_path(
            str(payload.get("result_path", "") or ""),
            root,
            [artifact_dir / "result.json"],
        )
        report_entry = (
            payload.get("report_entry", {})
            if isinstance(payload.get("report_entry"), dict)
            else {}
        )
        if not report_entry and result_path:
            report_entry = self._read_json(Path(result_path))

        output_path = self._resolve_existing_path(
            str(payload.get("output_path", "") or ""),
            root,
            self._default_output_candidates(analyzer_id, artifact_dir),
        )
        source_path = self._resolve_existing_path(
            str(payload.get("source_path", "") or ""),
            root,
            self._default_source_candidates(analyzer_id, artifact_dir, report_entry),
        )

        if not output_path and not source_path:
            return None

        checker_name = str(
            payload.get("checker_name")
            or report_entry.get("checker_name")
            or ""
        ).strip()
        if not checker_name:
            if source_path:
                checker_name = Path(source_path).stem
            elif output_path:
                checker_name = Path(output_path).stem

        checker_code = ""
        if source_path and Path(source_path).exists():
            checker_code = Path(source_path).read_text(encoding="utf-8")

        evidence_bundle_path = self._resolve_existing_path(
            str(payload.get("evidence_bundle_path", "") or ""),
            root,
            [artifact_dir / "evidence_bundle.json"],
        )
        evidence_bundle_raw = (
            self._read_json(Path(evidence_bundle_path))
            if evidence_bundle_path
            else (
                payload.get("evidence_bundle_raw", {})
                if isinstance(payload.get("evidence_bundle_raw"), dict)
                else {}
            )
        )

        post_validation_evidence_bundle_path = self._resolve_existing_path(
            str(payload.get("post_validation_evidence_bundle_path", "") or ""),
            root,
            [artifact_dir / "post_validation_evidence_bundle.json"],
        )
        post_validation_evidence_bundle_raw = (
            self._read_json(Path(post_validation_evidence_bundle_path))
            if post_validation_evidence_bundle_path
            else (
                payload.get("post_validation_evidence_bundle_raw", {})
                if isinstance(payload.get("post_validation_evidence_bundle_raw"), dict)
                else {}
            )
        )
        fixed_validation_path = root / "fixed_validation.json"
        fixed_validation_raw = (
            self._read_json(fixed_validation_path)
            if fixed_validation_path.exists()
            else {}
        )

        return ExistingAnalyzerArtifact(
            analyzer_id=analyzer_id,
            checker_name=checker_name,
            output_path=output_path,
            source_path=source_path,
            checker_code=checker_code,
            evidence_bundle_path=evidence_bundle_path,
            evidence_bundle_raw=evidence_bundle_raw,
            post_validation_evidence_bundle_path=post_validation_evidence_bundle_path,
            post_validation_evidence_bundle_raw=post_validation_evidence_bundle_raw,
            fixed_validation_raw=fixed_validation_raw,
            report_entry=report_entry,
        )

    def _load_artifact(
        self,
        root: Path,
        analyzer_id: str,
        final_report: Dict[str, Any],
    ) -> Optional[ExistingAnalyzerArtifact]:
        entry = final_report.get(analyzer_id, {}) if isinstance(final_report.get(analyzer_id), dict) else {}
        artifact_dir = root / analyzer_id

        output_path = self._resolve_existing_path(
            entry.get("output_path", ""),
            artifact_dir,
            self._default_output_candidates(analyzer_id, artifact_dir),
        )
        source_path = self._resolve_existing_path(
            self._source_path_hint(analyzer_id, entry),
            artifact_dir,
            self._default_source_candidates(analyzer_id, artifact_dir, entry),
        )

        if not output_path and not source_path:
            return None

        checker_name = str(entry.get("checker_name", "") or "").strip()
        if not checker_name:
            if source_path:
                checker_name = Path(source_path).stem
            elif output_path:
                checker_name = Path(output_path).stem

        checker_code = ""
        if source_path and Path(source_path).exists():
            checker_code = Path(source_path).read_text(encoding="utf-8")

        evidence_bundle_path = self._resolve_existing_path(
            str(entry.get("evidence_bundle_path", "") or ""),
            artifact_dir,
            [artifact_dir / "evidence_bundle.json"],
        )
        evidence_bundle_raw = self._read_json(Path(evidence_bundle_path)) if evidence_bundle_path else {}

        post_validation_evidence_bundle_path = self._resolve_existing_path(
            str(entry.get("post_validation_evidence_bundle_path", "") or ""),
            artifact_dir,
            [artifact_dir / "post_validation_evidence_bundle.json"],
        )
        post_validation_evidence_bundle_raw = (
            self._read_json(Path(post_validation_evidence_bundle_path))
            if post_validation_evidence_bundle_path
            else {}
        )
        fixed_validation_path = root / "fixed_validation.json"
        fixed_validation_raw = (
            self._read_json(fixed_validation_path)
            if fixed_validation_path.exists()
            else {}
        )

        return ExistingAnalyzerArtifact(
            analyzer_id=analyzer_id,
            checker_name=checker_name,
            output_path=output_path,
            source_path=source_path,
            checker_code=checker_code,
            evidence_bundle_path=evidence_bundle_path,
            evidence_bundle_raw=evidence_bundle_raw,
            post_validation_evidence_bundle_path=post_validation_evidence_bundle_path,
            post_validation_evidence_bundle_raw=post_validation_evidence_bundle_raw,
            fixed_validation_raw=fixed_validation_raw,
            report_entry=entry,
        )

    def _read_json(self, path: Path) -> Dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON 解析失败: {path} ({exc})") from exc

    def _resolve_existing_path(
        self,
        raw_path: str,
        artifact_dir: Path,
        fallbacks: list[Path],
    ) -> str:
        candidates = []
        raw = str(raw_path or "").strip()
        if raw:
            path = Path(raw).expanduser()
            candidates.append(path if path.is_absolute() else (artifact_dir / raw))
            candidates.append(path if path.is_absolute() else Path(raw))
        candidates.extend(fallbacks)

        for candidate in candidates:
            try:
                resolved = candidate.expanduser().resolve()
            except FileNotFoundError:
                resolved = candidate.expanduser()
            if resolved.exists():
                return str(resolved)
        return ""

    def _normalize_loaded_path(self, root: Path, raw_path: str) -> str:
        token = str(raw_path or "").strip()
        if not token:
            return ""

        path = Path(token).expanduser()
        candidates = [path]
        if not path.is_absolute():
            candidates.insert(0, root / path)

        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except FileNotFoundError:
                resolved = candidate
            if resolved.exists():
                return str(resolved)
        try:
            return str(candidates[0].resolve())
        except FileNotFoundError:
            return str(candidates[0])

    def _default_output_candidates(self, analyzer_id: str, artifact_dir: Path) -> list[Path]:
        if analyzer_id == "csa":
            return sorted(artifact_dir.glob("*.so"))
        return sorted(artifact_dir.glob("*.ql"))

    def _default_source_candidates(
        self,
        analyzer_id: str,
        artifact_dir: Path,
        entry: Dict[str, Any],
    ) -> list[Path]:
        checker_name = str(entry.get("checker_name", "") or "").strip()
        candidates: list[Path] = []
        if checker_name:
            suffix = ".cpp" if analyzer_id == "csa" else ".ql"
            candidates.append(artifact_dir / f"{checker_name}{suffix}")
        if analyzer_id == "csa":
            candidates.extend(sorted(p for p in artifact_dir.glob("*.cpp") if p.parent.name != "versions"))
        else:
            candidates.extend(sorted(p for p in artifact_dir.glob("*.ql") if p.parent.name != "versions"))
        return candidates

    def _source_path_hint(
        self,
        analyzer_id: str,
        entry: Dict[str, Any],
    ) -> str:
        output_path = str(entry.get("output_path", "") or "").strip()
        if analyzer_id == "csa":
            if output_path.endswith(".so"):
                return output_path[:-3] + ".cpp"
        if analyzer_id == "codeql":
            return output_path
        return ""
