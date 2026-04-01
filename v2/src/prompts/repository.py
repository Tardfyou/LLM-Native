"""
Hierarchical prompt repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import yaml


@dataclass(frozen=True)
class PromptDefinition:
    """Single prompt entry loaded from the manifest."""

    prompt_id: str
    path: str
    kind: str = "text"
    description: str = ""


class PromptRepository:
    """Resolve prompt templates from a manifest-backed prompt tree."""

    MANIFEST_NAME = "manifest.yaml"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._prompt_dirs = tuple(self._resolve_prompt_dirs())
        self._manifest_dir, self._definitions = self._load_manifest()

    def has_prompt(self, prompt_id: str) -> bool:
        return str(prompt_id or "").strip() in self._definitions

    def get_definition(self, prompt_id: str) -> Optional[PromptDefinition]:
        return self._definitions.get(str(prompt_id or "").strip())

    def load_text(self, prompt_id: str, *, strict: bool = False) -> Optional[str]:
        definition = self.get_definition(prompt_id)
        if definition is None:
            if strict:
                raise FileNotFoundError(f"未注册的 prompt: {prompt_id}")
            return None
        if definition.kind != "text":
            if strict:
                raise TypeError(f"prompt `{prompt_id}` 不是文本模板: {definition.kind}")
            return None
        prompt_path = self._resolve_registered_path(definition)
        if prompt_path is None:
            if strict:
                raise FileNotFoundError(f"prompt 文件不存在: {prompt_id} -> {definition.path}")
            return None
        return prompt_path.read_text(encoding="utf-8")

    def load_yaml(self, prompt_id: str, *, strict: bool = False) -> Optional[Dict[str, Any]]:
        definition = self.get_definition(prompt_id)
        if definition is None:
            if strict:
                raise FileNotFoundError(f"未注册的 prompt: {prompt_id}")
            return None
        if definition.kind != "yaml":
            if strict:
                raise TypeError(f"prompt `{prompt_id}` 不是 YAML 配置: {definition.kind}")
            return None
        prompt_path = self._resolve_registered_path(definition)
        if prompt_path is None:
            if strict:
                raise FileNotFoundError(f"prompt 文件不存在: {prompt_id} -> {definition.path}")
            return None
        content = yaml.safe_load(prompt_path.read_text(encoding="utf-8"))
        return content if isinstance(content, dict) else None

    def render(
        self,
        prompt_id: str,
        values: Optional[Dict[str, Any]] = None,
        *,
        strict: bool = False,
    ) -> Optional[str]:
        template = self.load_text(prompt_id, strict=strict)
        if template is None:
            return None
        rendered = template
        for key, value in (values or {}).items():
            rendered = rendered.replace(f"{{{{{key}}}}}", str(value))
        return rendered

    def load_legacy_text(self, filename: str) -> Optional[str]:
        for prompt_dir in self._prompt_dirs:
            prompt_path = prompt_dir / filename
            if prompt_path.exists():
                return prompt_path.read_text(encoding="utf-8")
        return None

    def load_legacy_yaml(self, filename: str) -> Optional[Dict[str, Any]]:
        content = self.load_legacy_text(filename)
        if content is None:
            return None
        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else None

    def _load_manifest(self) -> tuple[Optional[Path], Dict[str, PromptDefinition]]:
        for prompt_dir in self._prompt_dirs:
            manifest_path = prompt_dir / self.MANIFEST_NAME
            if not manifest_path.exists():
                continue
            data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
            prompts = data.get("prompts", {}) or {}
            definitions: Dict[str, PromptDefinition] = {}
            for prompt_id, raw_entry in prompts.items():
                if not isinstance(raw_entry, dict):
                    continue
                definition = PromptDefinition(
                    prompt_id=str(prompt_id).strip(),
                    path=str(raw_entry.get("path", "")).strip(),
                    kind=str(raw_entry.get("kind", "text")).strip() or "text",
                    description=str(raw_entry.get("description", "")).strip(),
                )
                if definition.prompt_id and definition.path:
                    definitions[definition.prompt_id] = definition
            return prompt_dir, definitions
        return None, {}

    def _resolve_registered_path(self, definition: PromptDefinition) -> Optional[Path]:
        candidate_roots = []
        if self._manifest_dir is not None:
            candidate_roots.append(self._manifest_dir)
        candidate_roots.extend(self._prompt_dirs)
        seen = set()
        for root in candidate_roots:
            resolved_root = root.resolve()
            if resolved_root in seen:
                continue
            seen.add(resolved_root)
            path = resolved_root / definition.path
            if path.exists():
                return path
        return None

    def _resolve_prompt_dirs(self) -> Iterable[Path]:
        configured_dir = self.config.get("paths", {}).get("prompts_dir")
        candidates = []

        if configured_dir:
            candidates.append(Path(configured_dir).expanduser())

        candidates.extend(
            [
                Path.cwd() / "prompts",
                Path(__file__).resolve().parents[2] / "prompts",
            ]
        )

        unique_candidates = []
        seen = set()
        for path in candidates:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            unique_candidates.append(resolved)
        return unique_candidates
