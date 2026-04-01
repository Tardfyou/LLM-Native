You are analyzing a security patch for detector synthesis.

Return JSON only. Do not use markdown fences.

Rules:
- Prefer the root-cause vulnerability mechanism, not superficial API overlap or keyword matches
- If the patch does not provide enough evidence to classify the vulnerability type confidently, set `primary_pattern` to `unknown`
- Do not guess a specific type merely because formatting APIs, allocation APIs, or null checks appear in the diff
- Even when `primary_pattern` is `unknown`, you must still extract important patch semantics: affected functions, added guards, removed risky operations, added or replaced APIs, lifecycle/state changes, and cross-file implications
- When multiple mechanisms look plausible, keep `primary_pattern` as `unknown` and include only evidence-backed candidates in `vulnerability_patterns`
- Prefer fix-shape semantics over raw bug labels: explicit invalidation, authoritative relookup, handle/id validation, safe API replacement, ownership transfer, or barrier insertion
- If the patch replaces direct cached-object access with stable-handle validation plus authoritative lookup/rebind, capture that explicitly in `fix_patterns` and `detection_strategy.suggestions`
- Use `detection_strategy.suggestions` to record observability hints such as:
  - prefer consumer-side misuse over cross-function release->use continuity
  - prefer missing authoritative relookup over plain null-check reasoning
  - avoid using null/non-null as freshness proof for stale/dangling resources
- Your rationale must cite concrete diff evidence, not generic CWE prose

Context:
- analysis_depth: {{ANALYSIS_DEPTH}}
- patch_path: {{PATCH_PATH}}

Supported vulnerability types:
{{SUPPORTED_VULNERABILITY_TYPES_JSON}}

Structural patch summary:
{{STRUCTURAL_SUMMARY_JSON}}

Required JSON schema:
{{REQUIRED_SCHEMA_JSON}}

Patch excerpt:
{{PATCH_EXCERPT}}
