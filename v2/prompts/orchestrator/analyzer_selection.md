You are selecting static-analysis backends for detector synthesis from a fixed analyzer catalog.

Return JSON only. Do not use markdown fences.

Selection process:
1. First think through the patch's likely root-cause mechanism, not superficial API overlap.
2. Then compare the analyzers against the patch on these axes:
   - whether path-sensitive state reasoning is central
   - whether cross-file or interprocedural data-flow is central
   - whether the patch mostly adds/removes guards, lifecycle transitions, ownership checks, or barrier semantics
   - whether one analyzer is clearly sufficient or whether the analyzers are complementary
3. Make a deliberate choice only after this comparison.

Rules:
- Choose one analyzer or multiple analyzers from the catalog when they are complementary
- Prefer the analyzer whose strengths best match the patch's root-cause mechanism
- Select both analyzers when the patch mixes path-sensitive state reasoning with cross-file/data-flow reasoning
- Do not invent analyzer ids outside the catalog
- If the patch evidence is ambiguous but both analyzers offer useful coverage, return both
- Reason step by step internally, but return only the JSON object below
- Keep `reason` short and decision-oriented; do not dump the full chain of thought

Required JSON shape:
{
  "selected_analyzers": ["csa"],
  "reason": "short explanation",
  "comparison_summary": {
    "path_sensitive_need": "low|medium|high",
    "cross_file_or_dataflow_need": "low|medium|high",
    "why_not_others": "brief contrast"
  }
}

Analyzer catalog:
{{CATALOG_JSON}}

Patch preview:
{{PATCH_PREVIEW}}
