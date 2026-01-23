"""
增强型提示词管理器 - 管理所有生成和修复的提示词模板

支持：
1. 多种生成阶段的提示词模板
2. 少样本示例加载和注入
3. 自然语言漏洞描述和补丁两种输入模式
4. Clang Static Analyzer 特定的知识库
5. 语法和语义修复提示词
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class PromptExample:
    """少样本示例数据类"""
    name: str
    pattern: str
    patch: str
    plan: str
    checker_code: str

    @classmethod
    def load_from_directory(cls, example_dir: Path) -> 'PromptExample':
        """从目录加载示例"""
        name = example_dir.name
        pattern_file = example_dir / "pattern.md"
        patch_file = example_dir / "patch.md"
        plan_file = example_dir / "plan.md"
        checker_file = example_dir / "checker.cpp"

        return cls(
            name=name,
            pattern=pattern_file.read_text() if pattern_file.exists() else "",
            patch=patch_file.read_text() if patch_file.exists() else "",
            plan=plan_file.read_text() if plan_file.exists() else "",
            checker_code=checker_file.read_text() if checker_file.exists() else ""
        )


@dataclass
class PromptContext:
    """提示词上下文信息"""
    vulnerability_type: Optional[str] = None
    input_type: str = "natural_language"  # natural_language or patch
    target_framework: str = "clang"
    clang_version: str = "18"
    enable_lsp: bool = True
    enable_rag: bool = True
    rag_context: Optional[str] = None
    failed_attempts: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "vulnerability_type": self.vulnerability_type,
            "input_type": self.input_type,
            "target_framework": self.target_framework,
            "clang_version": self.clang_version,
            "enable_lsp": self.enable_lsp,
            "enable_rag": self.enable_rag,
            "rag_context": self.rag_context,
            "failed_attempts": self.failed_attempts,
            "metadata": self.metadata
        }


class EnhancedPromptManager:
    """增强型提示词管理器"""

    def __init__(self, template_dir: Optional[Path] = None, example_dir: Optional[Path] = None):
        # 设置路径
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"

        if example_dir is None:
            example_dir = Path(__file__).parent / "examples"

        self.template_dir = Path(template_dir)
        self.example_dir = Path(example_dir)

        # 存储模板和示例
        self.templates: Dict[str, str] = {}
        self.examples: Dict[str, PromptExample] = {}

        # 知识库内容
        self.utility_functions = ""
        self.suggestions = ""
        self.checker_template = ""

        # 加载所有内容
        self._load_templates()
        self._load_examples()
        self._load_knowledge_base()

        logger.info(f"EnhancedPromptManager initialized with {len(self.templates)} templates "
                    f"and {len(self.examples)} examples")

    def _load_templates(self):
        """加载所有提示词模板"""
        try:
            # 加载主模板
            template_files = {
                "desc_to_pattern": self.template_dir / "desc_to_pattern.md",
                "pattern_to_plan": self.template_dir / "pattern_to_plan.md",
                "plan_to_checker": self.template_dir / "plan_to_checker.md",
                "repair_syntax": self.template_dir / "repair_syntax.md",
                "repair_semantic": self.template_dir / "repair_semantic.md"
            }

            for name, path in template_files.items():
                if path.exists():
                    self.templates[name] = path.read_text()
                    logger.debug(f"Loaded template: {name}")
                else:
                    logger.warning(f"Template file not found: {path}")

            logger.info(f"Loaded {len(self.templates)} prompt templates")

        except Exception as e:
            logger.error(f"Failed to load templates: {e}")

    def _load_examples(self):
        """加载少样本示例"""
        try:
            if not self.example_dir.exists():
                logger.warning(f"Example directory not found: {self.example_dir}")
                return

            for example_path in self.example_dir.iterdir():
                if example_path.is_dir():
                    try:
                        example = PromptExample.load_from_directory(example_path)
                        self.examples[example.name] = example
                        logger.debug(f"Loaded example: {example.name}")
                    except Exception as e:
                        logger.warning(f"Failed to load example {example_path}: {e}")

            logger.info(f"Loaded {len(self.examples)} examples")

        except Exception as e:
            logger.error(f"Failed to load examples: {e}")

    def _load_knowledge_base(self):
        """加载Clang知识库内容"""
        try:
            knowledge_dir = self.template_dir / "clang"
            if not knowledge_dir.exists():
                logger.warning(f"Knowledge directory not found: {knowledge_dir}")
                return

            # 加载知识库文件
            utility_file = knowledge_dir / "utility.md"
            suggestions_file = knowledge_dir / "suggestions.md"
            template_file = knowledge_dir / "template.md"

            if utility_file.exists():
                self.utility_functions = utility_file.read_text()
                logger.debug("Loaded utility functions")

            if suggestions_file.exists():
                self.suggestions = suggestions_file.read_text()
                logger.debug("Loaded development suggestions")

            if template_file.exists():
                self.checker_template = template_file.read_text()
                logger.debug("Loaded checker template")

        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")

    # ========================================================================
    # 模式提取阶段
    # ========================================================================

    def build_pattern_extraction_prompt(
        self,
        vulnerability_desc: str,
        context: PromptContext,
        patch: Optional[str] = None,
        num_examples: int = 3
    ) -> str:
        """
        构建模式提取提示词

        Args:
            vulnerability_desc: 漏洞描述（自然语言或补丁）
            context: 提示词上下文
            patch: 可选的补丁内容
            num_examples: 要包含的示例数量
        """
        template = self.templates.get("desc_to_pattern", "")

        # 选择最相关的示例
        example_text = self._select_examples_for_pattern(
            vulnerability_desc, num_examples
        )

        # 确定输入类型
        input_type = "Code Patch" if patch else "Natural Language Description"

        # 构建提示词
        prompt = template.replace("{{input_type}}", input_type)
        prompt = prompt.replace("{{input_description}}", vulnerability_desc)
        prompt = prompt.replace("{{examples}}", example_text)

        if patch:
            patch_section = f"\n**Patch:**\n```diff\n{patch}\n```\n"
            prompt = self._replace_conditional(prompt, "patch", True, patch=patch_section)
        else:
            prompt = self._replace_conditional(prompt, "patch", False)

        return prompt

    def _select_examples_for_pattern(self, description: str, num: int) -> str:
        """选择最相关的示例用于模式提取"""
        # 简单实现：返回前N个示例
        # 高级实现可以使用相似度匹配
        examples = list(self.examples.values())[:num]
        return self._format_pattern_examples(examples)

    def _format_pattern_examples(self, examples: List[PromptExample]) -> str:
        """格式化示例为模式提取提示词"""
        text = ""
        for i, example in enumerate(examples, 1):
            text += f"### Example {i}: {example.name}\n\n"
            text += f"**Vulnerability Type:** Uninitialized Variable Usage\n\n"
            text += example.pattern
            text += "\n\n---\n\n"
        return text

    # ========================================================================
    # 计划生成阶段
    # ========================================================================

    def build_plan_generation_prompt(
        self,
        bug_pattern: str,
        context: PromptContext,
        original_desc: Optional[str] = None,
        patch: Optional[str] = None,
        failed_plans: Optional[List[str]] = None,
        no_tp_plans: Optional[List[str]] = None,  # 新增：无法检测TP的plans
        no_fp_plans: Optional[List[str]] = None,  # 新增：无法正确处理FP的plans
        num_examples: int = 2
    ) -> str:
        """
        构建计划生成提示词 - 增强版，支持详细的反馈机制

        参考KNighter的agent.py pattern2plan实现:
        - 展示失败的plans作为负面示例
        - 区分无法检测TP和无法处理FP的plans
        - 限制反馈数量避免prompt过长

        Args:
            bug_pattern: 提取的漏洞模式
            context: 提示词上下文
            original_desc: 原始漏洞描述
            patch: 可选的补丁
            failed_plans: 之前失败的尝试（通用）
            no_tp_plans: 无法检测到目标漏洞的plans
            no_fp_plans: 正确标记非漏洞但有高误报的plans
            num_examples: 要包含的示例数量
        """
        template = self.templates.get("pattern_to_plan", "")

        # 选择相关示例
        example_text = self._select_examples_for_plan(bug_pattern, num_examples)

        # 构建增强的反馈部分 - 参考KNighter的实现
        feedback_section = self._build_feedback_section(failed_plans, no_tp_plans, no_fp_plans)

        # 构建提示词
        prompt = template.replace("{{bug_pattern}}", bug_pattern)
        prompt = prompt.replace("{{utility_functions}}", self.utility_functions)
        prompt = prompt.replace("{{suggestions}}", self.suggestions)
        prompt = prompt.replace("{{checker_template}}", self.checker_template)
        prompt = prompt.replace("{{examples}}", example_text)
        prompt = prompt.replace("{{failed_plan_examples}}", feedback_section)

        # 处理可选字段
        prompt = self._replace_conditional(prompt, "original_description", bool(original_desc),
                                         original_description=f"\n**Original Vulnerability Description:**\n{original_desc}\n")
        prompt = self._replace_conditional(prompt, "patch", bool(patch),
                                         patch=f"\n```diff\n{patch}\n```\n")

        return prompt

    def _build_feedback_section(
        self,
        failed_plans: Optional[List[str]],
        no_tp_plans: Optional[List[str]],
        no_fp_plans: Optional[List[str]]
    ) -> str:
        """
        构建反馈部分 - 参考KNighter的agent.py实现

        将不同类型的失败计划分类展示
        """
        feedback_parts = []

        # 处理无法检测TP的plans
        if no_tp_plans:
            # 限制显示最近3个
            display_plans = no_tp_plans[-3:] if len(no_tp_plans) > 3 else no_tp_plans
            no_tp_text = "# Plans that cannot detect the buggy pattern\n\n"
            for i, plan in enumerate(display_plans, 1):
                no_tp_text += f"## Failed Plan {i}\n{plan}\n\n"
            feedback_parts.append(no_tp_text)

        # 处理误报率高的plans
        if no_fp_plans:
            display_plans = no_fp_plans[-3:] if len(no_fp_plans) > 3 else no_fp_plans
            no_fp_text = "# Plans that can label the non-buggy pattern correctly (but have high false positives)\n\n"
            for i, plan in enumerate(display_plans, 1):
                no_fp_text += f"## Problematic Plan {i}\n{plan}\n\n"
            feedback_parts.append(no_fp_text)

        # 处理通用失败plans
        if failed_plans:
            display_plans = failed_plans[-3:] if len(failed_plans) > 3 else failed_plans
            general_failed_text = "# Other failed attempts\n\n"
            for i, plan in enumerate(display_plans, 1):
                general_failed_text += f"## Failed Attempt {i}\n{plan}\n\n"
            feedback_parts.append(general_failed_text)

        return "\n".join(feedback_parts)

    def _select_examples_for_plan(self, pattern: str, num: int) -> str:
        """选择最相关的示例用于计划生成"""
        examples = list(self.examples.values())[:num]
        return self._format_plan_examples(examples)

    def _format_plan_examples(self, examples: List[PromptExample]) -> str:
        """格式化示例为计划生成提示词"""
        text = ""
        for i, example in enumerate(examples, 1):
            text += f"### Example {i}: {example.name}\n\n"
            text += "**Bug Pattern:**\n"
            text += example.pattern[:500] + "...\n\n"  # 截断过长的内容
            text += "**Implementation Plan:**\n"
            text += example.plan
            text += "\n\n---\n\n"
        return text

    # ========================================================================
    # 代码生成阶段
    # ========================================================================

    def build_code_generation_prompt(
        self,
        bug_pattern: Optional[str] = None,
        implementation_plan: Optional[str] = None,
        context: Optional[PromptContext] = None,
        original_desc: Optional[str] = None,
        patch: Optional[str] = None,
        num_examples: int = 1,
        # 支持 generation_agent.py 的调用方式
        vulnerability_type: Optional[str] = None,
        framework: str = "clang",
        analysis_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        构建代码生成提示词 - 支持两种调用方式

        方式1（完整流水线）：build_code_generation_prompt(bug_pattern, implementation_plan, context, ...)
        方式2（直接生成）：build_code_generation_prompt(vulnerability_type=..., framework=..., analysis_context=...)

        Args:
            bug_pattern: 漏洞模式
            implementation_plan: 实现计划
            context: 提示词上下文
            original_desc: 原始描述
            patch: 可选的补丁
            num_examples: 要包含的示例数量
            vulnerability_type: 漏洞类型（用于直接生成模式）
            framework: 目标框架
            analysis_context: 分析上下文（用于直接生成模式）
        """
        # 检测调用方式：如果是直接生成模式
        if vulnerability_type is not None:
            return self._build_direct_generation_prompt(vulnerability_type, framework, analysis_context or {})

        # 否则使用完整的流水线模式
        template = self.templates.get("plan_to_checker", "")

        # 选择相关示例（包含完整代码）
        example_text = self._select_examples_for_code(bug_pattern, num_examples)

        # 构建提示词
        prompt = template.replace("{{bug_pattern}}", bug_pattern)
        prompt = prompt.replace("{{implementation_plan}}", implementation_plan)
        prompt = prompt.replace("{{utility_functions}}", self.utility_functions)
        prompt = prompt.replace("{{suggestions}}", self.suggestions)
        prompt = prompt.replace("{{checker_template}}", self.checker_template)
        prompt = prompt.replace("{{examples}}", example_text)

        # 处理可选字段
        prompt = self._replace_conditional(prompt, "original_description", bool(original_desc),
                                         original_description=f"\n**Original Description:**\n{original_desc}\n")
        prompt = self._replace_conditional(prompt, "patch", bool(patch),
                                         patch=f"\n```diff\n{patch}\n```\n")

        return prompt

    def _build_direct_generation_prompt(self, vulnerability_type: str, framework: str,
                                       analysis_context: Dict[str, Any],
                                       retrieved_knowledge: Optional[List] = None) -> str:
        """构建直接代码生成提示词（KNighter 风格）- 强调与具体漏洞的强相关性"""
        # 提取分析信息
        vuln_desc = analysis_context.get("description_summary", {}).get("summary", vulnerability_type)
        indicators = analysis_context.get("vulnerability_indicators", [])
        technical_terms = analysis_context.get("description_summary", {}).get("technical_terms", [])

        # 选择最相关的示例 - 只提供简短的示例
        example_text = self._select_examples_for_code_generation(vulnerability_type)

        # 使用精简的 utility functions 和 suggestions
        utility_brief = self._get_utility_brief()
        suggestions_brief = self._get_suggestions_brief()

        # 修复：格式化检索到的知识库内容
        knowledge_text = ""
        if retrieved_knowledge:
            knowledge_text = "\n## Retrieved Knowledge (RAG)\n\n"
            knowledge_text += "The following knowledge items were retrieved from the knowledge base and may help you understand similar vulnerabilities and detection patterns:\n\n"
            for i, item in enumerate(retrieved_knowledge[:5], 1):  # 限制显示前5条
                entry = item.entry if hasattr(item, 'entry') else item
                title = getattr(entry, 'title', 'Unknown')
                content = getattr(entry, 'content', '')[:600]  # 限制长度
                category = getattr(entry, 'category', 'general')
                knowledge_text += f"**{i}. [{category}] {title}**\n"
                knowledge_text += f"{content}...\n\n"
            knowledge_text += "---\n\n"

        # 构建提示词 - 强调与漏洞描述的强相关性
        prompt = f"""# Instruction

You are an expert in writing Clang Static Analyzer checkers using the **plugin-style architecture**.

Your task is to generate a **SPECIFIC, TARGETED checker** that detects **EXACTLY** the vulnerability described below.

**CRITICAL REQUIREMENTS:**

1. **MUST be directly related to the vulnerability description** - Do NOT generate generic utility checkers
2. **Focus on the specific vulnerability pattern** - Every line of code should relate to detecting THIS vulnerability
3. **DO NOT include generic utility functions** - Only include helpers that are ESSENTIAL for this specific vulnerability
4. **Plugin-Style Architecture** - Use `clang_registerCheckers()`, NOT `BuiltinCheckerRegistration.h`

The version of the Clang environment is Clang-21.

## Target Vulnerability (THIS is what you MUST detect)

**Vulnerability Type:** {vulnerability_type}

**Description:** {vuln_desc}

**Key Indicators:** {', '.join(indicators) if indicators else 'None'}

**Technical Terms:** {', '.join(technical_terms) if technical_terms else 'None'}

{knowledge_text}{utility_brief}

{suggestions_brief}

# Examples

{example_text}

# CRITICAL: What NOT to Do

❌ **DO NOT generate generic checkers like:**
- "GenericChecker" that just logs function calls
- "ExampleChecker" with placeholder detection logic
- Checkers with TODO comments or "implement your logic here" placeholders
- Checkers that copy entire utility.h or utility function collections

✅ **DO generate SPECIFIC checkers like:**
- "BufferOverflowChecker" that detects strcpy/memcpy without bounds checking
- "UseAfterFreeChecker" that tracks freed pointers and detects their reuse
- "NullDerefChecker" that checks pointer validity before dereference

# What Your Checker MUST Do

1. **Detect the EXACT vulnerability pattern described above**
2. **Implement concrete detection logic** - No placeholders, no TODOs
3. **Be compilable and ready to use** - Complete, working code
4. **Keep it focused** (~50-200 lines) - Only what's needed for THIS vulnerability

# Output Format

```cpp
// Your complete, specific checker implementation
#include "clang/StaticAnalyzer/Core/Checker.h"
// ... other necessary includes only

namespace {{
class YourSpecificChecker : public Checker<check::PreCall> {{
  // Implement ACTUAL detection for the described vulnerability
}};

void YourSpecificChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {{
  // REAL detection logic here - no placeholders!
}}

}} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<YourSpecificChecker>("custom.YourSpecificChecker", "Description", "");
}}

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;
```

**Generate the SPECIFIC checker code now - start directly with #include:**"""

        return prompt

    def _get_utility_brief(self) -> str:
        """获取精简的 utility functions 描述"""
        return """# Available Utility Functions

The following utility functions are available in `utility.h` (use: `#include "utility.h"`):

- `evaluateToInt(expr, C)`: Evaluate expression to integer
- `getMemRegionFromExpr(expr, C)`: Get memory region from expression
- `ExprHasName(expr, name, C)`: Check if expression's source contains a name
- `isNull(SVal)`, `isUndefined(SVal)`: Check value states

**IMPORTANT:**
- Use EXACTLY: `#include "utility.h"` (NOT `#include "clang/StaticAnalyzer/Checkers/utility.h"`)
- This is a project-specific header file, NOT a Clang official header
- DO NOT copy utility functions into your checker code"""

    def _get_suggestions_brief(self) -> str:
        """获取精简的 suggestions 描述"""
        return """# Key Guidelines

1. **NULL Safety**: Always check for NULL after `getMemRegionFromExpr()`, then call `getBaseRegion()`
2. **Non-Fatal Errors**: Use `generateNonFatalErrorNode()` to allow finding multiple bugs
3. **Short Messages**: Keep bug messages concise (e.g., "Potential buffer overflow on 'buf'")
4. **Modern APIs (LLVM-21)**: Use `std::optional` instead of `llvm::Optional`, `dyn_cast_or_null` for potentially null pointers
5. **Complete Code**: No TODO comments or placeholder logic"""

    def _select_examples_for_code_generation(self, vulnerability_type: str) -> str:
        """选择最相关的示例用于代码生成"""
        examples = list(self.examples.values())[:2]  # 取前2个示例
        if not examples:
            return "No examples available."

        text = ""
        for i, example in enumerate(examples, 1):
            text += f"## Example {i}: {example.name}\n\n"
            if example.pattern:
                text += "**Bug Pattern:**\n"
                text += example.pattern[:500] + "...\n\n"
            if example.plan:
                text += "**Implementation Plan:**\n"
                text += example.plan[:500] + "...\n\n"
            if example.checker_code:
                text += "**Complete Checker Code:**\n"
                text += "```cpp\n"
                text += example.checker_code
                text += "\n```\n\n"
            text += "---\n\n"
        return text

    def _select_examples_for_code(self, pattern: str, num: int) -> str:
        """选择最相关的示例用于代码生成（包含完整代码）"""
        examples = list(self.examples.values())[:num]
        return self._format_code_examples(examples)

    def _format_code_examples(self, examples: List[PromptExample]) -> str:
        """格式化示例为代码生成提示词"""
        text = ""
        for i, example in enumerate(examples, 1):
            text += f"### Example {i}: {example.name}\n\n"
            text += "**Bug Pattern:**\n"
            text += example.pattern[:300] + "...\n\n"
            text += "**Implementation Plan:**\n"
            text += example.plan[:500] + "...\n\n"
            text += "**Complete Checker Code:**\n"
            text += "```cpp\n"
            text += example.checker_code
            text += "\n```\n\n"
            text += "---\n\n"
        return text

    # ========================================================================
    # 修复阶段
    # ========================================================================

    def build_syntax_repair_prompt(
        self,
        checker_code: str,
        errors: List[str],
        context: PromptContext,
        error_details: Optional[str] = None
    ) -> str:
        """
        构建语法修复提示词

        Args:
            checker_code: 需要修复的检查器代码
            errors: 编译错误列表
            context: 提示词上下文
            error_details: 详细的错误信息
        """
        template = self.templates.get("repair_syntax", "")

        # 格式化错误信息
        error_text = "\n".join(f"- {err}" for err in errors)

        # 构建提示词
        prompt = template.replace("{{checker_code}}", checker_code)
        prompt = prompt.replace("{{errors}}", error_text)
        prompt = prompt.replace("{{clang_version}}", context.clang_version)

        prompt = self._replace_conditional(prompt, "error_details", bool(error_details),
                                         error_details=f"\n**Detailed Error Context:**\n{error_details}\n")
        prompt = self._replace_conditional(prompt, "has_errors", bool(errors))

        return prompt

    def build_semantic_repair_prompt(
        self,
        checker_code: str,
        bug_pattern: str,
        implementation_plan: str,
        context: PromptContext,
        issues: Dict[str, List[str]],
        reference_patch: Optional[str] = None,
        working_example: Optional[str] = None
    ) -> str:
        """
        构建语义修复提示词

        Args:
            checker_code: 需要修复的检查器代码
            bug_pattern: 漏洞模式
            implementation_plan: 实现计划
            context: 提示词上下文
            issues: 问题字典（false_positives, false_negatives, crashes）
            reference_patch: 参考补丁
            working_example: 工作示例代码
        """
        template = self.templates.get("repair_semantic", "")

        # 格式化问题
        issues_text = ""
        if issues.get("false_positives"):
            issues_text += "\n**False Positives:**\n"
            for fp in issues["false_positives"]:
                issues_text += f"- {fp}\n"

        if issues.get("false_negatives"):
            issues_text += "\n**False Negatives:**\n"
            for fn in issues["false_negatives"]:
                issues_text += f"- {fn}\n"

        if issues.get("crashes"):
            issues_text += "\n**Crashes/Errors:**\n"
            for crash in issues["crashes"]:
                issues_text += f"- {crash}\n"

        # 构建提示词
        prompt = template.replace("{{checker_code}}", checker_code)
        prompt = prompt.replace("{{bug_pattern}}", bug_pattern)
        prompt = prompt.replace("{{implementation_plan}}", implementation_plan)
        prompt = prompt.replace("{{issues}}", issues_text)

        # 处理可选字段
        prompt = self._replace_conditional(prompt, "false_positives",
                                         bool(issues.get("false_positives")))
        prompt = self._replace_conditional(prompt, "false_negatives",
                                         bool(issues.get("false_negatives")))
        prompt = self._replace_conditional(prompt, "crashes",
                                         bool(issues.get("crashes")))
        prompt = self._replace_conditional(prompt, "reference_patch", bool(reference_patch),
                                         reference_patch=f"\n```cpp\n{reference_patch}\n```\n")
        prompt = self._replace_conditional(prompt, "working_example", bool(working_example),
                                         working_example=f"\n```cpp\n{working_example}\n```\n")

        return prompt

    # ========================================================================
    # 工具方法
    # ========================================================================

    def _replace_conditional(self, template: str, name: str, condition: bool,
                            **kwargs) -> str:
        """替换条件块"""
        # 移除 {{#if name}} 或 {{#unless name}} 和 {{/if}} 或 {{/unless}}
        if_pattern = rf"{{{{#if {name}}}}}"
        unless_pattern = rf"{{{{#unless {name}}}}}"
        end_if_pattern = r"{{{/if}}}"
        end_unless_pattern = r"{{{/unless}}}"

        if condition:
            # 保留 if 块内容，移除 unless 块
            result = template.replace(if_pattern, "")
            result = result.replace(end_if_pattern, "")

            # 移除 unless 块
            unless_match = re.search(rf"{{{{#unless {name}}}}}.*?{{{{/unless}}}}",
                                   result, flags=re.DOTALL)
            if unless_match:
                result = result.replace(unless_match.group(0), "")

            # 替换变量
            for key, value in kwargs.items():
                result = result.replace(f"{{{{ {key} }}}}", value)
        else:
            # 移除 if 块，保留 unless 块内容（如果存在）
            if_match = re.search(rf"{{{{#if {name}}}}}.*?{{{{/if}}}}",
                               template, flags=re.DOTALL)
            if if_match:
                result = template.replace(if_match.group(0), "")
            else:
                result = template

            result = result.replace(unless_pattern, "")
            result = result.replace(end_unless_pattern, "")

        return result

    def get_prompt_hash(self, prompt: str) -> str:
        """获取提示词的哈希值，用于缓存"""
        return hashlib.sha256(prompt.encode()).hexdigest()[:16]

    def save_prompt_history(
        self,
        stage: str,
        prompt: str,
        response: str,
        output_dir: Path,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """保存提示词历史记录"""
        try:
            history_dir = output_dir / "prompt_history" / stage
            history_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # 保存提示词
            prompt_file = history_dir / f"prompt_{timestamp}.md"
            prompt_file.write_text(prompt)

            # 保存响应
            response_file = history_dir / f"response_{timestamp}.md"
            response_file.write_text(response)

            # 保存元数据
            if metadata:
                meta_file = history_dir / f"metadata_{timestamp}.json"
                meta_file.write_text(json.dumps(metadata, indent=2))

        except Exception as e:
            logger.error(f"Failed to save prompt history: {e}")

    def get_template_stats(self) -> Dict[str, Any]:
        """获取模板统计信息"""
        return {
            "total_templates": len(self.templates),
            "template_names": list(self.templates.keys()),
            "total_examples": len(self.examples),
            "example_names": list(self.examples.keys()),
            "has_utility_functions": bool(self.utility_functions),
            "has_suggestions": bool(self.suggestions),
            "has_checker_template": bool(self.checker_template),
            "template_dir": str(self.template_dir),
            "example_dir": str(self.example_dir)
        }

    def add_example(self, example: PromptExample):
        """动态添加示例"""
        self.examples[example.name] = example
        logger.info(f"Added example: {example.name}")

    def get_example(self, name: str) -> Optional[PromptExample]:
        """获取特定示例"""
        return self.examples.get(name)

    def list_examples(self) -> List[str]:
        """列出所有示例名称"""
        return list(self.examples.keys())


# 创建默认实例
_default_manager: Optional[EnhancedPromptManager] = None


def get_default_prompt_manager() -> EnhancedPromptManager:
    """获取默认的提示词管理器实例"""
    global _default_manager
    if _default_manager is None:
        _default_manager = EnhancedPromptManager()
    return _default_manager


# 保持向后兼容 - 旧的 PromptManager 类
class PromptManager:
    """向后兼容的提示词管理器（委托给 EnhancedPromptManager）"""

    def __init__(self, template_dir: Optional[Path] = None):
        self._enhanced = EnhancedPromptManager(template_dir)

    # 委托属性访问到内部 EnhancedPromptManager
    @property
    def utility_functions(self):
        return self._enhanced.utility_functions

    @property
    def suggestions(self):
        return self._enhanced.suggestions

    @property
    def checker_template(self):
        return self._enhanced.checker_template

    @property
    def examples(self):
        return self._enhanced.examples

    def build_pattern_extraction_prompt(self, code_changes: str, metadata: Dict[str, Any]) -> str:
        context = PromptContext(input_type="patch")
        return self._enhanced.build_pattern_extraction_prompt(code_changes, context)

    def build_code_generation_prompt(self, vulnerability_type: str, framework: str,
                                   analysis_context: Dict[str, Any],
                                   retrieved_knowledge: Optional[List] = None) -> str:
        """构建代码生成提示词 - KNighter 风格，使用插件式架构"""
        # 加载知识库内容
        utility_functions = self.utility_functions if self.utility_functions else ""
        suggestions = self.suggestions if self.suggestions else ""
        checker_template = self.checker_template if self.checker_template else ""

        # 提取分析信息
        vuln_desc = analysis_context.get("description_summary", {}).get("summary", vulnerability_type)
        indicators = analysis_context.get("vulnerability_indicators", [])
        technical_terms = analysis_context.get("description_summary", {}).get("technical_terms", [])

        # 选择最相关的示例
        example_text = self._select_examples_for_code_generation(vulnerability_type)

        # 修复：格式化检索到的知识库内容
        knowledge_text = ""
        if retrieved_knowledge:
            knowledge_text = "\n# Retrieved Knowledge (RAG)\n\n"
            knowledge_text += "The following knowledge items were retrieved from the knowledge base and may help you understand similar vulnerabilities and detection patterns:\n\n"
            for i, item in enumerate(retrieved_knowledge[:5], 1):  # 限制显示前5条
                entry = item.entry if hasattr(item, 'entry') else item
                title = getattr(entry, 'title', 'Unknown')
                content = getattr(entry, 'content', '')[:800]  # 限制长度
                category = getattr(entry, 'category', 'general')
                knowledge_text += f"**{i}. [{category}] {title}**\n"
                knowledge_text += f"{content}...\n\n"
            knowledge_text += "---\n\n"

        # 构建 KNighter 风格的提示词
        prompt = f"""# Instruction

You are an expert in writing Clang Static Analyzer checkers using the **plugin-style architecture**.

Please help me write a CSA checker to detect the following vulnerability type.

**CRITICAL: Use PLUGIN-STYLE registration with `clang_registerCheckers`, NOT `BuiltinCheckerRegistration.h`**

The checker you write should:
1. Use `extern "C" void clang_registerCheckers(CheckerRegistry &registry)` for registration
2. NOT include `BuiltinCheckerRegistration.h`
3. Include `clang/StaticAnalyzer/Frontend/CheckerRegistry.h` instead
4. Be compilable as a plugin (.so file)

The version of the Clang environment is Clang-21. You should consider the API compatibility.

**Vulnerability Type:** {vulnerability_type}

**Description:** {vuln_desc}

**Key Indicators:** {', '.join(indicators) if indicators else 'None'}

**Technical Terms:** {', '.join(technical_terms) if technical_terms else 'None'}

{knowledge_text}{utility_functions}

{suggestions}

# Examples

{example_text}

# Checker Template

{checker_template}

# Formatting

Please show me the completed checker code following the plugin-style template above.

Your response should be like:

```cpp
{{checker code here}}
```

**IMPORTANT:**
- Start your response with the first `#include` statement
- DO NOT include any explanations or introductory text
- Use `clang_registerCheckers` for registration
- DO NOT use `BuiltinCheckerRegistration.h`
- Wrap your entire response in a single ```cpp code block

Generate the checker code now:"""

        return prompt

    def _select_examples_for_code_generation(self, vulnerability_type: str) -> str:
        """选择最相关的示例用于代码生成"""
        examples = list(self.examples.values())[:2]  # 取前2个示例
        if not examples:
            return "No examples available."

        text = ""
        for i, example in enumerate(examples, 1):
            text += f"## Example {{i}}: {{example.name}}\n\n"
            if example.pattern:
                text += "**Bug Pattern:**\n"
                text += example.pattern[:500] + "...\n\n"
            if example.plan:
                text += "**Implementation Plan:**\n"
                text += example.plan[:500] + "...\n\n"
            if example.checker_code:
                text += "**Complete Checker Code:**\n"
                text += "```cpp\n"
                text += example.checker_code
                text += "\n```\n\n"
            text += "---\n\n"
        return text

    def build_code_repair_prompt(self, original_code: str, issues: List[str]) -> str:
        return f"Fix issues in:\n{original_code}\n\nIssues:\n{chr(10).join(issues)}"

    def get_template_stats(self) -> Dict[str, Any]:
        return self._enhanced.get_template_stats()
