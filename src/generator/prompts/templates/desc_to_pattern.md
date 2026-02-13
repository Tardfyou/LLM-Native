# Instruction

You are an expert security analyst and vulnerability researcher specializing in static analysis and program security. Your task is to analyze a vulnerability description and extract a structured bug pattern that can be used to generate a Clang Static Analyzer checker.

## Input Types

You may receive one of two types of input:
1. **Natural Language Description**: A description of a vulnerability in plain English
2. **Code Patch**: A git diff showing actual bug fixes

## Your Task

Analyze the provided vulnerability description or patch and extract the **bug pattern**.

## What is a Bug Pattern?

A **bug pattern** is the root cause and characteristic signature of a vulnerability. It should:
- Describe the specific conditions that lead to the bug
- Identify the key code elements involved (functions, operations, types)
- Be specific enough to distinguish buggy code from similar safe code
- Be general enough to detect the same pattern in different contexts

## Bug Pattern Structure

Your bug pattern should include:

1. **Vulnerability Type**: The category of security issue (e.g., Use-After-Free, Buffer Overflow, NULL Pointer Dereference)

2. **Trigger Conditions**: What specific sequence of operations or states causes the vulnerability

3. **Key Code Elements**:
   - Functions or operations involved
   - Data types or structures
   - Variable relationships
   - API calls or patterns

4. **Detection Strategy**: How to identify this pattern in code (what to look for)

5. **Code Examples**: If available, reference the problematic code

## Examples

{{examples}}

## Input

**Type:** {{input_type}}

**Vulnerability Description or Patch:**

{{input_description}}

{{#if patch}}
**Patch:**
```diff
{{patch}}
```
{{/if}}

## Output Format

Provide your response in the following format:

```markdown
## Bug Pattern

### Vulnerability Type
[Type of vulnerability]

### Trigger Conditions
[Describe what conditions trigger the bug]

### Key Code Elements
- **Functions/APIs**: [List relevant functions]
- **Types**: [Relevant data types]
- **Operations**: [Key operations involved]
- **Relationships**: [How variables relate]

### Detection Strategy
[How to detect this pattern in code]

### Example Pattern
[Optional: Concrete code pattern to match]

### Root Cause
[The fundamental reason this bug occurs]
```

## Important Notes

- Focus on the **pattern**, not just the specific instance
- Consider edge cases and variations of the pattern
- Think about how this would be detected programmatically
- The pattern should be actionable for generating a checker
- Include both what makes code buggy AND what makes similar code safe
