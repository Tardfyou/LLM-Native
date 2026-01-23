# Instruction

You are an expert in developing Clang Static Analyzer checkers with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

Your task is to create a detailed, step-by-step implementation plan for a Clang Static Analyzer checker that detects the specified bug pattern.

## Input

### Bug Pattern

{{bug_pattern}}

### Context

{{#if original_description}}
**Original Vulnerability Description:**
{{original_description}}
{{/if}}

{{#if patch}}
**Reference Patch:**
```diff
{{patch}}
```
{{/if}}

### Available Resources

You have access to the following utility functions that are already implemented:

**Utility Functions:**

```cpp
{{utility_functions}}
```

**Development Suggestions:**

{{suggestions}}

**Code Template:**

```cpp
{{checker_template}}
```

## Your Task

Create a comprehensive implementation plan that includes:

### 1. Program State Design

Decide if you need to track program state across analysis. Specify:
- What state to track (use `REGISTER_TRAIT_WITH_PROGRAMSTATE`, `REGISTER_MAP_WITH_PROGRAMSTATE`, or `REGISTER_SET_WITH_PROGRAMSTATE`)
- What information to store
- When to update the state

### 2. Callback Selection

Choose the appropriate checker callbacks. Common options:
- `checkPreStmt<T>` / `checkPostStmt<T>` - For statement-level analysis
- `checkPreCall` / `checkPostCall` - For function call analysis
- `checkBranchCondition` - For analyzing branch conditions
- `checkLocation` - For memory load/store operations
- `checkBind` - For tracking variable assignments
- `checkBeginFunction` / `checkEndFunction` - For function lifecycle

### 3. Step-by-Step Implementation

For each callback, provide:
1. What to check/analyze
2. What state to read/update
3. What conditions indicate a bug
4. How to report the bug

### 4. Edge Cases

Consider and address:
- NULL pointers
- Unknown values
- Symbolic values without constraints
- Multiple code paths
- Different variable scopes

## Output Format

Provide your plan in the following structure:

```markdown
## Implementation Plan

### 1. Program State Design

[Describe what program state to track and why]

**State Definition:**
```cpp
REGISTER_MAP_WITH_PROGRAMSTATE(...)
```

### 2. Callback Selection

**Primary Callbacks:**
- [Callback 1]: [Purpose]
- [Callback 2]: [Purpose]

**Helper Callbacks (if needed):**
- [Callback 3]: [Purpose]

### 3. Implementation Steps

#### Step 1: [Step Name]
[Callback to use]

**What to check:**
- [Check 1]
- [Check 2]

**What state to use:**
- Read: [State to read]
- Write: [State to update]

**Pseudocode:**
```cpp
void callback(...) const {
    // Step 1: ...
    // Step 2: ...
    // Step 3: ...
}
```

#### Step 2: [Step Name]
[Continue with detailed steps...]

### 4. Bug Detection Logic

**Conditions for bug report:**
1. [Condition 1]
2. [Condition 2]
3. [Condition 3]

**Bug report message:**
"[Short, clear description of the bug]"

### 5. Edge Cases and Special Handling

- **Case 1**: [How to handle]
- **Case 2**: [How to handle]
- **Case 3**: [How to handle]

### 6. Testing Considerations

**True Positive Cases:**
- [Example scenario 1]
- [Example scenario 2]

**True Negative Cases:**
- [Example scenario 1]
- [Example scenario 2]

## Implementation Notes

[Additional considerations or warnings]
```

## Important Guidelines

1. **Be Specific**: Each step should be concrete and actionable
2. **Use Available Utilities**: Leverage the provided utility functions
3. **Follow Best Practices**: Adhere to the development suggestions
4. **Consider All Cases**: Think about NULL, unknown, and edge cases
5. **Keep It Simple**: Use the simplest approach that achieves the goal
6. **Be Complete**: Don't leave placeholders or TODOs

## Feedback from Previous Attempts

{{#if failed_attempts}}
The following implementation attempts had issues. Learn from them:

{{failed_attempts}}
{{/if}}

---
*Your plan should be detailed enough that a developer can directly implement a working checker from it.*
