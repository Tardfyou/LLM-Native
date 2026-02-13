# Instruction

You are an expert in developing Clang Static Analyzer checkers with decades of experience in the Clang project, particularly in the Static Analyzer plugin.

Your task is to create a detailed, step-by-step implementation plan for a Clang Static Analyzer checker that detects the specified bug pattern.

**IMPORTANT**: Write your plan in the style of Knighter checker implementation plans - clear, concrete steps with bullet points and specific API calls.

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

## Knighter Reference Examples

Study these example plans from Knighter to understand the expected style and detail level:

### Example 1: ArrayBoundChecker Plan

```
1. Register for the Location event:
   • The checker listens for memory load/store events via the check::Location callback.

2. Identify element accesses:
   • In checkLocation, obtain the memory region from the passed SVal.
   • Ensure the region is an ElementRegion (which represents an array element access). If not, ignore the event.

3. Extract the index used for the array access:
   • Retrieve the element index from the ElementRegion as a DefinedOrUnknownSVal.
   • If the index is a known zero constant (which is always safe), simply return without further action.

4. Determine the array bounds:
   • Use getDynamicElementCount() with the ElementRegion's super region and the element type to obtain the total number of elements in the array.
   • This function accounts for run-time size information.

5. Check index against the array size:
   • Use the program state method assumeInBoundDual() with the index and element count. This will yield two possible states: one where the index is in-bound (StInBound) and one where it is out-of-bound (StOutBound).
   • If you can prove that the index is out-of-bound (StOutBound exists) and not in-bound (StInBound does not exist), then this access is unsafe.

6. Report the bug:
   • Generate an error node for the out-of-bound case.
   • Create and populate a PathSensitiveBugReport with a clear message ("Access out-of-bound array element (buffer overflow)").
   • Use the source range from the load statement to highlight the error.
   • Emit the report so that the analyzer later presents it to the user.

7. Transition the state:
   • If the index is in-bound, update the state by transitioning to StInBound. This helps avoid duplicate warnings along different paths.
```

### Example 2: MallocChecker Plan (Memory Management)

```
1. Initialization and Modeling of Memory Regions
   • Set up program–state maps (for example, a RegionState map keyed by the allocation's "symbol") that hold a "RefState" value representing whether memory is allocated, released, relinquished, escaped, or zero allocated.
   • Register the checker with the CheckerRegistry and initialize bug types for various reports (double free, leak, use–after–free, mismatched deallocation, etc).

2. Modeling Memory Allocation
   • In callbacks for allocation calls (e.g. for malloc, calloc, new, new[]), intercept the call (via checkPostCall or EvalCall).
   • Create a symbolic heap region for the returned pointer using helper functions (like MallocMemAux). This binds the allocation site (the call's expression) to a conjured symbol.
   • Initialize the region's state by storing a RefState showing that the memory has been allocated (or allocated with size zero in special cases).

3. Modeling Memory Deallocation
   • Intercept deallocation calls (free, delete, delete[] and other custom free functions) in checkPreCall or checkPostCall.
   • Call helper functions such as FreeMemAux to update state:
     – Look up the associated symbolic region (by stripping casts, following base regions).
     – Check that the deallocation "family" matches the allocation family.
     – Detect errors like double free (if the region is already released or relinquished) or free on non–heap regions.
   • Update the region's state (mark it "released" or "relinquished") so that later accesses can be caught as use–after–free.

4. Reporting Bugs and Leaks
   • When an error condition is detected (memory already freed, pointer used after deallocation, freeing memory allocated on the stack, mismatching allocation/deallocation functions, or leak detection when dead symbols remain allocated), invoke one of the handler functions (e.g. HandleDoubleFree, HandleUseAfterFree, HandleLeak, etc).
   • Within these handlers, generate a non–fatal error node and create a PathSensitiveBugReport with a concrete diagnostic message.
   • Optionally, attach hints such as a call–stack or additional details to help guide the user.
```

### Available Resources

**Utility Functions:**

```cpp
{{utility_functions}}
```

**Development Suggestions:**

{{suggestions}}

## Your Task

Create a comprehensive implementation plan following the Knighter style shown above. Your plan should:

1. **Use numbered steps** (1. 2. 3...) with clear descriptions
2. **Use bullet points (•)** for sub-items within each step
3. **Include specific API calls** and function names
4. **Be concrete and actionable** - no vague descriptions

### Your plan should cover:

**If you need program state tracking:**
- What state to track (REGISTER_MAP_WITH_PROGRAMSTATE, etc.)
- When to update the state
- How to query the state

**For each callback:**
- What the callback checks for
- What state it reads/updates
- What API calls it uses
- When to report a bug

## Output Format

Provide your plan in the following structure (Knighter style):

```markdown
### Implementation Plan

1. [Step Name with Clear Purpose]
   • [First specific action with API call]
   • [Second specific action with API call]
   • [Third specific action if applicable]

2. [Next Step Name]
   • [Action description]
   • [More details]
   • [Even more details if needed]

3. [Continue with steps...]

Each step should be specific and include actual API calls where relevant.
```

## Important Guidelines

1. **Follow Knighter Style**: Numbered steps with bullet points
2. **Be Specific**: Include actual API names and function calls
3. **Be Concrete**: Each step should be directly implementable
4. **Use Available Utilities**: Reference the provided utility functions
5. **Consider Edge Cases**: NULL pointers, unknown values, multiple paths
6. **Keep It Focused**: Only include steps relevant to THIS vulnerability
7. **No Placeholders**: Don't use "TODO" or "implement this"

## Feedback from Previous Attempts

{{#if failed_attempts}}
The following implementation attempts had issues. Learn from them:

{{failed_attempts}}
{{/if}}

---
*Your plan should match the Knighter style shown in the examples above - concrete, actionable, and ready to implement.*
