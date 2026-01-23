### Bug Pattern

**Vulnerability Type:** Uninitialized Variable Usage

**Trigger Conditions:**
A local variable is allocated using memory allocation functions like `kmalloc()` (which returns uninitialized memory) and then copied to user space using `copy_to_user()` without proper initialization or validation.

**Key Code Elements:**
- **Functions/APIs:** `kmalloc()`, `kzalloc()`, `copy_to_user()`, `copy_to_user()`
- **Types:** Any pointer type (e.g., `struct file_handle *`, `char *`)
- **Operations:** Memory allocation followed by memory copy to user space
- **Relationships:** Tracking whether allocated memory has been initialized before use

**Detection Strategy:**
1. Track memory allocations from `kmalloc()` (returns uninitialized memory) and `kzalloc()` (returns zeroed memory)
2. Mark regions allocated with `kmalloc()` as uninitialized
3. Mark regions allocated with `kzalloc()` as initialized
4. When detecting `copy_to_user()` calls, check if the source region is marked as uninitialized
5. Report a bug if uninitialized memory would be copied to user space

**Example Pattern:**
```c
// Buggy pattern
handle = kmalloc(sizeof(struct file_handle) + handle_bytes, GFP_KERNEL);
if (!handle)
    return -ENOMEM;
// Missing initialization of handle
copy_to_user(ufh, handle, sizeof(struct file_handle) + handle_bytes);  // BUG!

// Safe pattern
handle = kzalloc(sizeof(struct file_handle) + handle_bytes, GFP_KERNEL);  // Zeroed
if (!handle)
    return -ENOMEM;
// Now safe to copy to user
copy_to_user(ufh, handle, sizeof(struct file_handle) + handle_bytes);  // SAFE
```

**Root Cause:**
The root cause is the use of `kmalloc()` which returns memory containing whatever was previously at that location (potentially sensitive kernel data). When this uninitialized memory is copied to user space, it creates an information leak vulnerability. Using `kzalloc()` instead ensures memory is zeroed, preventing the leak.
