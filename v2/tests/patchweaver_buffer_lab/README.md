# PATCHWEAVER Buffer Lab

This fixture is a small C project designed for end-to-end PATCHWEAVER runs.

Design goals:
- patch paths are relative to the project root
- `compile_commands.json` covers every relevant source file
- the primary vulnerability mechanism is buffer overflow via unsafe copy/build operations
- one untouched sibling file retains a similar mechanism for optional variant mining

Primary patch:
- [`buffer_guard.patch`](./buffer_guard.patch)

Recommended command:

```bash
python3 -m src.main generate \
  --patch ./tests/patchweaver_buffer_lab/buffer_guard.patch \
  --output ./tests/test_project \
  --validate-path ./tests/patchweaver_buffer_lab \
  --analyzer both
```
