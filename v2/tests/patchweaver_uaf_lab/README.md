# PATCHWEAVER UAF Lab

This fixture is a small C project for cross-file lifetime bugs.

Design goals:
- patch paths are relative to the fixture root
- `compile_commands.json` covers every relevant source file
- the primary mechanism is stale session-pointer use after release/expiry
- one untouched sibling file keeps a similar stale-pointer pattern for optional variant mining

Primary patch:
- [`session_lifetime.patch`](./session_lifetime.patch)

Recommended command:

```bash
python3 -m src.main generate \
  --patch ./tests/patchweaver_uaf_lab/session_lifetime.patch \
  --output ./tests/test_project_uaf \
  --validate-path ./tests/patchweaver_uaf_lab \
  --analyzer both
```
