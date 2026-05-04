# Manual Test Steps

Use this lab from the `v2` directory.

## Paths

```bash
cd /home/spa/LLM-Native/v2

LAB_DIR="/home/spa/LLM-Native/v2/tests/manual_buffer_guard_lab"
PATCH_PATH="$LAB_DIR/patches/packet_parser_bounds_fix.patch"
CONFIG_PATH="/home/spa/LLM-Native/v2/config/config.yaml"
RUN_DIR="/home/spa/LLM-Native/v2/output/manual_buffer_guard_lab"
```

If you want to test with PackyAPI, set the provider in [config.yaml](/home/spa/LLM-Native/v2/config/config.yaml#L27) to `packyapi` and provide `PACKY_API_KEY` or fill `llm.api_keys.packyapi`.

## 1. Generate

```bash
python3 -m src.main \
  --config "$CONFIG_PATH" \
  generate \
  --patch "$PATCH_PATH" \
  --output "$RUN_DIR" \
  --validate-path "$LAB_DIR" \
  --analyzer csa \
  --verbose
```

## 2. Collect Evidence Into The Same Output Directory

```bash
python3 -m src.main \
  --config "$CONFIG_PATH" \
  evidence \
  --patch "$PATCH_PATH" \
  --evidence-dir "$LAB_DIR" \
  --output "$RUN_DIR" \
  --analyzer csa \
  --verbose
```

This writes `evidence_manifest.json` and analyzer evidence bundles directly into `$RUN_DIR`.

## 3. Refine Using The Generate Output And The Collected Evidence

```bash
python3 -m src.main \
  --config "$CONFIG_PATH" \
  refine \
  --input "$RUN_DIR" \
  --validate-path "$LAB_DIR" \
  --evidence-input "$RUN_DIR" \
  --patch "$PATCH_PATH" \
  --analyzer csa \
  --verbose
```

## Expected Data Flow

- `generate` writes the initial session artifacts into `$RUN_DIR`
- `evidence` appends evidence artifacts into the same `$RUN_DIR`
- `refine` reads both the generation session and the evidence artifacts from `$RUN_DIR`

## 4. Compile The Latest Refine Checker And Confirm A Hit

This is the shortest manual confirmation path when you want to inspect the newest refined CSA checker directly.

```bash
LATEST_REFINE_DIR="$(ls -1dt "$RUN_DIR"/csa/refinements/* | head -n1)"
CHECKER_CPP="$LATEST_REFINE_DIR/csa/BufferOverflowChecker.cpp"
CHECKER_SO="/tmp/manual_buffer_guard_lab_checker.so"

/usr/lib/llvm-18/bin/clang++ \
  -shared -fPIC -std=c++20 -O2 \
  -I/usr/lib/llvm-18/include \
  -I/usr/lib/llvm-18/include/clang \
  -I/usr/lib/llvm-18/include/clang/StaticAnalyzer \
  -I/usr/lib/llvm-18/include/clang/StaticAnalyzer/Core \
  -I/usr/lib/llvm-18/include/clang/StaticAnalyzer/Frontend \
  -I/usr/lib/llvm-18/include/llvm \
  "$CHECKER_CPP" \
  -L/usr/lib/llvm-18/lib \
  -lclang-cpp \
  -Wl,-rpath,/usr/lib/llvm-18/lib \
  -o "$CHECKER_SO"

/usr/lib/llvm-18/bin/clang --analyze \
  -Xclang -load -Xclang "$CHECKER_SO" \
  -Xclang -analyzer-checker -Xclang custom.BufferOverflowChecker \
  -Xclang -analyzer-display-progress \
  -Xclang -analyzer-output=text \
  "$LAB_DIR/src/packet_parser.c"
```

Expected result:

- A warning on `src/packet_parser.c:14`
- Message similar to `copy length is not proven smaller than the fixed destination buffer`
