# 使用示例

本目录包含LLM-Native框架的使用示例。

## 快速开始示例

### 1. 生成缓冲区溢出检测器

```bash
# 使用Clang Static Analyzer框架
python3 src/main.py generate_detector \
  --vulnerability_desc "检测数组越界访问的缓冲区溢出漏洞" \
  --target_framework clang \
  --output_dir ./examples/buffer_overflow_detector

# 查看生成的结果
ls -la ./examples/buffer_overflow_detector/
cat ./examples/buffer_overflow_detector/checker.cpp
```

### 2. 生成CodeQL查询

```bash
# 使用CodeQL框架
python3 src/main.py generate_detector \
  --vulnerability_desc "检测路径遍历漏洞，防止../等恶意路径访问" \
  --target_framework codeql \
  --output_dir ./examples/path_traversal_detector
```

### 3. 验证检测器

```bash
# 验证生成的检测器
python3 src/main.py validate_detector \
  --detector_path ./examples/buffer_overflow_detector/checker.cpp
```

### 4. 知识库搜索

```bash
# 搜索相关API信息
python3 src/main.py knowledge_search \
  --query "Clang Static Analyzer中如何检测内存访问" \
  --top_k 3
```

### 5. 框架评估

```bash
# 在基准数据集上评估框架性能
python3 src/main.py evaluate_framework \
  --benchmark_name juliet_suite \
  --output_dir ./examples/evaluation_results
```

## 示例文件结构

```
examples/
├── buffer_overflow_detector/          # 缓冲区溢出检测器示例
│   ├── checker.cpp                   # 生成的C++代码
│   ├── checker.h                     # 头文件
│   └── metadata.json                 # 元数据
├── path_traversal_detector/          # 路径遍历检测器示例
│   └── detector.ql                   # 生成的CodeQL查询
├── test_cases/                       # 测试用例
│   ├── buffer_overflow_test.c        # 缓冲区溢出测试
│   └── safe_code_test.c              # 安全代码测试
└── evaluation_results/               # 评估结果
    ├── evaluation_metrics.json       # 性能指标
    └── evaluation_summary.txt        # 总结报告
```

## 自定义示例

### 创建自己的检测器

1. **准备漏洞描述**：
   ```bash
   # 使用自然语言描述漏洞
   VULN_DESC="检测使用已释放指针的释放后使用(UAF)漏洞"
   ```

2. **选择目标框架**：
   ```bash
   # Clang适用于C/C++代码
   TARGET_FRAMEWORK="clang"

   # CodeQL适用于多语言支持
   TARGET_FRAMEWORK="codeql"
   ```

3. **生成检测器**：
   ```bash
   python3 src/main.py generate_detector \
     --vulnerability_desc "$VULN_DESC" \
     --target_framework "$TARGET_FRAMEWORK"
   ```

4. **验证和改进**：
   ```bash
   # 验证编译
   python3 src/main.py validate_detector --detector_path ./result/detector.cpp

   # 如果验证失败，框架会自动尝试修复
   ```

### 集成到现有工作流

```bash
# 在CI/CD中集成
#!/bin/bash
python3 src/main.py generate_detector \
  --vulnerability_desc "检测SQL注入漏洞" \
  --target_framework codeql \
  --output_dir ./security_checkers/

# 运行生成的检查器
codeql database analyze ./target_db ./security_checkers/detector.ql
```

## 故障排除

### 常见问题

1. **生成失败**：
   - 检查LLM API密钥配置
   - 确保网络连接正常
   - 查看日志文件了解具体错误

2. **编译失败**：
   - 检查目标框架的编译环境
   - 验证系统依赖（LLVM/Clang）
   - 查看编译错误信息

3. **验证失败**：
   - 确保测试用例格式正确
   - 检查基准数据集路径
   - 验证检测器逻辑

### 日志调试

```bash
# 启用详细日志
python3 src/main.py generate_detector \
  --vulnerability_desc "测试漏洞" \
  --verbose
```

日志文件位置：`logs/llm_native.log`
