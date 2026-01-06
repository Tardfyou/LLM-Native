# LLM-Native 预训练模型设置指南

本文档介绍如何在LLM-Native项目中设置和使用预训练模型。

## 📁 目录结构

```
LLM-Native/
├── config/
│   ├── models-config.yaml     # 模型下载配置
│   └── models-paths.yaml      # 模型路径映射
├── pretrained_models/         # 预训练模型存储目录
│   ├── embedding/             # 嵌入模型
│   ├── generation/            # 生成模型
│   ├── cache/                 # 缓存文件
│   └── model_inventory.txt    # 模型清单
└── scripts/
    ├── dev-manual.sh          # 环境构建脚本（包含模型下载）
    └── test_models.py         # 模型配置测试脚本
```

## 🚀 快速开始

### 1. 自动环境构建（推荐）

使用开发环境构建脚本，它会自动下载所有必要的模型：

```bash
# 进入项目目录
cd LLM-Native

# 运行环境构建脚本（包含模型下载）
./scripts/dev-manual.sh
```

该脚本会：
- ✅ 创建必要的目录结构
- ✅ 解析模型配置文件
- ✅ 下载所有配置的预训练模型
- ✅ 生成模型清单文件
- ✅ 启动开发容器

### 2. 手动模型下载

如果需要单独下载模型，可以使用Python脚本：

```bash
# 测试当前模型配置
python3 scripts/test_models.py

# 如果需要手动下载特定模型
pip install huggingface_hub
huggingface-cli download microsoft/unixcoder-base --local-dir pretrained_models/embedding/microsoft_unixcoder-base
```

## 📋 支持的模型

### 嵌入模型 (用于知识库向量化)

| 模型名称 | 大小 | 用途 | 下载状态 |
|---------|------|------|----------|
| `microsoft/unixcoder-base` | 500MB | 代码语义理解 | 高优先级 |
| `BAAI/bge-m3` | 2.2GB | 多语言文本嵌入 | 高优先级 |
| `sentence-transformers/paraphrase-MiniLM-L3-v2` | 90MB | 轻量级文本嵌入 | 中优先级 |

### 生成模型 (用于本地推理)

| 模型名称 | 大小 | 用途 | 下载状态 |
|---------|------|------|----------|
| `distilbert-base-uncased` | 250MB | 文本分类 | 中优先级 |
| `microsoft/DialoGPT-medium` | 1.5GB | 对话生成 | 低优先级 |

### API模型 (无需下载)

| 模型名称 | 提供商 | 用途 |
|---------|--------|------|
| `deepseek-chat` | DeepSeek | 通用对话 |
| `deepseek-reasoner` | DeepSeek | 推理增强 |

## ⚙️ 配置文件说明

### models-config.yaml

主配置文件，定义要下载的模型和下载策略：

```yaml
# 嵌入模型配置
embedding_models:
  - name: "microsoft/unixcoder-base"
    priority: "high"  # 下载优先级

# 生成模型配置
generation_models:
  - name: "distilbert-base-uncased"
    priority: "medium"

# 下载配置
download:
  network:
    timeout: 600  # 下载超时时间
    retries: 3    # 重试次数
  filter:
    by_priority: ["high", "medium"]  # 只下载指定优先级的模型
```

### models-paths.yaml

路径映射配置文件，定义模型在文件系统中的位置：

```yaml
# 基础路径
paths:
  models_base: "pretrained_models"
  embedding_base: "pretrained_models/embedding"

# 模型别名
aliases:
  code_embedder: "unixcoder_base"  # 代码嵌入器
  text_embedder: "bge_m3"          # 文本嵌入器
```

## 🐳 Docker集成

### 开发环境

模型文件通过volume挂载到容器中：

```yaml
volumes:
  - ./pretrained_models:/app/pretrained_models:cached
```

### 生产环境

生产环境使用只读挂载：

```yaml
volumes:
  - ./pretrained_models:/app/pretrained_models:ro
```

### 环境变量

容器内设置的环境变量：

```bash
-e HF_HOME=/app/pretrained_models
-e TRANSFORMERS_CACHE=/app/pretrained_models/cache
-e TOKENIZERS_PARALLELISM=false
```

## 🔍 验证安装

### 运行测试脚本

```bash
# 测试模型配置和目录结构
python3 scripts/test_models.py
```

### 手动验证

```bash
# 检查目录结构
ls -la pretrained_models/

# 检查模型清单
cat pretrained_models/model_inventory.txt

# 检查环境变量
echo $HF_HOME
echo $TRANSFORMERS_CACHE
```

### 在Python中验证

```python
import sys
sys.path.append('src')

from config.models_config import ModelsConfig

# 加载模型配置
config = ModelsConfig()
print("可用模型:", config.get_available_models())

# 测试模型加载
embedder = config.load_embedding_model('unixcoder_base')
print("嵌入模型加载成功")
```

## 🚨 故障排除

### 常见问题

#### 1. 模型下载失败

**症状**: 下载过程中断或失败
**解决**:
- 检查网络连接
- 增加超时时间
- 使用VPN或代理
- 手动下载特定模型

#### 2. 磁盘空间不足

**症状**: 下载过程中磁盘空间不足
**解决**:
- 检查可用磁盘空间 (`df -h`)
- 清理不需要的文件
- 只下载高优先级模型

#### 3. 容器内无法访问模型

**症状**: 容器内提示模型文件不存在
**解决**:
- 检查volume挂载是否正确
- 验证宿主机文件权限
- 重启容器

### 日志位置

- 环境构建日志: `scripts/test_results/`
- 模型下载日志: `pretrained_models/cache/logs/`
- 应用运行日志: `logs/`

## 📊 性能优化

### 存储优化

1. **使用符号链接**: 减少磁盘占用
2. **压缩存储**: 对不常用的模型进行压缩
3. **分层存储**: 频繁使用的模型放在SSD上

### 下载优化

1. **并发下载**: 合理设置并发数避免网络拥塞
2. **断点续传**: 支持中断后继续下载
3. **镜像加速**: 使用国内镜像源加速下载

### 运行时优化

1. **模型缓存**: 预加载常用模型到内存
2. **量化**: 使用量化版本减少内存占用
3. **GPU加速**: 利用GPU进行模型推理

## 🔄 更新模型

### 添加新模型

1. 编辑 `config/models-config.yaml`
2. 添加新的模型配置
3. 重新运行环境构建脚本

### 更新现有模型

```bash
# 删除旧版本
rm -rf pretrained_models/embedding/microsoft_unixcoder-base

# 重新下载
./scripts/dev-manual.sh
```

## 📞 技术支持

如果遇到问题，请：

1. 查看日志文件
2. 运行测试脚本诊断
3. 检查GitHub Issues
4. 提交新的Issue

---

**最后更新**: 2024-01-06
