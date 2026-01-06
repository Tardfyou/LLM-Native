# 预训练模型设置指南

## 概述

LLM-Native框架的知识库系统需要使用多个预训练模型来进行代码理解和语义检索。本文档介绍如何下载、配置和验证这些模型。

## 模型列表

### 1. microsoft/unixcoder-base
- **用途**: 代码专用嵌入模型，专门用于理解编程语言语义
- **特点**:
  - 支持多种编程语言（C/C++、Java、Python等）
  - 针对代码结构优化的嵌入表示
  - 上下文长度：8K tokens
- **下载大小**: ~500MB

### 2. sentence-transformers/paraphrase-MiniLM-L3-v2
- **用途**: 轻量化通用文本嵌入模型
- **特点**:
  - 快速推理，适合实时应用
  - 适用于代码注释和文档检索
  - 嵌入维度：384
- **下载大小**: ~90MB

### 3. BAAI/bge-m3
- **用途**: 多语言混合检索模型
- **特点**:
  - 支持中英文混合检索
  - 优秀的语义理解能力
  - 适合复杂的技术文档检索
- **下载大小**: ~2.2GB

## 自动下载设置

### 使用dev-manual.sh脚本（推荐）

```bash
# 在项目根目录执行
./scripts/dev-manual.sh
```

该脚本会：
1. 自动构建Docker镜像
2. 下载所有必要的预训练模型
3. 验证模型功能
4. 启动开发环境

### 手动下载（备选方案）

如果自动脚本失败，可以手动下载：

```bash
# 创建模型目录
mkdir -p pretrained_models

# 下载模型
python3 -c "
from transformers import AutoTokenizer, AutoModel
from sentence_transformers import SentenceTransformer

# 下载unixcoder
tokenizer = AutoTokenizer.from_pretrained('microsoft/unixcoder-base', cache_dir='./pretrained_models')
model = AutoModel.from_pretrained('microsoft/unixcoder-base', cache_dir='./pretrained_models')

# 下载MiniLM
model = SentenceTransformer('paraphrase-MiniLM-L3-v2', cache_folder='./pretrained_models')

# 下载BGE-M3
tokenizer = AutoTokenizer.from_pretrained('BAAI/bge-m3', cache_dir='./pretrained_models')
model = AutoModel.from_pretrained('BAAI/bge-m3', cache_dir='./pretrained_models')
"
```

## 模型验证

下载完成后，可以运行验证脚本：

```bash
# 在容器内运行
python3 scripts/verify_models.py

# 或在宿主机运行（需要安装相关依赖）
python3 scripts/verify_models.py
```

验证脚本会检查：
- 模型文件是否存在
- 模型是否可以正常加载
- 基本功能是否正常工作

## 配置说明

### 环境变量

在Docker环境中，模型路径通过以下环境变量配置：

```bash
# HuggingFace缓存目录
HF_HOME=/app/pretrained_models

# Transformers缓存目录
TRANSFORMERS_CACHE=/app/pretrained_models

# SentenceTransformers缓存目录
SENTENCE_TRANSFORMERS_HOME=/app/pretrained_models
```

### docker-compose.yml配置

```yaml
services:
  dev:
    volumes:
      - ./pretrained_models:/app/pretrained_models:cached
    environment:
      - HF_HOME=/app/pretrained_models
      - TRANSFORMERS_CACHE=/app/pretrained_models
```

## 磁盘空间要求

- **总下载大小**: ~2.8GB
- **解压后大小**: ~5-6GB
- **建议磁盘空间**: 10GB+

## 网络要求

- 需要稳定的互联网连接
- 首次下载可能需要10-30分钟
- 支持断点续传

## 故障排除

### 网络问题
如果下载失败，尝试：
1. 检查网络连接
2. 使用VPN（如果在受限网络环境）
3. 手动设置代理：
   ```bash
   export HTTP_PROXY=http://proxy.example.com:8080
   export HTTPS_PROXY=http://proxy.example.com:8080
   ```

### 磁盘空间不足
如果磁盘空间不足：
1. 清理临时文件：`docker system prune -a`
2. 删除旧的模型版本
3. 使用外部存储挂载

### 权限问题
如果遇到权限问题：
```bash
# 修复目录权限
sudo chown -R $USER:$USER pretrained_models/
chmod -R 755 pretrained_models/
```

## 性能优化

### CPU优化
- 使用 `paraphrase-MiniLM-L3-v2` 作为轻量化选项
- 减少批量处理大小

### GPU加速
- 确保CUDA可用：`nvidia-smi`
- 设置环境变量：
  ```bash
  export CUDA_VISIBLE_DEVICES=0
  ```

### 缓存优化
- 定期清理缓存：`rm -rf ~/.cache/huggingface/*`
- 使用SSD存储以提高加载速度

## 更新模型

### 检查更新
```bash
# 检查模型是否有新版本
python3 -c "
from transformers import AutoModel
model = AutoModel.from_pretrained('microsoft/unixcoder-base', local_files_only=True)
print('模型信息:', model.config)
"
```

### 强制重新下载
```bash
# 删除旧模型
rm -rf pretrained_models/models--microsoft--unixcoder-base/

# 重新下载
python3 -c "
from transformers import AutoModel
model = AutoModel.from_pretrained('microsoft/unixcoder-base', cache_dir='./pretrained_models', force_download=True)
"
```

## 相关链接

- [HuggingFace Model Hub](https://huggingface.co/models)
- [Sentence Transformers](https://www.sbert.net/)
- [BAAI bge-m3](https://huggingface.co/BAAI/bge-m3)
- [microsoft/unixcoder-base](https://huggingface.co/microsoft/unixcoder-base)
