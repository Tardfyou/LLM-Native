# 预训练模型下载指南

## 📋 概述

为了实现离线使用的知识库系统，需要预先下载所需的Embedding模型。本指南介绍如何下载和配置模型以供容器环境使用。

## 🎯 支持的模型

根据毕设需求，系统支持以下类型的Embedding模型：

### 代码专用模型
- **UniXcoder** (`microsoft/unixcoder-base`): 专门为代码设计的预训练模型
- **CodeBERT** (`microsoft/codebert-base`): 微软开源的代码理解模型

### 通用文本模型
- **BGE-M3** (`BAAI/bge-m3`): 多语言、多任务的通用嵌入模型

### 轻量级测试模型
- **MiniLM** (`sentence-transformers/paraphrase-MiniLM-L3-v2`): 轻量级通用模型

## 🚀 下载步骤

### 1. 安装依赖
```bash
pip install sentence-transformers transformers torch
```

### 2. 下载模型
```bash
# 切换到项目根目录
cd /path/to/LLM-Native

# 运行下载脚本
python3 scripts/download_models.py
```

### 3. 验证下载
```bash
# 检查模型下载状态
python3 scripts/check_models.py
```

## 📁 文件结构

下载完成后，模型文件将存储在：
```
LLM-Native/
├── pretrained_models/           # 模型缓存目录
│   ├── models--microsoft--unixcoder-base/
│   ├── models--microsoft--codebert-base/
│   ├── models--BAAI--bge-m3/
│   └── models--sentence-transformers--paraphrase-MiniLM-L3-v2/
```

## 🐳 容器使用

### 自动挂载
启动开发环境时，系统会自动挂载本地模型缓存：
```bash
./scripts/dev-manual.sh
```

### 手动挂载
如果需要自定义挂载：
```bash
docker run -v /path/to/LLM-Native/pretrained_models:/root/.cache/huggingface/hub:cached \
           -e HF_HUB_CACHE=/root/.cache/huggingface/hub \
           your-image
```

## 🔧 环境变量配置

容器内会自动设置以下环境变量：
- `HF_HUB_CACHE=/root/.cache/huggingface/hub`
- `TRANSFORMERS_CACHE=/root/.cache/huggingface/hub`
- `HF_HUB_OFFLINE=1` (优先使用本地缓存)

## 🧪 测试验证

运行环境测试脚本验证模型加载：
```bash
python3 scripts/test_environment_comprehensive.py
```

成功的测试输出应包含：
- ✅ 向量操作测试通过
- ✅ 句子嵌入测试通过
- 显示使用的模型名称

## 📊 模型大小估算

- **UniXcoder**: ~500MB
- **CodeBERT**: ~400MB
- **BGE-M3**: ~2.2GB
- **MiniLM**: ~70MB

**总计**: 约3.2GB

## 🚨 故障排除

### 网络问题
如果下载失败，检查网络连接或使用代理：
```bash
# 使用代理下载
export HTTP_PROXY=http://127.0.0.1:7897
export HTTPS_PROXY=http://127.0.0.1:7897
python3 scripts/download_models.py
```

### 磁盘空间不足
确保有足够的磁盘空间（建议预留5GB）。

### 权限问题
确保对`pretrained_models`目录有写权限。

## 🔄 更新模型

如需更新模型或添加新模型，编辑`scripts/download_models.py`中的`models_to_download`列表。

## 📚 相关链接

- [HuggingFace Model Hub](https://huggingface.co/models)
- [Sentence Transformers](https://www.sbert.net/)
- [UniXcoder Paper](https://arxiv.org/abs/2203.03860)
- [CodeBERT Paper](https://arxiv.org/abs/2002.08155)
