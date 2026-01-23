#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
下载预训练模型到本地缓存
支持离线使用的Embedding模型下载

功能：
1. 下载核心代码分析模型（transformers格式）
2. 下载兼容sentence-transformers的句子嵌入模型
3. 下载交叉编码器用于搜索结果重排序
4. 自动跳过已下载的模型
5. 支持离线环境使用

模型列表：
- 代码分析：microsoft/unixcoder-base, microsoft/codebert-base
- 句子嵌入：all-MiniLM-L6-v2（兼容sentence-transformers）
- 交叉编码器：BAAI/bge-reranker-base（用于重排序搜索结果）
"""

import os
import sys
from pathlib import Path
from typing import List, Tuple
import logging

# 在任何导入之前设置环境变量
cache_dir = Path("pretrained_models").resolve()
cache_dir.mkdir(parents=True, exist_ok=True)
os.environ['HF_HUB_CACHE'] = str(cache_dir)
os.environ['TRANSFORMERS_CACHE'] = str(cache_dir)
os.environ['HF_DATASETS_CACHE'] = str(cache_dir)
os.environ['HF_MODULES_CACHE'] = str(cache_dir)
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '0'  # 显示进度条

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ModelDownloader:
    """模型下载器"""

    def __init__(self, cache_dir: str = "pretrained_models"):
        self.cache_dir = Path(cache_dir).resolve()  # 获取绝对路径
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # 在导入相关库之前设置环境变量
        os.environ['HF_HUB_CACHE'] = str(self.cache_dir)
        os.environ['TRANSFORMERS_CACHE'] = str(self.cache_dir)
        os.environ['HF_DATASETS_CACHE'] = str(self.cache_dir)
        os.environ['HF_MODULES_CACHE'] = str(self.cache_dir)

        logger.info(f"模型缓存目录: {self.cache_dir}")
        logger.info(f"缓存环境变量已设置: HF_HUB_CACHE={os.environ.get('HF_HUB_CACHE')}")

    def download_sentence_transformers_model(self, model_name: str) -> bool:
        """下载SentenceTransformers模型"""
        try:
            logger.info(f"开始下载 SentenceTransformers 模型: {model_name}")

            # 设置下载参数
            os.environ['HF_HUB_TIMEOUT'] = '300'  # 5分钟超时

            # 检查是否是交叉编码器
            if 'reranker' in model_name or 'rerank' in model_name:
                # 下载交叉编码器
                from sentence_transformers import CrossEncoder  # type: ignore
                logger.info(f"下载交叉编码器: {model_name}")
                model = CrossEncoder(model_name)
                # 测试交叉编码器
                test_pairs = [("What is Python?", "Python is a programming language."), ("What is Java?", "Python is a programming language.")]
                scores = model.predict(test_pairs)
                logger.info(f"✅ 交叉编码器 {model_name} 下载完成，测试分数: {scores[:2]}")
            else:
                # 下载普通句子嵌入模型
                from sentence_transformers import SentenceTransformer  # type: ignore
                model = SentenceTransformer(model_name)
                # 强制加载模型到内存以确保完全下载
                test_sentences = ["Hello world", "Test sentence"]
                embeddings = model.encode(test_sentences)
                logger.info(f"✅ 句子嵌入模型 {model_name} 下载完成，嵌入维度: {embeddings.shape[1]}")

            return True

        except Exception as e:
            logger.error(f"❌ {model_name} 下载失败: {str(e)}")
            return False

    def download_transformers_model(self, model_name: str) -> bool:
        """下载Transformers模型"""
        try:
            from transformers import AutoTokenizer, AutoModel  # type: ignore
            logger.info(f"开始下载 Transformers 模型: {model_name}")

            # 设置下载参数
            os.environ['HF_HUB_TIMEOUT'] = '300'

            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModel.from_pretrained(model_name)

            logger.info(f"✅ {model_name} 下载完成")
            return True

        except Exception as e:
            logger.error(f"❌ {model_name} 下载失败: {str(e)}")
            return False

    def is_model_downloaded(self, model_name: str, model_type: str) -> bool:
        """检查模型是否已下载"""
        try:
            # 检查本地缓存目录是否存在
            model_dir = self.cache_dir / f"models--{model_name.replace('/', '--')}"
            if not model_dir.exists():
                return False

            # 检查是否有snapshots目录（HuggingFace格式）
            snapshots_dir = model_dir / "snapshots"
            if snapshots_dir.exists():
                # 检查是否有至少一个snapshot目录
                snapshot_dirs = list(snapshots_dir.glob("*"))
                if snapshot_dirs:
                    # 检查任何一个snapshot是否有config.json
                    for snapshot_dir in snapshot_dirs:
                        config_path = snapshot_dir / "config.json"
                        if config_path.exists():
                            return True

            # 检查根目录是否有config.json（直接格式）
            config_path = model_dir / "config.json"
            if config_path.exists():
                return True

            return False
        except Exception as e:
            logger.debug(f"检查模型 {model_name} 时出错: {e}")
            return False

    def download_model(self, model_name: str, model_type: str = "sentence-transformers") -> bool:
        """下载模型（带重复检查）"""
        # 检查是否已下载
        if self.is_model_downloaded(model_name, model_type):
            logger.info(f"✅ {model_name} 已存在，跳过下载")
            return True

        # 下载模型
        if model_type == "sentence-transformers":
            return self.download_sentence_transformers_model(model_name)
        elif model_type == "transformers":
            return self.download_transformers_model(model_name)
        else:
            logger.error(f"不支持的模型类型: {model_type}")
            return False

def main():
    """主函数"""
    print("🤖 LLM-Native 预训练模型下载器")
    print("=" * 50)

    # 检查是否安装了必要的库
    required_packages = ["sentence_transformers", "transformers", "torch"]
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print("❌ 缺少必要的依赖包，请先安装:")
        print(f"pip install {' '.join(missing_packages)}")
        sys.exit(1)

    # 初始化下载器
    downloader = ModelDownloader()

    # 根据毕设.md定义的核心模型列表（只下载项目最需要的模型）
    models_to_download = [
        # 核心代码专用模型 - UniXcoder（最重要）
        ("microsoft/unixcoder-base", "transformers"),

        # 代码理解模型 - CodeBERT
        ("microsoft/codebert-base", "transformers"),

        # 多语言文本嵌入模型 - BGE-M3
        ("BAAI/bge-m3", "sentence-transformers"),

        # ===== 新增：兼容sentence-transformers的句子嵌入模型 =====

        # 通用英文句子嵌入 - 最常用，速度快，效果好 ⭐推荐下载
        ("all-MiniLM-L6-v2", "sentence-transformers"),

        # 交叉编码器 - 用于重排序搜索结果 ⭐重要补充
        ("BAAI/bge-reranker-base", "sentence-transformers"),

        # 高精度句子嵌入 - 更准确但模型更大
        # ("all-mpnet-base-v2", "sentence-transformers"),

        # 多语言句子嵌入 - 支持中文和其他语言
        # ("paraphrase-multilingual-MiniLM-L12-v2", "sentence-transformers"),

        # 代码搜索专用嵌入 - 专门为代码搜索优化
        # ("flax-sentence-embeddings/st-codesearch-distilroberta-base", "sentence-transformers"),
    ]

    print(f"📋 计划下载 {len(models_to_download)} 个模型（核心模型+兼容句子嵌入模型）:")
    print("📂 核心模型（代码分析专用）:")
    model_descriptions = {
        "microsoft/unixcoder-base": "代码专用语义嵌入模型（transformers）",
        "microsoft/codebert-base": "代码理解模型（transformers）",
        "BAAI/bge-m3": "多语言文本嵌入模型（sentence-transformers）",
    }
    for model_name, model_type in models_to_download[:3]:
        desc = model_descriptions.get(model_name, "")
        status = "✅ 已下载" if downloader.is_model_downloaded(model_name, model_type) else "🔄 待下载"
        print(f"  - {model_name} ({model_type}) - {desc} {status}")

    print("\n🔍 句子嵌入模型（兼容sentence-transformers，支持向量搜索和重排序）:")
    embedding_descriptions = {
        "all-MiniLM-L6-v2": "通用英文句子嵌入（最常用，速度快，推荐首选）",
        "BAAI/bge-reranker-base": "交叉编码器（用于重排序搜索结果，提升检索质量）",
        # "all-mpnet-base-v2": "高精度句子嵌入（更准确但模型更大）",
        # "paraphrase-multilingual-MiniLM-L12-v2": "多语言句子嵌入（支持中文等）",
        # "flax-sentence-embeddings/st-codesearch-distilroberta-base": "代码搜索专用嵌入（针对代码优化）"
    }
    # 只显示sentence-transformers类型的模型
    active_embedding_models = [m for m in models_to_download if len(m) == 2 and m[1] == "sentence-transformers"]
    for model_name, model_type in active_embedding_models:
        desc = embedding_descriptions.get(model_name, "")
        status = "✅ 已下载" if downloader.is_model_downloaded(model_name, model_type) else "🔄 待下载"
        print(f"  - {model_name} ({model_type}) - {desc} {status}")

    # 显示注释掉的模型
    commented_models = [
        ("all-mpnet-base-v2", "高精度句子嵌入（更准确但模型更大）"),
        ("paraphrase-multilingual-MiniLM-L12-v2", "多语言句子嵌入（支持中文等）"),
        ("flax-sentence-embeddings/st-codesearch-distilroberta-base", "代码搜索专用嵌入（针对代码优化）")
    ]
    if commented_models:
        print("\n  💭 其他可用模型（已注释，可根据需要取消注释）:")
        for model_name, desc in commented_models:
            print(f"  - {model_name} - {desc} 💤 已注释")

    print("\n🚀 开始下载...")
    print("⚠️  注意：下载过程可能需要一些时间，请耐心等待")

    success_count = 0
    total_count = len(models_to_download)

    for model_name, model_type in models_to_download:
        print(f"\n🔄 下载进度: {success_count + 1}/{total_count}")
        if downloader.download_model(model_name, model_type):
            success_count += 1
        else:
            print(f"⚠️  {model_name} 下载失败，跳过")

    print("\n" + "=" * 50)
    print("📊 下载结果统计:")
    print(f"✅ 成功: {success_count}/{total_count}")
    print(f"❌ 失败: {total_count - success_count}/{total_count}")

    if success_count == total_count:
        print("🎉 所有模型下载完成！现在可以在离线环境中使用这些模型了。")
        print("\n💡 使用提示:")
        print("  1. 启动容器时会自动挂载模型缓存")
        print("  2. 句子嵌入模型将启用知识库的向量搜索功能")
        print("  3. 交叉编码器将启用搜索结果重排序，提升检索质量")
        print("  4. 推荐优先使用 all-MiniLM-L6-v2 作为默认嵌入模型")
        print("  5. 多语言模型支持中文知识条目的处理")
        print("  6. 代码搜索模型专门优化了代码相关的语义搜索")
        print("  7. 如需添加新模型，请根据毕设需求修改 models_to_download 列表")
        print("\n🔧 技术说明:")
        print("  - 前3个模型：用于代码理解和生成")
        print("  - 第4个模型：句子嵌入，支持向量检索")
        print("  - 第5个模型：交叉编码器，用于重排序搜索结果")
        print("  - 已下载的模型会被自动跳过，避免重复下载")
        print("  - 如需更多模型，可取消注释其他模型")
    else:
        print("⚠️  部分模型下载失败，请检查网络连接后重试")
        print("💡 可以单独下载失败的模型: python3 scripts/download_models.py --model MODEL_NAME")

    print(f"\n📁 模型存储位置: {downloader.cache_dir}")

if __name__ == "__main__":
    main()
