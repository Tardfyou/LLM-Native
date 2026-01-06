#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
下载预训练模型到本地缓存
支持离线使用的Embedding模型下载
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
            from sentence_transformers import SentenceTransformer
            logger.info(f"开始下载 SentenceTransformers 模型: {model_name}")

            # 设置下载参数
            os.environ['HF_HUB_TIMEOUT'] = '300'  # 5分钟超时

            model = SentenceTransformer(model_name)
            # 强制加载模型到内存以确保完全下载
            test_sentences = ["Hello world", "Test sentence"]
            embeddings = model.encode(test_sentences)

            logger.info(f"✅ {model_name} 下载完成，嵌入维度: {embeddings.shape[1]}")
            return True

        except Exception as e:
            logger.error(f"❌ {model_name} 下载失败: {str(e)}")
            return False

    def download_transformers_model(self, model_name: str) -> bool:
        """下载Transformers模型"""
        try:
            from transformers import AutoTokenizer, AutoModel
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

    def download_model(self, model_name: str, model_type: str = "sentence-transformers") -> bool:
        """下载模型"""
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
    ]

    print(f"📋 计划下载 {len(models_to_download)} 个核心模型（根据毕设需求精简）:")
    model_descriptions = {
        "microsoft/unixcoder-base": "代码专用语义嵌入模型",
        "microsoft/codebert-base": "代码理解模型",
        "BAAI/bge-m3": "多语言文本嵌入模型"
    }
    for model_name, model_type in models_to_download:
        desc = model_descriptions.get(model_name, "")
        print(f"  - {model_name} ({model_type}) - {desc}")

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
        print("🎉 所有核心模型下载完成！现在可以在离线环境中使用这些模型了。")
        print("\n💡 使用提示:")
        print("  1. 启动容器时会自动挂载模型缓存")
        print("  2. 运行测试脚本将优先使用这些核心模型")
        print("  3. 如需添加新模型，请根据毕设需求修改 models_to_download 列表")
        print("  4. 这3个模型已涵盖代码分析和文本嵌入的核心需求")
    else:
        print("⚠️  部分模型下载失败，请检查网络连接后重试")
        print("💡 可以单独下载失败的模型: python3 scripts/download_models.py --model MODEL_NAME")

    print(f"\n📁 模型存储位置: {downloader.cache_dir}")

if __name__ == "__main__":
    main()
