#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查预训练模型下载状态
"""

import os
from pathlib import Path

def check_models():
    """检查模型下载状态"""
    pretrained_dir = Path("pretrained_models")

    if not pretrained_dir.exists():
        print("❌ pretrained_models 目录不存在")
        return False

    # 只检查毕设项目核心需要的模型
    models = [
        ("microsoft", "unixcoder-base"),      # 核心代码专用模型
        ("microsoft", "codebert-base"),       # 代码理解模型
        ("BAAI", "bge-m3")                    # 多语言文本嵌入模型
    ]

    found_count = 0
    for org, model in models:
        # 检查HuggingFace缓存格式
        cache_path = pretrained_dir / f"models--{org}--{model.replace('/', '--')}"

        if cache_path.exists() and any(cache_path.iterdir()):
            print(f"✅ {org}/{model} - 已下载")
            found_count += 1
        else:
            print(f"❌ {org}/{model} - 未下载")

    print(f"\n📊 模型下载状态: {found_count}/{len(models)} 个模型已下载")

    if found_count == len(models):
        print("🎉 所有核心模型已准备就绪！")
        print("   ✅ UniXcoder - 代码语义嵌入")
        print("   ✅ CodeBERT - 代码理解")
        print("   ✅ BGE-M3 - 多语言文本嵌入")
        return True
    else:
        print("⚠️  部分核心模型缺失，请运行下载脚本:")
        print("   python3 scripts/download_models.py")
        return False

if __name__ == "__main__":
    # 切换到项目根目录
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)

    print("🔍 检查预训练模型状态...")
    check_models()
