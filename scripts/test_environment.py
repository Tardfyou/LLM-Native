#!/usr/bin/env python3
"""
Environment Test Script for LLM-Native Framework
测试开发环境是否正常工作
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def test_imports():
    """测试核心模块导入"""
    print("🔍 测试核心模块导入...")

    try:
        from core.config import Config
        print("✅ Config模块导入成功")

        from model.deepseek_client import DeepSeekClient
        print("✅ DeepSeek客户端导入成功")

        from frameworks.codeql import CodeQLFramework
        print("✅ CodeQL框架导入成功")

        from knowledge_base.manager import KnowledgeBaseManager
        print("✅ 知识库管理器导入成功")

        from generator.engine import GeneratorEngine
        print("✅ 生成引擎导入成功")

        from validator.validator import Validator
        print("✅ 验证器导入成功")

        return True
    except ImportError as e:
        print(f"❌ 导入失败: {e}")
        return False

def test_config():
    """测试配置加载"""
    print("\n🔍 测试配置加载...")

    try:
        from core.config import Config
        config = Config.load_from_file("config/config.yaml")
        print("✅ 配置文件加载成功")
        print(f"   项目名称: {config.project_name}")
        print(f"   LLM模型: {config.primary_llm_model}")
        return True
    except Exception as e:
        print(f"❌ 配置加载失败: {e}")
        return False

def test_deepseek_connection():
    """测试DeepSeek API连接"""
    print("\n🔍 测试DeepSeek API连接...")

    try:
        from model.deepseek_client import DeepSeekClient
        from model.llm_client import LLMConfig

        # 使用测试配置
        config = LLMConfig(
            api_key=os.getenv("DEEPSEEK_API_KEY", "sk-test-key"),
            model_name="deepseek-chat"
        )

        client = DeepSeekClient(config)
        print("✅ DeepSeek客户端创建成功")

        # 测试连接（可能需要真实API密钥）
        if os.getenv("DEEPSEEK_API_KEY"):
            is_available = client.is_available()
            if is_available:
                print("✅ DeepSeek API连接正常")
            else:
                print("⚠️  DeepSeek API连接失败（可能需要检查API密钥）")
        else:
            print("⚠️  未设置DEEPSEEK_API_KEY环境变量，跳过连接测试")

        return True
    except Exception as e:
        print(f"❌ DeepSeek连接测试失败: {e}")
        return False

def test_frameworks():
    """测试框架系统"""
    print("\n🔍 测试框架系统...")

    try:
        from frameworks.codeql import CodeQLFramework

        framework = CodeQLFramework()
        print("✅ CodeQL框架创建成功")
        print(f"   框架名称: {framework.name}")
        print(f"   描述: {framework.description}")
        print(f"   支持的语言: {framework.config.language}")

        # 检查是否可用
        is_available = framework.is_available()
        if is_available:
            print("✅ CodeQL可用")
        else:
            print("⚠️  CodeQL不可用（需要安装CodeQL CLI）")

        return True
    except Exception as e:
        print(f"❌ 框架测试失败: {e}")
        return False

def test_directories():
    """测试必要目录"""
    print("\n🔍 测试目录结构...")

    required_dirs = [
        "config",
        "src",
        "data/knowledge",
        "data/benchmarks",
        "results",
        "logs"
    ]

    all_exist = True
    for dir_path in required_dirs:
        full_path = Path(dir_path)
        if full_path.exists():
            print(f"✅ {dir_path} 目录存在")
        else:
            print(f"❌ {dir_path} 目录不存在")
            all_exist = False

    return all_exist

def main():
    """主测试函数"""
    print("🚀 LLM-Native Framework 环境测试")
    print("=" * 50)

    tests = [
        ("核心模块导入", test_imports),
        ("配置文件加载", test_config),
        ("DeepSeek API连接", test_deepseek_connection),
        ("框架系统", test_frameworks),
        ("目录结构", test_directories),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n📋 执行测试: {test_name}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} 测试通过")
            else:
                print(f"❌ {test_name} 测试失败")
        except Exception as e:
            print(f"❌ {test_name} 测试异常: {e}")

    print("\n" + "=" * 50)
    print(f"🎯 测试结果: {passed}/{total} 通过")

    if passed == total:
        print("🎉 所有测试通过！环境配置正确。")
        print("\n💡 接下来可以：")
        print("1. 运行生成器: python3 src/main.py generate_detector --help")
        print("2. 启动API服务器: python3 -m uvicorn src.api:app --host 0.0.0.0 --port 8000")
        print("3. 查看完整文档: cat README.md")
    else:
        print("⚠️  部分测试失败，请检查环境配置。")
        print("   查看文档: cat docs/development_workflow.md")

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
