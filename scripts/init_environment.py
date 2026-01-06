#!/usr/bin/env python3
"""
Environment Initialization Script
初始化LLM-Native框架的运行环境
"""

import os
import sys
from pathlib import Path
import subprocess as sp
import shutil

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from loguru import logger
from core.config import Config
from knowledge_base.manager import KnowledgeBaseManager


def init_environment():
    """Initialize the LLM-Native environment"""
    logger.info("Initializing LLM-Native environment...")

    # Get project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    # Create necessary directories
    dirs_to_create = [
        "data/knowledge",
        "data/benchmarks",
        "results",
        "logs",
        "config"
    ]

    for dir_path in dirs_to_create:
        full_path = project_root / dir_path
        full_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {full_path}")

    # Check and create default configuration files
    config_files = {
        "config/config.yaml": create_default_config,
        "llm_keys.yaml": create_default_llm_keys,
        "requirements.txt": None,  # Already exists
    }

    for config_file, creator_func in config_files.items():
        config_path = project_root / config_file
        if not config_path.exists() and creator_func:
            creator_func(config_path)
            logger.info(f"Created config file: {config_path}")

    # Validate configuration
    try:
        config = Config.load_from_file(str(project_root / "config/config.yaml"))
        issues = config.validate_config()

        if issues:
            logger.warning("Configuration issues found:")
            for issue in issues:
                logger.warning(f"  - {issue}")
        else:
            logger.success("Configuration validation passed")

        # Initialize knowledge base
        logger.info("Initializing knowledge base...")
        kb_manager = KnowledgeBaseManager(config)
        if kb_manager.setup(force_rebuild=False):
            logger.success("Knowledge base initialized successfully")
        else:
            logger.warning("Knowledge base initialization failed")

    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")

    # Check Python environment
    check_python_environment()

    # Check system dependencies
    check_system_dependencies()

    logger.success("Environment initialization completed!")
    logger.info("Next steps:")
    logger.info("1. Edit llm_keys.yaml with your API keys")
    logger.info("2. Run 'docker-compose up dev' to start development environment")
    logger.info("3. Or run 'python3 src/main.py --help' to see available commands")


def create_default_config(config_path: Path):
    """Create default configuration file"""
    default_config = """# LLM-Native Static Analysis Framework Configuration

# Project Settings
project:
  name: "LLM-Native Static Analysis Framework"
  version: "0.1.0"
  description: "面向缺陷检测的大预言模型原生静态分析框架"

# Directory Paths
paths:
  root_dir: "/app"
  src_dir: "/app/src"
  data_dir: "/app/data"
  results_dir: "/app/results"
  logs_dir: "/app/logs"
  knowledge_dir: "/app/data/knowledge"
  benchmarks_dir: "/app/data/benchmarks"
  config_dir: "/app/config"
  prompt_templates_dir: "/app/prompt_templates"

# LLM Configuration
llm:
  # Primary model for generation
  primary_model: "gpt-4o"
  # Fallback models
  fallback_models: ["claude-3-5-sonnet-20241022", "gemini-1.5-pro"]
  # API keys file
  keys_file: "llm_keys.yaml"
  # Generation parameters
  generation:
    temperature: 0.1
    max_tokens: 4096
    top_p: 0.9
    frequency_penalty: 0.0
    presence_penalty: 0.0

# Knowledge Base Configuration
knowledge_base:
  # Vector database settings
  vector_db:
    type: "chromadb"
    host: "localhost"
    port: 8001
    collection: "api_knowledge"
    # Embedding model
    embedding_model: "microsoft/unixcoder-base"

# Generation Engine Configuration
generator:
  # Maximum iterations for self-healing
  max_iterations: 3
  # Supported frameworks
  supported_frameworks: ["clang", "codeql"]

# Validation Configuration
validator:
  # Validation layers
  layers: ["compilation", "semantic", "performance"]

# Logging Configuration
logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "/app/logs/llm_native.log"

# Development Settings
development:
  enable_debug: false
  enable_profiling: false
  mock_llm_responses: false
"""

    config_path.write_text(default_config)


def create_default_llm_keys(keys_path: Path):
    """Create default LLM keys file"""
    default_keys = """# LLM API Keys Configuration
# Copy this file and fill in your actual API keys

# OpenAI API Key
openai_key: "sk-your-openai-key-here"

# Anthropic Claude API Key
claude_key: "sk-ant-api03-your-claude-key-here"

# Google Gemini API Key
google_key: "AIzaSy-your-gemini-key-here"

# DeepSeek API Key (optional)
deepseek_key: "sk-your-deepseek-key-here"

# For local models (optional)
# base_url: "http://localhost:8000/v1"
# api_key: "dummy"
"""

    keys_path.write_text(default_keys)


def check_python_environment():
    """Check Python environment"""
    logger.info("Checking Python environment...")

    # Check Python version
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        logger.warning(f"Python version {version.major}.{version.minor} may be too old. Recommended: 3.8+")
    else:
        logger.info(f"Python version: {version.major}.{version.minor}.{version.micro}")

    # Check required packages
    required_packages = [
        "loguru",
        "pyyaml",
        "pathlib",
    ]

    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        logger.warning(f"Missing core packages: {missing_packages}")
        logger.info("Run: pip install -r requirements.txt")
    else:
        logger.info("Core packages available")


def check_system_dependencies():
    """Check system dependencies"""
    logger.info("Checking system dependencies...")

    # Check for common build tools
    tools = ["gcc", "g++", "make", "cmake"]
    missing_tools = []

    for tool in tools:
        if not shutil.which(tool):
            missing_tools.append(tool)

    if missing_tools:
        logger.warning(f"Missing build tools: {missing_tools}")
        logger.info("On Ubuntu/Debian: sudo apt-get install build-essential cmake")
    else:
        logger.info("Build tools available")

    # Check for LLVM/Clang (optional but recommended)
    if not shutil.which("clang"):
        logger.warning("Clang not found. LLVM/Clang is recommended for Clang Static Analyzer development")
    else:
        logger.info("Clang available")


if __name__ == "__main__":
    try:
        init_environment()
    except KeyboardInterrupt:
        logger.info("Initialization interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Environment initialization failed: {e}")
        sys.exit(1)
