"""
配置加载工具
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

from loguru import logger


def load_config(config_path: str) -> Dict[str, Any]:
    """
    加载配置文件

    Args:
        config_path: 配置文件路径

    Returns:
        配置字典
    """
    with open(config_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 替换环境变量
    content = _replace_env_vars(content)

    # 解析YAML
    config = yaml.safe_load(content)

    # 设置项目根目录
    project_root = str(Path(config_path).parent.parent)
    config["paths"]["root_dir"] = project_root

    # 更新相对路径
    for key, value in config.get("paths", {}).items():
        if isinstance(value, str) and "${PROJECT_ROOT}" in value:
            config["paths"][key] = value.replace("${PROJECT_ROOT}", project_root)

    logger.info(f"配置加载完成: {config_path}")
    return config


def _replace_env_vars(content: str) -> str:
    """替换环境变量"""
    pattern = r'\$\{([^}:]+)(?::-([^}]*))?\}'

    def replacer(match):
        var_name = match.group(1)
        default = match.group(2) if match.group(2) is not None else ""
        return os.environ.get(var_name, default)

    return re.sub(pattern, replacer, content)
