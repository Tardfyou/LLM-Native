"""
Configuration Management for LLM-Native Static Analysis Framework
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from loguru import logger


class Config:
    """Configuration management class"""

    def __init__(self):
        self._config: Dict[str, Any] = {}

    @classmethod
    def load_from_file(cls, config_file: str) -> 'Config':
        """Load configuration from YAML file"""
        config = cls()

        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config._config = yaml.safe_load(f)

            # Resolve environment variables
            config._resolve_env_vars()

            # Set up paths
            config._setup_paths()

            logger.info(f"Configuration loaded from {config_file}")
            return config

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise

    def _resolve_env_vars(self):
        """Resolve environment variables in configuration"""
        def resolve_value(value: Any) -> Any:
            if isinstance(value, str):
                return os.path.expandvars(value)
            elif isinstance(value, dict):
                return {k: resolve_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [resolve_value(item) for item in value]
            else:
                return value

        self._config = resolve_value(self._config)

    def _setup_paths(self):
        """Set up and validate paths"""
        root_dir = Path(self._config.get('paths', {}).get('root_dir', '/app'))
        root_dir = Path(root_dir).resolve()

        # Update all path configurations to be absolute
        paths_config = self._config.get('paths', {})
        for key, path in paths_config.items():
            if key.endswith('_dir') and not Path(path).is_absolute():
                paths_config[key] = str(root_dir / path)

        # Create necessary directories
        dirs_to_create = [
            'results_dir', 'logs_dir', 'knowledge_dir', 'benchmarks_dir'
        ]

        for dir_key in dirs_to_create:
            dir_path = paths_config.get(dir_key)
            if dir_path:
                Path(dir_path).mkdir(parents=True, exist_ok=True)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        keys = key.split('.')
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

        return value if value is not None else default

    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration"""
        return self._config.copy()

    def save_to_file(self, config_file: str):
        """Save configuration to file"""
        config_path = Path(config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._config, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to {config_file}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise

    # Convenience methods for common configurations
    @property
    def project_name(self) -> str:
        return self.get('project.name', 'LLM-Native Framework')

    @property
    def project_version(self) -> str:
        return self.get('project.version', '0.1.0')

    @property
    def src_dir(self) -> Path:
        return Path(self.get('paths.src_dir', '/app/src'))

    @property
    def data_dir(self) -> Path:
        return Path(self.get('paths.data_dir', '/app/data'))

    @property
    def results_dir(self) -> Path:
        return Path(self.get('paths.results_dir', '/app/results'))

    @property
    def logs_dir(self) -> Path:
        return Path(self.get('paths.logs_dir', '/app/logs'))

    @property
    def knowledge_dir(self) -> Path:
        return Path(self.get('paths.knowledge_dir', '/app/data/knowledge'))

    @property
    def benchmarks_dir(self) -> Path:
        return Path(self.get('paths.benchmarks_dir', '/app/data/benchmarks'))

    @property
    def primary_llm_model(self) -> str:
        return self.get('llm.primary_model', 'gpt-4o')

    @property
    def vector_db_type(self) -> str:
        return self.get('knowledge_base.vector_db.type', 'chromadb')

    @property
    def supported_frameworks(self) -> List[str]:
        return self.get('generator.code_gen.target_frameworks', ['clang', 'codeql'])

    @property
    def max_generation_iterations(self) -> int:
        return self.get('generator.max_iterations', 3)

    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []

        # Check required paths
        required_paths = ['src_dir', 'data_dir', 'results_dir', 'logs_dir']
        for path_attr in required_paths:
            path = getattr(self, path_attr)
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    issues.append(f"Cannot create {path_attr}: {path} - {e}")

        # Check LLM configuration
        if not self.get('llm.keys_file'):
            issues.append("LLM keys file not configured")

        # Check knowledge base configuration
        if not self.get('knowledge_base.vector_db.type'):
            issues.append("Vector database type not configured")

        return issues
