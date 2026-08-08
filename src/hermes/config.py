"""
Hermes Review Sentinel - Configuration System
Enterprise-grade configuration with Pydantic models for .hermes.yml support.
"""

from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml


class ExclusionConfig(BaseModel):
    """File and directory exclusion patterns."""
    directories: Set[str] = Field(
        default_factory=lambda: {
            "venv", ".venv", "node_modules", ".next", "__pycache__", ".git",
            "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
            "dist", "build", "target", ".gradle", "venv", "env"
        }
    )
    extensions: Set[str] = Field(
        default_factory=lambda: {
            ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe", ".bin", ".dat",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
            ".ttf", ".eot", ".map", ".min.js", ".min.css", ".lock",
            "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock"
        }
    )
    patterns: List[str] = Field(
        default_factory=lambda: [
            "*.min.js", "*.min.css", "*.bundle.js", "*.bundle.css",
            "*.generated.*", "*.auto.*", "*.generated.ts", "*.generated.tsx",
            "*.d.ts", "*.map", "*.lock", "*.pb.go", "*.pb.cc", "*.pb.h"
        ]
    )
    max_file_size: int = Field(default=1_024 * 1_024, description="Max file size in bytes (1MB default)")

    def should_skip(self, path: Path, project_root: Path) -> bool:
        """Check if path should be skipped based on exclusion rules."""
        try:
            rel_path = path.relative_to(project_root)
        except ValueError:
            return True
        
        rel_str = str(path)
        rel_str_posix = str(path).replace("\\", "/")
        parts = path.parts
        
        # Check excluded directories
        if any(part in self.directories for part in parts):
            return True
        
        # Check excluded extensions
        if path.suffix in self.extensions:
            return True
        
        # Check patterns
        import fnmatch
        path_str = str(path)
        path_posix = str(path).replace("\\", "/")
        for pattern in self.patterns:
            if fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(path_posix, pattern):
                return True
        
        # Check file size
        try:
            if path.stat().st_size > self.max_file_size:
                return True
        except (OSError, PermissionError):
            return True
        
        return False


class DiffParsingConfig(BaseModel):
    """Configuration for diff parsing and optimization."""
    ignore_lockfiles: bool = Field(default=True, description="Ignore lockfiles (package-lock.json, poetry.lock, etc.)")
    ignore_minified: bool = Field(default=True, description="Ignore minified files (*.min.js, *.min.css)")
    ignore_assets: bool = Field(default=True, description="Ignore asset files (images, fonts, etc.)")
    ignore_generated: bool = Field(default=True, description="Ignore auto-generated code")
    max_diff_size: int = Field(default=50000, description="Max diff size in characters before truncation")
    truncation_strategy: str = Field(default="smart", description="Truncation strategy: smart, head, tail, middle")
    context_lines: int = Field(default=3, description="Number of context lines in diff")


class OutputConfig(BaseModel):
    """Output formatting configuration."""
    format: str = Field(default="markdown", description="Output format: markdown, json, sarif")
    include_context: bool = Field(default=True, description="Include context lines in output")
    show_line_numbers: bool = Field(default=True, description="Show line numbers in output")
    group_by_file: bool = Field(default=True, description="Group findings by file")
    severity_threshold: str = Field(default="low", description="Minimum severity to report: low, medium, high, critical")


class ResilienceConfig(BaseModel):
    """Resilience and rate limiting configuration."""
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    base_delay: float = Field(default=1.0, description="Base delay in seconds for exponential backoff")
    max_delay: float = Field(default=60.0, description="Maximum delay in seconds")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    strict_mode: bool = Field(default=False, description="Fail pipeline on any error if true")
    rate_limit_requests: int = Field(default=60, description="Max requests per minute")
    rate_limit_window: int = Field(default=60, description="Rate limit window in seconds")


class SecurityConfig(BaseModel):
    """Security rules and thresholds configuration."""
    severity_threshold: str = Field(default="low", description="Minimum severity to report")
    custom_rules: Dict[str, Any] = Field(default_factory=dict, description="Custom security rules")
    excluded_rules: List[str] = Field(default_factory=list, description="Rules to exclude")
    severity_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "info": 0.1
        }
    )
    max_risk_score: float = Field(default=1.0, description="Maximum risk score before blocking")


class HermesConfig(BaseModel):
    """Main configuration model for Hermes Review Sentinel."""
    model_config = SettingsConfigDict(
        env_prefix="HERMES_",
        env_nested_delimiter="__",
        extra="ignore"
    )
    
    # Core settings
    version: str = Field(default="2.0.0", description="Configuration version")
    project_name: str = Field(default="", description="Project name for reporting")
    
    # Module configurations
    exclusions: ExclusionConfig = Field(default_factory=ExclusionConfig)
    diff_parsing: DiffParsingConfig = Field(default_factory=DiffParsingConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    resilience: ResilienceConfig = Field(default_factory=ResilienceConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    
    # LLM Settings
    llm_model: str = Field(default="gpt-4o-mini", description="LLM model to use")
    llm_temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    llm_max_tokens: int = Field(default=4096, gt=0)
    
    # Exit codes
    exit_code_clean: int = Field(default=0, description="Exit code for clean pass")
    exit_code_findings: int = Field(default=1, description="Exit code when findings found")
    exit_code_error: int = Field(default=2, description="Exit code for runtime/config errors")
    
    @classmethod
    def from_yaml(cls, yaml_path: Path) -> "HermesConfig":
        """Load configuration from .hermes.yml file."""
        if not yaml_path.exists():
            return cls()
        
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
        
        return cls(**data)
    
    def to_yaml(self, yaml_path: Path) -> None:
        """Save configuration to .hermes.yml file."""
        data = self.model_dump(exclude_unset=True, exclude_none=True)
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Default configuration instance
DEFAULT_CONFIG = HermesConfig()


def load_config(project_root: Path = None) -> HermesConfig:
    """Load configuration from .hermes.yml or return defaults."""
    if project_root is None:
        project_root = Path.cwd()
    
    config_path = project_root / ".hermes.yml"
    if config_path.exists():
        return HermesConfig.from_yaml(config_path)
    
    # Check for .hermes.yaml as well
    yaml_path = project_root / ".hermes.yaml"
    if yaml_path.exists():
        return HermesConfig.from_yaml(yaml_path)
    
    return DEFAULT_CONFIG


# Export all configuration classes
__all__ = [
    "HermesConfig",
    "ExclusionConfig",
    "DiffParsingConfig",
    "OutputConfig",
    "ResilienceConfig",
    "SecurityConfig",
    "ExclusionConfig",
    "DEFAULT_CONFIG",
    "load_config",
]