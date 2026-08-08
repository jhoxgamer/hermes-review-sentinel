"""
Hermes Review Sentinel - Enterprise Security Pair Programmer
Enterprise-grade AI Security Pair Programmer CLI and GitHub Action.
"""

from hermes.config import (
    HermesConfig,
    load_config,
    DEFAULT_CONFIG,
    ExclusionConfig,
    DiffParsingConfig,
    OutputConfig,
    ResilienceConfig,
    SecurityConfig,
)

from hermes.diff_parser import (
    DiffParser,
    DiffHunk,
    ParsedDiff,
    DiffType,
)

from security_pair_programmer import (
    SecurityPairProgrammer,
    auto_fix_secrets,
    EXCLUDED_DIRS,
    MAX_FILE_SIZE,
)

from hermes.formatters import (
    OutputFormatter,
    FindingFormatter,
    OutputFormat,
    FindingFormatter,
)

from hermes.resilience import (
    CircuitBreaker,
    RateLimiter,
    RetryConfig,
    CircuitBreakerRegistry,
    get_rate_limiter,
    get_circuit_breaker,
    with_retry,
)

__version__ = "2.1.1"

__all__ = [
    # Config
    "HermesConfig",
    "load_config",
    "DEFAULT_CONFIG",
    "ExclusionConfig",
    "DiffParsingConfig",
    "OutputConfig",
    "ResilienceConfig",
    "SecurityConfig",
    
    # Diff Parser
    "DiffParser",
    "DiffHunk",
    "ParsedDiff",
    "DiffType",
    "SecurityPairProgrammer",
    "auto_fix_secrets",
    "EXCLUDED_DIRS",
    "MAX_FILE_SIZE",
    
    # Formatters
    "OutputFormatter",
    "FindingFormatter",
    "OutputFormat",
    "FindingFormatter",
    
    # Resilience
    "CircuitBreaker",
    "RateLimiter",
    "RetryConfig",
    "CircuitBreakerRegistry",
    "get_rate_limiter",
    "get_circuit_breaker",
    "with_retry",
    
    # Main classes
    "SecurityPairProgrammer",
    "auto_fix_secrets",
    "EXCLUDED_DIRS",
    "MAX_FILE_SIZE",
]

__version__ = "2.1.1"