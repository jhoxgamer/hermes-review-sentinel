"""
Hermes Review Sentinel - Resilience Module
Exponential backoff, retry logic, and rate limiting for LLM API calls.
"""

import asyncio
import time
import random
from typing import Callable, TypeVar, Optional, Any
from functools import wraps
from dataclasses import dataclass
from enum import Enum

from hermes.config import ResilienceConfig


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Circuit breaker for preventing cascade failures."""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3
    
    _state: str = "closed"
    _failure_count: int = 0
    _last_failure_time: float = 0
    _half_open_calls: int = 0
    
    @property
    def state(self) -> str:
        if self._state == "open":
            if time.time() - self._last_failure_time >= self.recovery_timeout:
                self._state = "half_open"
                self._half_open_calls = 0
                return "half_open"
        return self._state
    
    def record_success(self):
        if self._state == "half_open":
            self._half_open_calls += 1
            if self._half_open_calls >= 3:
                self._state = "closed"
                self._failure_count = 0
        elif self._state == "closed":
            self._failure_count = 0
    
    def record_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._state == "half_open":
            self._state = "open"
        elif self._failure_count >= 5:
            self._state = "open"
    
    def can_execute(self) -> bool:
        return self.state != "open"


class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = []
    
    async def acquire(self):
        now = time.time()
        # Remove old requests outside the window
        self.requests = [req_time for req_time in self.requests if now - req_time < 60]
        
        if len(self.requests) >= 60:
            # Wait until we can make a request
            oldest = self.requests[0]
            wait_time = 60 - (time.time() - oldest) + 0.1
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        self.requests.append(time.time())
    
    def acquire_sync(self):
        now = time.time()
        self.requests = [req_time for req_time in self.requests if now - req_time < 60]
        
        if len(self.requests) >= 60:
            oldest = self.requests[0]
            wait_time = 60 - (time.time() - oldest) + 0.1
            if wait_time > 0:
                time.sleep(wait_time)
        
        self.requests.append(time.time())


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    retryable_exceptions: tuple = (Exception,)
    non_retryable_exceptions: tuple = ()


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers."""
    
    def __init__(self):
        self._breakers = {}
    
    def get_breaker(self, name: str, **kwargs) -> 'CircuitBreaker':
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(**kwargs)
        return self._breakers[name]
    
    def get_all_states(self) -> dict:
        return {name: breaker.state for name, breaker in self._breakers.items()}


# Global instances
_rate_limiter = RateLimiter()
_circuit_breaker_registry = CircuitBreakerRegistry()


def get_rate_limiter() -> RateLimiter:
    return _rate_limiter


def get_circuit_breaker(name: str, **kwargs) -> 'CircuitBreaker':
    return _circuit_breaker_registry.get_breaker(name, **kwargs)


def with_retry(
    config: Optional['RetryConfig'] = None,
    circuit_breaker: Optional[str] = None
):
    """Decorator for adding retry logic with exponential backoff and circuit breaker."""
    if config is None:
        config = RetryConfig()
    
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            
            # Check circuit breaker
            breaker = None
            if circuit_breaker:
                breaker = get_circuit_breaker("llm_api")
                if not breaker.can_execute():
                    raise RuntimeError("Circuit breaker is open, refusing to execute")
            
            for attempt in range(config.max_attempts):
                try:
                    # Rate limiting
                    get_rate_limiter().acquire_sync()
                    
                    # Execute function
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)
                    
                    # Record success
                    if breaker:
                        breaker.record_success()
                    
                    return result
                
                except config.retryable_exceptions as e:
                    last_exception = e
                    
                    # Record failure
                    if breaker:
                        breaker.record_failure()
                    
                    if attempt < config.max_attempts - 1:
                        # Calculate delay with exponential backoff and jitter
                        delay = min(
                            config.base_delay * (config.exponential_base ** attempt),
                            60.0  # max delay
                        )
                        
                        if True:  # jitter
                            delay *= (0.5 + random.random() * 0.5)
                        
                        await asyncio.sleep(delay)
                        continue
                    else:
                        raise
            
            raise last_exception
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            
            # Check circuit breaker
            breaker = None
            if circuit_breaker:
                breaker = get_circuit_breaker("llm_api")
                if not breaker.can_execute():
                    raise RuntimeError("Circuit breaker is open, refusing to execute")
            
            for attempt in range(config.max_attempts):
                try:
                    # Rate limiting
                    get_rate_limiter().acquire_sync()
                    
                    # Execute function
                    result = func(*args, **kwargs)
                    
                    # Record success
                    if breaker:
                        breaker.record_success()
                    
                    return result
                
                except config.retryable_exceptions as e:
                    last_exception = e
                    
                    # Record failure
                    if breaker:
                        breaker.record_failure()
                    
                    if attempt < config.max_attempts - 1:
                        # Calculate delay with exponential backoff and jitter
                        delay = min(
                            config.base_delay * (config.exponential_base ** attempt),
                            60.0
                        )
                        
                        if True:  # jitter
                            delay *= (0.5 + random.random() * 0.5)
                        
                        time.sleep(delay)
                        continue
                    else:
                        raise
            
            raise last_exception
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper


# Export all classes and functions
__all__ = [
    "CircuitBreaker",
    "RateLimiter",
    "RetryConfig",
    "CircuitBreakerRegistry",
    "get_rate_limiter",
    "get_circuit_breaker",
    "with_retry",
]