#!/usr/bin/env python3
"""
DKrypt Retry and Rate Limiting System
Handles automatic retries and rate limiting for resilient operations
"""

import time
import asyncio
from typing import Callable, Any, Optional, TypeVar, Coroutine
from functools import wraps
from .exceptions import RateLimitError, TimeoutError as DKryptTimeoutError
from .logger import logger


T = TypeVar('T')


class RetryConfig:
    """Configuration for retry behavior"""
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        retry_on_exceptions: tuple = (Exception,)
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.retry_on_exceptions = retry_on_exceptions
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for attempt"""
        import random
        delay = min(
            self.initial_delay * (self.exponential_base ** attempt),
            self.max_delay
        )
        
        if self.jitter:
            delay += random.uniform(0, delay * 0.1)
        
        return delay


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, rate: float, capacity: float):
        """
        Initialize rate limiter
        
        Args:
            rate: Tokens per second
            capacity: Maximum tokens in bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self, tokens: float = 1.0, timeout: Optional[float] = None) -> bool:
        """
        Acquire tokens from rate limiter
        
        Args:
            tokens: Number of tokens to acquire
            timeout: Timeout in seconds
            
        Returns:
            True if tokens acquired, False if timeout
        """
        start_time = time.time()
        
        while True:
            async with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(
                    self.capacity,
                    self.tokens + elapsed * self.rate
                )
                self.last_update = now
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            
            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    return False
            
            # Wait before retry
            await asyncio.sleep(0.01)
    
    def acquire_sync(self, tokens: float = 1.0, timeout: Optional[float] = None) -> bool:
        """
        Synchronous version of acquire
        
        Args:
            tokens: Number of tokens to acquire
            timeout: Timeout in seconds
            
        Returns:
            True if tokens acquired, False if timeout
        """
        start_time = time.time()
        
        while True:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    return False
            
            # Wait before retry
            time.sleep(0.01)


def retry(
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[int, Exception], None]] = None
):
    """
    Decorator for retrying functions
    
    Args:
        config: RetryConfig object
        on_retry: Callback function on retry
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            
            for attempt in range(config.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except config.retry_on_exceptions as e:
                    last_exception = e
                    
                    if attempt < config.max_retries:
                        delay = config.get_delay(attempt)
                        logger.warning(
                            f"Attempt {attempt + 1}/{config.max_retries + 1} failed: {str(e)}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        
                        if on_retry:
                            on_retry(attempt, e)
                        
                        time.sleep(delay)
                    else:
                        logger.error(f"All {config.max_retries + 1} attempts failed")
            
            raise last_exception
        
        return wrapper
    
    return decorator


def async_retry(
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[int, Exception], Any]] = None
):
    """
    Decorator for retrying async functions
    
    Args:
        config: RetryConfig object
        on_retry: Async callback function on retry
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable[..., Coroutine]) -> Callable[..., Coroutine]:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except config.retry_on_exceptions as e:
                    last_exception = e
                    
                    if attempt < config.max_retries:
                        delay = config.get_delay(attempt)
                        logger.warning(
                            f"Attempt {attempt + 1}/{config.max_retries + 1} failed: {str(e)}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        
                        if on_retry:
                            result = on_retry(attempt, e)
                            if asyncio.iscoroutine(result):
                                await result
                        
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"All {config.max_retries + 1} attempts failed")
            
            raise last_exception
        
        return wrapper
    
    return decorator


def with_rate_limit(
    rate: float,
    capacity: Optional[float] = None
):
    """
    Decorator to apply rate limiting to function
    
    Args:
        rate: Tokens per second
        capacity: Maximum tokens (defaults to rate)
    """
    if capacity is None:
        capacity = rate
    
    limiter = RateLimiter(rate, capacity)
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            limiter.acquire_sync(1.0)
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator


def with_timeout(seconds: float):
    """
    Decorator to apply timeout to function
    
    Args:
        seconds: Timeout in seconds
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            import signal
            
            def handler(signum, frame):
                raise DKryptTimeoutError(
                    f"Operation timed out after {seconds} seconds",
                    timeout=seconds
                )
            
            # Set signal handler (Unix only)
            try:
                old_handler = signal.signal(signal.SIGALRM, handler)
                signal.alarm(int(seconds))
                try:
                    result = func(*args, **kwargs)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
                return result
            except AttributeError:
                # signal.SIGALRM not available on Windows
                logger.warning("Timeout decorator not supported on Windows")
                return func(*args, **kwargs)
        
        return wrapper
    
    return decorator
