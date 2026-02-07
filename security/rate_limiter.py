"""
Rate Limiter - Token bucket algorithm implementation.
"""

import time
import threading


class RateLimitExceeded(Exception):
    def __init__(self, message: str = "Rate limit exceeded", retry_after: float = 0):
        super().__init__(message)
        self.retry_after = retry_after


class TokenBucket:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_update = time.monotonic()
        self.lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now

    def acquire(self, tokens: int = 1) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def try_acquire(self, tokens: int = 1) -> tuple[bool, float]:
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0
            needed = tokens - self.tokens
            wait_time = needed / self.rate
            return False, wait_time

    def get_remaining(self) -> int:
        with self.lock:
            self._refill()
            return int(self.tokens)


class RateLimiter:
    def __init__(self, requests_per_minute: int = 60, burst_size: int = 10, enabled: bool = True):
        self.enabled = enabled
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        rate_per_second = requests_per_minute / 60.0
        self._bucket = TokenBucket(rate=rate_per_second, capacity=burst_size)
        self._read_bucket = TokenBucket(rate=requests_per_minute * 2 / 60.0, capacity=burst_size * 2)
        self._write_bucket = TokenBucket(rate=requests_per_minute / 60.0, capacity=burst_size)
        self._delete_bucket = TokenBucket(rate=requests_per_minute / 2 / 60.0, capacity=max(5, burst_size // 2))

    def acquire(self, operation_type: str = "read") -> bool:
        if not self.enabled:
            return True
        if not self._bucket.acquire():
            return False
        bucket = self._get_operation_bucket(operation_type)
        return bucket.acquire()

    def try_acquire(self, operation_type: str = "read") -> tuple[bool, float]:
        if not self.enabled:
            return True, 0.0
        success, wait_time = self._bucket.try_acquire()
        if not success:
            return False, wait_time
        bucket = self._get_operation_bucket(operation_type)
        return bucket.try_acquire()

    def _get_operation_bucket(self, operation_type: str) -> TokenBucket:
        if operation_type == "delete":
            return self._delete_bucket
        elif operation_type == "write":
            return self._write_bucket
        return self._read_bucket

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "global_remaining": self._bucket.get_remaining(),
            "read_remaining": self._read_bucket.get_remaining(),
            "write_remaining": self._write_bucket.get_remaining(),
            "delete_remaining": self._delete_bucket.get_remaining(),
            "requests_per_minute": self.requests_per_minute,
        }

    def check_or_raise(self, operation_type: str = "read") -> None:
        success, retry_after = self.try_acquire(operation_type)
        if not success:
            raise RateLimitExceeded(f"Rate limit exceeded for {operation_type}", retry_after=retry_after)
