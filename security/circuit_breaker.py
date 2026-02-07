"""
Circuit Breaker Pattern - Prevents cascading failures.
"""

import time
import threading
from enum import Enum
from typing import Optional, Callable, TypeVar, Any

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpen(Exception):
    def __init__(self, message: str = "Circuit breaker is open", state: CircuitState = CircuitState.OPEN):
        super().__init__(message)
        self.state = state


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, success_threshold: int = 3,
                 timeout_seconds: float = 60.0, enabled: bool = True, name: str = "default"):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled
        self.name = name
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._get_state()

    def _get_state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if self._last_failure_time:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.timeout_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
        return self._state

    def can_execute(self) -> bool:
        if not self.enabled:
            return True
        with self._lock:
            state = self._get_state()
            return state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def record_success(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._success_count = 0
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitState.OPEN

    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None

    def get_status(self) -> dict:
        with self._lock:
            state = self._get_state()
            time_until_half_open = None
            if state == CircuitState.OPEN and self._last_failure_time:
                elapsed = time.monotonic() - self._last_failure_time
                time_until_half_open = max(0, self.timeout_seconds - elapsed)
            return {
                "name": self.name,
                "state": state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "failure_threshold": self.failure_threshold,
                "success_threshold": self.success_threshold,
                "timeout_seconds": self.timeout_seconds,
                "time_until_half_open": time_until_half_open,
                "enabled": self.enabled,
            }

    def execute(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        if not self.can_execute():
            raise CircuitBreakerOpen(f"Circuit breaker '{self.name}' is open", state=self.state)
        try:
            result = func(*args, **kwargs)
            self.record_success()
            return result
        except Exception:
            self.record_failure()
            raise
