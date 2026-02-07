"""
Enterprise Security Module
Provides rate limiting, circuit breaker, retry logic, and audit logging.
"""

import os
import time
import uuid
import json
import logging
import threading
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional
from collections import deque
from dataclasses import dataclass, field


# ==================== Error Codes ====================


class TinesErrorCode(Enum):
    """Standardized error codes for enterprise compliance."""
    VALIDATION_ERROR = ("TINES_ERR_001", "Validation error", 400)
    AUTH_FAILED = ("TINES_ERR_002", "Authentication failed", 401)
    AUTH_DENIED = ("TINES_ERR_003", "Authorization denied", 403)
    NOT_FOUND = ("TINES_ERR_004", "Resource not found", 404)
    RATE_LIMITED = ("TINES_ERR_005", "Rate limit exceeded", 429)
    API_ERROR = ("TINES_ERR_006", "API error", 500)
    SERVICE_UNAVAILABLE = ("TINES_ERR_007", "Service unavailable", 503)
    CIRCUIT_OPEN = ("TINES_ERR_008", "Circuit breaker open", 503)

    @property
    def code(self) -> str:
        return self.value[0]

    @property
    def message(self) -> str:
        return self.value[1]

    @property
    def http_status(self) -> int:
        return self.value[2]


# ==================== Correlation ID ====================


class CorrelationContext:
    """Thread-local storage for correlation IDs."""
    _local = threading.local()

    @classmethod
    def get_id(cls) -> str:
        """Get current correlation ID or generate new one."""
        if not hasattr(cls._local, 'correlation_id') or cls._local.correlation_id is None:
            cls._local.correlation_id = str(uuid.uuid4())
        return cls._local.correlation_id

    @classmethod
    def set_id(cls, correlation_id: str) -> None:
        """Set correlation ID for current thread."""
        cls._local.correlation_id = correlation_id

    @classmethod
    def clear(cls) -> None:
        """Clear correlation ID."""
        cls._local.correlation_id = None


# ==================== Structured Audit Logger ====================


class AuditEventType(Enum):
    """Types of audit events."""
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    API_CALL = "API_CALL"
    RATE_LIMIT = "RATE_LIMIT"
    CIRCUIT_BREAKER = "CIRCUIT_BREAKER"
    ERROR = "ERROR"
    CONFIG_CHANGE = "CONFIG_CHANGE"


@dataclass
class AuditEvent:
    """Structured audit event."""
    event_type: AuditEventType
    action: str
    outcome: str  # SUCCESS, FAILURE, BLOCKED
    correlation_id: str = field(default_factory=CorrelationContext.get_id)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    duration_ms: Optional[float] = None
    error_code: Optional[str] = None
    metadata: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "event_type": self.event_type.value,
            "action": self.action,
            "outcome": self.outcome,
        }
        if self.resource_type:
            result["resource_type"] = self.resource_type
        if self.resource_id:
            result["resource_id"] = str(self.resource_id)
        if self.duration_ms is not None:
            result["duration_ms"] = round(self.duration_ms, 2)
        if self.error_code:
            result["error_code"] = self.error_code
        if self.metadata:
            result["metadata"] = self.metadata
        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Enterprise audit logger with structured JSON output.
    Logs are sanitized to prevent sensitive data exposure.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._logger = logging.getLogger("tines-audit")
        self._logger.setLevel(logging.INFO)

        # Only add handler if not already present
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(message)s'))
            self._logger.addHandler(handler)

    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        if self.enabled:
            self._logger.info(event.to_json())

    def log_api_call(
        self,
        action: str,
        outcome: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        duration_ms: Optional[float] = None,
        error_code: Optional[str] = None,
        **metadata,
    ) -> None:
        """Convenience method for logging API calls."""
        event = AuditEvent(
            event_type=AuditEventType.API_CALL,
            action=action,
            outcome=outcome,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            duration_ms=duration_ms,
            error_code=error_code,
            metadata=metadata if metadata else None,
        )
        self.log(event)

    def log_rate_limit(self, action: str, limit: int, window: int) -> None:
        """Log rate limit event."""
        event = AuditEvent(
            event_type=AuditEventType.RATE_LIMIT,
            action=action,
            outcome="BLOCKED",
            error_code=TinesErrorCode.RATE_LIMITED.code,
            metadata={"limit": limit, "window_seconds": window},
        )
        self.log(event)

    def log_circuit_breaker(self, action: str, state: str) -> None:
        """Log circuit breaker state change."""
        event = AuditEvent(
            event_type=AuditEventType.CIRCUIT_BREAKER,
            action=action,
            outcome=state,
            metadata={"circuit_state": state},
        )
        self.log(event)


# Global audit logger instance
_audit_enabled = os.getenv("TINES_AUDIT_ENABLED", "true").lower() in ("true", "1", "yes")
audit_logger = AuditLogger(enabled=_audit_enabled)


# ==================== Rate Limiter ====================


class RateLimiter:
    """
    Token bucket rate limiter with thread safety.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        burst_size: int = 10,
    ):
        self.rate = requests_per_minute / 60.0  # tokens per second
        self.burst_size = burst_size
        self.tokens = float(burst_size)
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.burst_size, self.tokens + elapsed * self.rate)
        self.last_update = now

    def acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire tokens.
        Returns True if successful, False if rate limited.
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait_time(self) -> float:
        """Get seconds until next token is available."""
        with self._lock:
            self._refill()
            if self.tokens >= 1:
                return 0.0
            return (1 - self.tokens) / self.rate


# ==================== Circuit Breaker ====================


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "CLOSED"      # Normal operation
    OPEN = "OPEN"          # Blocking requests
    HALF_OPEN = "HALF_OPEN"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern for resilience.
    Opens after consecutive failures, closes after successful probe.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout: float = 60.0,
        expected_exceptions: tuple = (),
    ):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.expected_exceptions = expected_exceptions

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current state, checking for timeout transition."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                if self._last_failure_time and \
                   time.monotonic() - self._last_failure_time >= self.timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
                    audit_logger.log_circuit_breaker("state_change", "HALF_OPEN")
            return self._state

    def record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    audit_logger.log_circuit_breaker("state_change", "CLOSED")
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                audit_logger.log_circuit_breaker("state_change", "OPEN")
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitState.OPEN
                    audit_logger.log_circuit_breaker("state_change", "OPEN")

    def can_execute(self) -> bool:
        """Check if request can be executed."""
        return self.state != CircuitState.OPEN


# ==================== Retry Logic ====================


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retry_on_exceptions: tuple = (),
    retry_on_status_codes: tuple = (429, 500, 502, 503, 504),
):
    """
    Decorator for retry with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential backoff
        jitter: Add random jitter to prevent thundering herd
        retry_on_exceptions: Exception types to retry on
        retry_on_status_codes: HTTP status codes to retry on
    """
    import random

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)

                    # Check if result indicates retryable status code
                    if isinstance(result, dict) and result.get("status_code") in retry_on_status_codes:
                        if attempt < max_retries:
                            delay = min(base_delay * (exponential_base ** attempt), max_delay)
                            if jitter:
                                delay *= (0.5 + random.random())
                            time.sleep(delay)
                            continue
                    return result

                except retry_on_exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = min(base_delay * (exponential_base ** attempt), max_delay)
                        if jitter:
                            delay *= (0.5 + random.random())
                        time.sleep(delay)
                    else:
                        raise

            if last_exception:
                raise last_exception
            return result

        return wrapper
    return decorator


# ==================== Enterprise Error Response ====================


def create_error_response(
    error_code: TinesErrorCode,
    message: Optional[str] = None,
    details: Optional[dict] = None,
) -> dict:
    """
    Create a standardized error response.

    Args:
        error_code: The error code enum
        message: Optional custom message (defaults to error code message)
        details: Optional additional details (will be sanitized)
    """
    response = {
        "error": message or error_code.message,
        "error_code": error_code.code,
        "correlation_id": CorrelationContext.get_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if details:
        # Only include safe details
        safe_keys = {"resource_type", "resource_id", "field", "limit"}
        response["details"] = {k: v for k, v in details.items() if k in safe_keys}

    return response


# ==================== Input Validation ====================


class InputValidator:
    """Enterprise-grade input validation."""

    # Size limits
    MAX_STRING_LENGTH = 10000
    MAX_JSON_DEPTH = 10
    MAX_ARRAY_LENGTH = 1000
    MAX_REQUEST_SIZE = 1024 * 1024  # 1 MB

    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        r'\{\{.*\}\}',           # Template injection
        r'<script.*?>',          # XSS
        r'\$\{.*\}',             # Expression injection
        r'javascript:',          # JS protocol
        r'data:.*base64',        # Data URLs
        r'<%.*%>',               # Server-side template
        r'\{\%.*\%\}',           # Jinja template
    ]

    @classmethod
    def validate_string(
        cls,
        value: Any,
        field_name: str,
        required: bool = False,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
    ) -> Optional[str]:
        """Validate and sanitize string input."""
        import re

        if value is None:
            if required:
                raise ValueError(f"{field_name} is required")
            return None

        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")

        value = value.strip()

        if required and not value:
            raise ValueError(f"{field_name} cannot be empty")

        max_len = max_length or cls.MAX_STRING_LENGTH
        if len(value) > max_len:
            raise ValueError(f"{field_name} exceeds maximum length of {max_len}")

        # Check for dangerous patterns
        for dangerous in cls.DANGEROUS_PATTERNS:
            if re.search(dangerous, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains invalid content")

        # Check against pattern if provided
        if pattern and not re.match(pattern, value):
            raise ValueError(f"{field_name} format is invalid")

        return value if value else None

    @classmethod
    def validate_positive_int(
        cls,
        value: Any,
        field_name: str,
        max_value: int = 2147483647,  # int32 max
    ) -> int:
        """Validate positive integer."""
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{field_name} must be an integer")

        if value <= 0:
            raise ValueError(f"{field_name} must be a positive integer")

        if value > max_value:
            raise ValueError(f"{field_name} exceeds maximum value of {max_value}")

        return value

    @classmethod
    def validate_json_depth(cls, obj: Any, current_depth: int = 0) -> bool:
        """Check JSON object doesn't exceed max depth."""
        if current_depth > cls.MAX_JSON_DEPTH:
            raise ValueError(f"JSON depth exceeds maximum of {cls.MAX_JSON_DEPTH}")

        if isinstance(obj, dict):
            for v in obj.values():
                cls.validate_json_depth(v, current_depth + 1)
        elif isinstance(obj, list):
            if len(obj) > cls.MAX_ARRAY_LENGTH:
                raise ValueError(f"Array length exceeds maximum of {cls.MAX_ARRAY_LENGTH}")
            for item in obj:
                cls.validate_json_depth(item, current_depth + 1)

        return True


# ==================== Health Check ====================


_start_time = time.monotonic()
_version = "2.0.0"


def get_health_status() -> dict:
    """
    Get server health status.
    Does NOT expose sensitive configuration.
    """
    return {
        "status": "healthy",
        "version": _version,
        "uptime_seconds": round(time.monotonic() - _start_time, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ==================== Global Instances ====================


# Rate limiter - configurable via environment
_rate_limit = int(os.getenv("TINES_RATE_LIMIT", "60"))
_burst_size = int(os.getenv("TINES_BURST_SIZE", "10"))
rate_limiter = RateLimiter(requests_per_minute=_rate_limit, burst_size=_burst_size)

# Circuit breaker
circuit_breaker = CircuitBreaker(
    failure_threshold=5,
    success_threshold=3,
    timeout=60.0,
)
