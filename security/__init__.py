"""
Security Module - Enterprise Edition
Provides enterprise-grade security features for the Tines MCP Server.
"""

import os
import time
import uuid
from enum import Enum
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# Core security components
from security.sanitizer import Sanitizer, SensitiveDataFilter
from security.audit import AuditLogger, AuditEvent, EventType, Outcome
from security.rate_limiter import RateLimiter, RateLimitExceeded
from security.circuit_breaker import CircuitBreaker, CircuitBreakerOpen, CircuitState
from security.validator import InputValidator, ValidationError
from security.secrets import SecretsManager, get_secret


# ==================== Error Codes ====================


class TinesErrorCode(Enum):
    """Standardized error codes for Tines MCP operations."""

    # Validation Errors (4xx)
    VALIDATION_ERROR = ("TINES_ERR_001", "Validation error", 400)
    NOT_FOUND = ("TINES_ERR_002", "Resource not found", 404)
    RATE_LIMITED = ("TINES_ERR_003", "Rate limit exceeded", 429)
    REQUEST_TOO_LARGE = ("TINES_ERR_004", "Request too large", 413)

    # Authentication Errors
    AUTH_REQUIRED = ("TINES_ERR_010", "Authentication required", 401)
    AUTH_FAILED = ("TINES_ERR_011", "Authentication failed", 401)
    TOKEN_EXPIRED = ("TINES_ERR_012", "Token expired", 401)
    AUTH_DENIED = ("TINES_ERR_013", "Access denied", 403)

    # Server Errors (5xx)
    API_ERROR = ("TINES_ERR_050", "API error", 500)
    SERVICE_UNAVAILABLE = ("TINES_ERR_051", "Service unavailable", 503)
    UPSTREAM_ERROR = ("TINES_ERR_052", "Upstream service error", 502)
    CIRCUIT_OPEN = ("TINES_ERR_053", "Circuit breaker open", 503)
    TIMEOUT = ("TINES_ERR_054", "Request timeout", 504)

    def __init__(self, code: str, message: str, status_code: int):
        self.code = code
        self.message = message
        self.status_code = status_code


# ==================== Correlation Context ====================


class CorrelationContext:
    """Thread-safe correlation ID management."""

    _correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")

    @classmethod
    def get_id(cls) -> str:
        """Get or generate correlation ID."""
        cid = cls._correlation_id.get()
        if not cid:
            cid = str(uuid.uuid4())
            cls._correlation_id.set(cid)
        return cid

    @classmethod
    def set_id(cls, cid: Optional[str]) -> None:
        """Set correlation ID."""
        cls._correlation_id.set(cid or str(uuid.uuid4()))

    @classmethod
    def reset(cls) -> str:
        """Reset and return new correlation ID."""
        cid = str(uuid.uuid4())
        cls._correlation_id.set(cid)
        return cid


# ==================== Global Instances ====================


# Configuration
_config = {
    "rate_limit_enabled": os.getenv("TINES_RATE_LIMIT_ENABLED", "true").lower() == "true",
    "circuit_breaker_enabled": os.getenv("TINES_CIRCUIT_BREAKER_ENABLED", "true").lower() == "true",
    "audit_enabled": os.getenv("TINES_AUDIT_ENABLED", "true").lower() == "true",
    "requests_per_minute": int(os.getenv("TINES_RATE_LIMIT", "60")),
    "log_level": os.getenv("TINES_LOG_LEVEL", "WARNING"),
}


# Singleton instances
_sanitizer: Optional[Sanitizer] = None
_audit_logger: Optional[AuditLogger] = None
_rate_limiter: Optional[RateLimiter] = None
_circuit_breaker: Optional[CircuitBreaker] = None
_secrets_manager: Optional[SecretsManager] = None
_start_time: float = time.time()


def _get_sanitizer() -> Sanitizer:
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = Sanitizer()
    return _sanitizer


def _get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        tenant = os.getenv("TINES_TENANT", "")
        _audit_logger = AuditLogger(
            name="tines-mcp",
            log_level=_config["log_level"],
            audit_log_path=os.getenv("TINES_AUDIT_LOG_PATH"),
            json_format=True,
            tenant=tenant,
        )
    return _audit_logger


def _get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(
            requests_per_minute=_config["requests_per_minute"],
            burst_size=10,
            enabled=_config["rate_limit_enabled"],
        )
    return _rate_limiter


def _get_circuit_breaker() -> CircuitBreaker:
    global _circuit_breaker
    if _circuit_breaker is None:
        _circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            success_threshold=3,
            timeout_seconds=60.0,
            enabled=_config["circuit_breaker_enabled"],
            name="tines-api",
        )
    return _circuit_breaker


def _get_secrets_manager() -> SecretsManager:
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# Lazy-loaded singletons as properties
class _SecurityComponents:
    @property
    def sanitizer(self) -> Sanitizer:
        return _get_sanitizer()

    @property
    def audit_logger(self) -> AuditLogger:
        return _get_audit_logger()

    @property
    def rate_limiter(self) -> RateLimiter:
        return _get_rate_limiter()

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return _get_circuit_breaker()

    @property
    def secrets_manager(self) -> SecretsManager:
        return _get_secrets_manager()


_components = _SecurityComponents()

# Expose as module-level properties for convenience
sanitizer = _components.sanitizer
audit_logger = _components.audit_logger
rate_limiter = _components.rate_limiter
circuit_breaker = _components.circuit_breaker
secrets_manager = _components.secrets_manager


# ==================== Helper Functions ====================


def create_error_response(
    error_code: TinesErrorCode,
    message: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> dict[str, Any]:
    """Create standardized error response."""
    response = {
        "error": message or error_code.message,
        "error_code": error_code.code,
        "correlation_id": CorrelationContext.get_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if metadata:
        response["metadata"] = metadata
    return response


def get_health_status() -> dict[str, Any]:
    """Get server health status."""
    uptime = time.time() - _start_time

    return {
        "status": "healthy",
        "version": "2.0.0",
        "uptime_seconds": int(uptime),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "rate_limiter": _get_rate_limiter().get_status(),
            "circuit_breaker": _get_circuit_breaker().get_status(),
            "secrets_manager": _get_secrets_manager().get_status(),
        },
    }


def log_startup() -> None:
    """Log server startup."""
    _get_audit_logger().log_startup({
        "version": "2.0.0",
        "rate_limit_enabled": _config["rate_limit_enabled"],
        "circuit_breaker_enabled": _config["circuit_breaker_enabled"],
    })


def log_shutdown() -> None:
    """Log server shutdown."""
    _get_audit_logger().log_shutdown({
        "uptime_seconds": int(time.time() - _start_time),
    })


# ==================== Exports ====================


__all__ = [
    # Core components
    "Sanitizer",
    "SensitiveDataFilter",
    "AuditLogger",
    "AuditEvent",
    "EventType",
    "Outcome",
    "RateLimiter",
    "RateLimitExceeded",
    "CircuitBreaker",
    "CircuitBreakerOpen",
    "CircuitState",
    "InputValidator",
    "ValidationError",
    "SecretsManager",
    "get_secret",
    # Error handling
    "TinesErrorCode",
    "create_error_response",
    # Correlation
    "CorrelationContext",
    # Singleton instances
    "sanitizer",
    "audit_logger",
    "rate_limiter",
    "circuit_breaker",
    "secrets_manager",
    # Utilities
    "get_health_status",
    "log_startup",
    "log_shutdown",
]
