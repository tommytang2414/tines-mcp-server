"""
Audit Logging System
Enterprise-grade structured logging for compliance and security monitoring.
"""

import json
import logging
import logging.handlers
import os
import sys
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pathlib import Path

from security.sanitizer import Sanitizer


correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


def get_correlation_id() -> str:
    cid = correlation_id_var.get()
    if not cid:
        cid = str(uuid.uuid4())
        correlation_id_var.set(cid)
    return cid


class EventType(str, Enum):
    API_CALL = "API_CALL"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    RATE_LIMIT = "RATE_LIMIT"
    CIRCUIT_BREAKER = "CIRCUIT_BREAKER"
    ERROR = "ERROR"
    SECURITY_EVENT = "SECURITY_EVENT"
    STARTUP = "STARTUP"
    SHUTDOWN = "SHUTDOWN"


class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"


@dataclass
class AuditEvent:
    event_type: EventType
    action: str
    outcome: Outcome
    correlation_id: str = field(default_factory=get_correlation_id)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    duration_ms: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    actor: str = "mcp-client"
    tenant: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["event_type"] = self.event_type.value
        result["outcome"] = self.outcome.value
        return {k: v for k, v in result.items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class JSONFormatter(logging.Formatter):
    def __init__(self):
        super().__init__()
        self.sanitizer = Sanitizer()

    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "correlation_id": get_correlation_id(),
            "message": self.sanitizer.sanitize_string(record.getMessage()),
        }
        if record.exc_info:
            log_record["exception"] = self.sanitizer.sanitize_string(self.formatException(record.exc_info))
        return json.dumps(log_record, default=str)


class AuditLogger:
    _instance: Optional["AuditLogger"] = None
    _initialized: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, name: str = "tines-mcp", log_level: str = "WARNING",
                 audit_log_path: Optional[str] = None, json_format: bool = True,
                 tenant: Optional[str] = None):
        if self._initialized:
            return
        self.name = name
        self.log_level = getattr(logging, log_level.upper(), logging.WARNING)
        self.audit_log_path = audit_log_path
        self.tenant = tenant
        self.sanitizer = Sanitizer()
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)
        self.logger.handlers.clear()
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(console_handler)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        self._initialized = True

    def _mask_tenant(self, tenant: str | None) -> str | None:
        if not tenant:
            return None
        parts = tenant.split(".")
        if len(parts) >= 2:
            return f"***-{parts[0].split('-')[-1] if '-' in parts[0] else parts[0][:3]}.{'.'.join(parts[1:])}"
        return "***"

    def log_event(self, event: AuditEvent) -> None:
        if not event.tenant and self.tenant:
            event.tenant = self._mask_tenant(self.tenant)
        if event.metadata:
            event.metadata = self.sanitizer.sanitize_dict(event.metadata)
        if event.error_message:
            event.error_message = self.sanitizer.sanitize_string(event.error_message)
        log_level = logging.ERROR if event.outcome == Outcome.FAILURE else logging.INFO
        self.logger.log(log_level, event.to_json())

    def log_api_call(self, action: str, outcome: Outcome, resource_type: Optional[str] = None,
                     resource_id: Optional[str] = None, duration_ms: Optional[int] = None,
                     error_code: Optional[str] = None, error_message: Optional[str] = None,
                     metadata: Optional[dict[str, Any]] = None) -> None:
        event = AuditEvent(
            event_type=EventType.API_CALL, action=action, outcome=outcome,
            resource_type=resource_type, resource_id=str(resource_id) if resource_id else None,
            duration_ms=duration_ms, error_code=error_code, error_message=error_message,
            metadata=metadata or {}
        )
        self.log_event(event)

    def log_rate_limit(self, action: str, metadata: Optional[dict[str, Any]] = None) -> None:
        event = AuditEvent(
            event_type=EventType.RATE_LIMIT, action=action, outcome=Outcome.RATE_LIMITED,
            metadata=metadata or {}
        )
        self.log_event(event)

    def log_error(self, action: str, error: Exception, error_code: Optional[str] = None,
                  metadata: Optional[dict[str, Any]] = None) -> None:
        event = AuditEvent(
            event_type=EventType.ERROR, action=action, outcome=Outcome.FAILURE,
            error_code=error_code, error_message=self.sanitizer.sanitize_error(error),
            metadata=metadata or {}
        )
        self.log_event(event)

    def log_startup(self, metadata: Optional[dict[str, Any]] = None) -> None:
        event = AuditEvent(event_type=EventType.STARTUP, action="server_start",
                          outcome=Outcome.SUCCESS, metadata=metadata or {})
        self.log_event(event)

    def log_shutdown(self, metadata: Optional[dict[str, Any]] = None) -> None:
        event = AuditEvent(event_type=EventType.SHUTDOWN, action="server_stop",
                          outcome=Outcome.SUCCESS, metadata=metadata or {})
        self.log_event(event)
