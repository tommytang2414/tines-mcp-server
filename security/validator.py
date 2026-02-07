"""
Input Validator - Enterprise-grade input validation.
"""

import re
from typing import Any, Optional
from dataclasses import dataclass


class ValidationError(ValueError):
    def __init__(self, message: str, field: Optional[str] = None):
        super().__init__(message)
        self.field = field


@dataclass
class ValidationLimits:
    max_string_length: int = 10_000
    max_input_size: int = 1_048_576
    max_array_length: int = 1_000
    max_json_depth: int = 10
    max_pagination: int = 100
    min_id: int = 1
    max_id: int = 2_147_483_647


class InputValidator:
    DANGEROUS_PATTERNS = [
        re.compile(r'\{\{.*\}\}', re.DOTALL),
        re.compile(r'<script.*?>', re.IGNORECASE),
        re.compile(r'\$\{.*\}', re.DOTALL),
        re.compile(r'javascript:', re.IGNORECASE),
    ]
    limits = ValidationLimits()

    @classmethod
    def validate_positive_int(cls, value: int, field_name: str = "id", max_value: Optional[int] = None) -> int:
        if not isinstance(value, int):
            raise ValidationError(f"{field_name} must be an integer", field_name)
        if value < cls.limits.min_id:
            raise ValidationError(f"{field_name} must be a positive integer", field_name)
        if max_value and value > max_value:
            raise ValidationError(f"{field_name} exceeds maximum value", field_name)
        if value > cls.limits.max_id:
            raise ValidationError(f"{field_name} exceeds maximum value", field_name)
        return value

    @classmethod
    def validate_string(cls, value: Optional[str], field_name: str, required: bool = False,
                       max_length: Optional[int] = None, check_dangerous: bool = True) -> Optional[str]:
        if value is None:
            if required:
                raise ValidationError(f"{field_name} is required", field_name)
            return None
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string", field_name)
        value = value.strip()
        if required and not value:
            raise ValidationError(f"{field_name} cannot be empty", field_name)
        max_len = max_length or cls.limits.max_string_length
        if len(value) > max_len:
            raise ValidationError(f"{field_name} exceeds maximum length of {max_len} characters", field_name)
        if check_dangerous and value:
            for pattern in cls.DANGEROUS_PATTERNS:
                if pattern.search(value):
                    raise ValidationError(f"{field_name} contains disallowed content", field_name)
        return value if value else None

    @classmethod
    def validate_json_depth(cls, data: Any, current_depth: int = 0, max_depth: Optional[int] = None) -> None:
        max_depth = max_depth or cls.limits.max_json_depth
        if current_depth > max_depth:
            raise ValidationError(f"JSON exceeds maximum nesting depth of {max_depth}")
        if isinstance(data, dict):
            for value in data.values():
                cls.validate_json_depth(value, current_depth + 1, max_depth)
        elif isinstance(data, list):
            if len(data) > cls.limits.max_array_length:
                raise ValidationError(f"Array exceeds maximum length of {cls.limits.max_array_length}")
            for item in data:
                cls.validate_json_depth(item, current_depth + 1, max_depth)

    @classmethod
    def validate_pagination(cls, page: int, per_page: int) -> tuple[int, int]:
        if not isinstance(page, int) or page < 1:
            page = 1
        if not isinstance(per_page, int) or per_page < 1:
            per_page = 20
        if per_page > cls.limits.max_pagination:
            per_page = cls.limits.max_pagination
        return page, per_page

    @classmethod
    def validate_tenant(cls, tenant: str) -> str:
        if not tenant:
            raise ValidationError("tenant is required", "tenant")
        tenant = tenant.strip().lower()
        tenant = tenant.replace("http://", "").replace("https://", "")
        tenant = tenant.rstrip("/").split("/")[0]
        pattern = re.compile(r'^[a-z0-9][a-z0-9\-\.]*\.(tines\.com|tines\.io)$')
        if not pattern.match(tenant):
            raise ValidationError("tenant must be a valid Tines domain", "tenant")
        return tenant
