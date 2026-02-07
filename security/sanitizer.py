"""
Sensitive Data Sanitizer
Removes/masks sensitive information from logs, errors, and outputs.
"""

import re
from typing import Any


class SensitiveDataFilter:
    """Filter for detecting and redacting sensitive data patterns."""

    PATTERNS = [
        # API Tokens & Authentication Headers
        (r'x-user-token["\s:]+[^"}\s,]+', 'x-user-token: [REDACTED]'),
        (r'Authorization["\s:]+[^"}\s,]+', 'Authorization: [REDACTED]'),
        (r'Bearer\s+[A-Za-z0-9_\-\.]+', 'Bearer [REDACTED]'),
        # Generic Tokens & API Keys
        (r'(?i)token["\s:=]+[A-Za-z0-9_\-]{10,}', 'token: [REDACTED]'),
        (r'(?i)api[_-]?key["\s:=]+[A-Za-z0-9_\-]{10,}', 'api_key: [REDACTED]'),
        (r'(?i)secret[_-]?key["\s:=]+[^"}\s,]+', 'secret_key: [REDACTED]'),
        # OAuth & Session
        (r'(?i)client[_-]?secret["\s:=]+[^"}\s,]+', 'client_secret: [REDACTED]'),
        (r'(?i)access[_-]?token["\s:=]+[^"}\s,]+', 'access_token: [REDACTED]'),
        (r'(?i)refresh[_-]?token["\s:=]+[^"}\s,]+', 'refresh_token: [REDACTED]'),
        # AWS Credentials
        (r'(?i)aws[_-]?secret["\s:=]+[^"}\s,]+', 'aws_secret: [REDACTED]'),
        (r'AKIA[A-Z0-9]{16}', '[AWS_KEY_REDACTED]'),
        # Private Keys
        (r'(?i)private[_-]?key["\s:=]+[^"}\s,]+', 'private_key: [REDACTED]'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
         '[PRIVATE_KEY_REDACTED]'),
        # Passwords & Secrets
        (r'(?i)password["\s:=]+[^"}\s,]+', 'password: [REDACTED]'),
        (r'(?i)secret["\s:=]+[A-Za-z0-9_\-]{8,}', 'secret: [REDACTED]'),
        # Crypto-Specific
        (r'(?i)mnemonic["\s:=]+[^"}\s,]+', 'mnemonic: [REDACTED]'),
        (r'(?i)seed[_-]?phrase["\s:=]+[^"}\s,]+', 'seed_phrase: [REDACTED]'),
        (r'(?i)wallet[_-]?key["\s:=]+[^"}\s,]+', 'wallet_key: [REDACTED]'),
        # URLs with Embedded Credentials
        (r'://[^:]+:[^@]+@', '://[REDACTED]:[REDACTED]@'),
        # JWT Tokens
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', '[JWT_REDACTED]'),
    ]

    _compiled_patterns: list[tuple[re.Pattern, str]] | None = None

    @classmethod
    def _get_compiled_patterns(cls) -> list[tuple[re.Pattern, str]]:
        if cls._compiled_patterns is None:
            cls._compiled_patterns = [
                (re.compile(pattern, re.IGNORECASE), replacement)
                for pattern, replacement in cls.PATTERNS
            ]
        return cls._compiled_patterns

    @classmethod
    def sanitize(cls, text: str) -> str:
        if not text:
            return text
        result = text
        for pattern, replacement in cls._get_compiled_patterns():
            result = pattern.sub(replacement, result)
        return result


class Sanitizer:
    """Main sanitizer class for cleaning sensitive data."""

    def __init__(self, mask_char: str = "*", visible_chars: int = 4):
        self.mask_char = mask_char
        self.visible_chars = visible_chars
        self.filter = SensitiveDataFilter()

    def sanitize_string(self, text: str) -> str:
        return self.filter.sanitize(text)

    def mask_token(self, token: str) -> str:
        if not token:
            return "[EMPTY]"
        if len(token) <= self.visible_chars:
            return self.mask_char * len(token)
        return self.mask_char * (len(token) - self.visible_chars) + token[-self.visible_chars:]

    def sanitize_dict(self, data: dict[str, Any], sensitive_keys: set[str] | None = None) -> dict[str, Any]:
        if sensitive_keys is None:
            sensitive_keys = {
                "token", "api_token", "api_key", "secret", "password",
                "private_key", "secret_key", "access_token", "refresh_token",
                "mnemonic", "seed_phrase", "wallet_key", "x-user-token"
            }
        result = {}
        for key, value in data.items():
            key_lower = key.lower().replace("-", "_")
            if key_lower in sensitive_keys or any(s in key_lower for s in ["secret", "password", "token", "key"]):
                result[key] = self.mask_token(str(value)) if isinstance(value, str) else "[REDACTED]"
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value, sensitive_keys)
            elif isinstance(value, list):
                result[key] = [self.sanitize_dict(item, sensitive_keys) if isinstance(item, dict) else item for item in value]
            elif isinstance(value, str):
                result[key] = self.filter.sanitize(value)
            else:
                result[key] = value
        return result

    def sanitize_error(self, error: Exception) -> str:
        return self.filter.sanitize(str(error))
