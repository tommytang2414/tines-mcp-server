# Tines MCP Server - Enterprise Security Specification

**Version:** 2.0
**Classification:** Internal - Security Sensitive
**Last Updated:** 2024-01

## 1. Overview

This specification defines enterprise-grade security requirements for the Tines MCP Server, designed for deployment in crypto/financial services environments with strict security and compliance requirements.

---

## 2. Security Architecture

### 2.1 Defense in Depth Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Layer 1: Input Validation                │
│         (Schema validation, sanitization, size limits)      │
├─────────────────────────────────────────────────────────────┤
│                 Layer 2: Authentication                     │
│           (API token validation, key rotation)              │
├─────────────────────────────────────────────────────────────┤
│                  Layer 3: Rate Limiting                     │
│        (Request throttling, circuit breaker)                │
├─────────────────────────────────────────────────────────────┤
│                Layer 4: Transport Security                  │
│         (TLS 1.2+, certificate validation)                  │
├─────────────────────────────────────────────────────────────┤
│                 Layer 5: Error Handling                     │
│      (Sanitized responses, no info leakage)                 │
├─────────────────────────────────────────────────────────────┤
│                 Layer 6: Audit Logging                      │
│       (Structured logs, correlation IDs)                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Authentication & Secrets Management

### 3.1 API Token Security

| Requirement | Implementation |
|-------------|----------------|
| Token storage | Environment variables only, never in code |
| Token format validation | Regex pattern matching before use |
| Token rotation | Support for graceful token rotation |
| Token masking | All logs/errors mask tokens completely |

### 3.2 Secrets Management Integration

```python
# Supported secret backends (priority order):
1. HashiCorp Vault (VAULT_ADDR, VAULT_TOKEN)
2. AWS Secrets Manager (AWS_REGION, secret ARN)
3. Azure Key Vault (AZURE_KEYVAULT_URL)
4. Environment variables (fallback)
```

### 3.3 Configuration Requirements

| Variable | Required | Description | Validation |
|----------|----------|-------------|------------|
| `TINES_TENANT` | Yes | Tines tenant domain | Must match `*.tines.com\|.io` |
| `TINES_API_TOKEN` | Yes | API authentication token | Min 16 chars, alphanumeric |
| `TINES_API_TIMEOUT` | No | Request timeout (1-120s) | Integer, default 30 |
| `TINES_RATE_LIMIT` | No | Requests per minute | Integer, default 60 |
| `TINES_LOG_LEVEL` | No | Logging level | WARNING/ERROR only in prod |
| `TINES_AUDIT_ENABLED` | No | Enable audit logging | Boolean, default true |

---

## 4. Transport Security

### 4.1 TLS Requirements

| Requirement | Specification |
|-------------|---------------|
| Minimum TLS version | TLS 1.2 (prefer 1.3) |
| Certificate validation | Always enabled, no bypass |
| Certificate pinning | Optional, configurable |
| Cipher suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |

### 4.2 HTTP Client Configuration

```python
httpx.Client(
    verify=True,                    # SSL verification mandatory
    http2=True,                     # HTTP/2 for performance
    follow_redirects=False,         # No auto-redirect (security)
    timeout=Timeout(connect=5.0, read=30.0, write=10.0),
    limits=Limits(
        max_connections=20,
        max_keepalive_connections=10,
        keepalive_expiry=30.0
    )
)
```

---

## 5. Rate Limiting & Resilience

### 5.1 Rate Limiting

| Limit Type | Default | Configurable |
|------------|---------|--------------|
| Requests per minute | 60 | Yes |
| Requests per second (burst) | 10 | Yes |
| Concurrent connections | 20 | Yes |

### 5.2 Circuit Breaker Pattern

```python
CircuitBreaker(
    failure_threshold=5,      # Open after 5 failures
    success_threshold=3,      # Close after 3 successes
    timeout=60,               # Reset after 60 seconds
    expected_exceptions=[     # Exceptions that trigger breaker
        TinesAPIError,
        httpx.TimeoutException,
        httpx.ConnectError
    ]
)
```

### 5.3 Retry Policy

```python
RetryPolicy(
    max_retries=3,
    backoff_factor=2.0,           # Exponential backoff
    retry_on_status=[429, 500, 502, 503, 504],
    retry_on_exceptions=[httpx.TimeoutException],
    jitter=True                    # Random jitter to prevent thundering herd
)
```

---

## 6. Input Validation

### 6.1 Validation Rules

| Input Type | Validation |
|------------|------------|
| Integer IDs | Positive, within int32 range |
| Strings | Length limits, character whitelist |
| JSON | Schema validation, max depth, max size |
| Pagination | page >= 1, 1 <= per_page <= 100 |
| URLs | HTTPS only, domain whitelist |

### 6.2 Size Limits

| Resource | Limit |
|----------|-------|
| Request body | 1 MB |
| JSON depth | 10 levels |
| String fields | 10,000 chars |
| Array elements | 1,000 items |

### 6.3 Sanitization Patterns

```python
DANGEROUS_PATTERNS = [
    r'\{\{.*\}\}',           # Template injection
    r'<script.*?>',          # XSS
    r'\$\{.*\}',             # Expression injection
    r'javascript:',          # JS protocol
    r'data:.*base64',        # Data URLs
]
```

---

## 7. Error Handling & Information Disclosure

### 7.1 Error Response Format

```json
{
    "error": "Human-readable message (no sensitive data)",
    "error_code": "TINES_ERR_001",
    "correlation_id": "uuid-for-support",
    "timestamp": "ISO-8601"
}
```

### 7.2 Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `TINES_ERR_001` | Validation error | 400 |
| `TINES_ERR_002` | Authentication failed | 401 |
| `TINES_ERR_003` | Authorization denied | 403 |
| `TINES_ERR_004` | Resource not found | 404 |
| `TINES_ERR_005` | Rate limit exceeded | 429 |
| `TINES_ERR_006` | API error | 500 |
| `TINES_ERR_007` | Service unavailable | 503 |

### 7.3 Sensitive Data Patterns (Auto-Redacted)

```python
REDACTION_PATTERNS = [
    # Authentication
    r'x-user-token["\s:]+[^"}\s,]+',
    r'Authorization["\s:]+[^"}\s,]+',
    r'Bearer\s+[A-Za-z0-9_\-\.]+',

    # API Keys
    r'api[_-]?key["\s:=]+[A-Za-z0-9_\-]{10,}',
    r'token["\s:=]+[A-Za-z0-9_\-]{10,}',

    # OAuth
    r'client_secret["\s:=]+[^"}\s,]+',
    r'access_token["\s:=]+[^"}\s,]+',
    r'refresh_token["\s:=]+[^"}\s,]+',

    # Cloud Credentials
    r'aws_secret["\s:=]+[^"}\s,]+',
    r'private_key["\s:=]+[^"}\s,]+',

    # Passwords
    r'password["\s:=]+[^"}\s,]+',
    r'secret["\s:=]+[A-Za-z0-9_\-]{8,}',

    # Embedded credentials in URLs
    r'://[^:]+:[^@]+@',

    # Crypto-specific
    r'mnemonic["\s:=]+[^"}\s,]+',
    r'seed["\s:=]+[^"}\s,]+',
    r'wallet[_-]?key["\s:=]+[^"}\s,]+',
]
```

---

## 8. Audit Logging

### 8.1 Audit Event Schema

```json
{
    "timestamp": "2024-01-15T10:30:00.000Z",
    "correlation_id": "uuid",
    "event_type": "API_CALL",
    "action": "create_story",
    "actor": "mcp-client",
    "resource_type": "story",
    "resource_id": "12345",
    "outcome": "SUCCESS|FAILURE",
    "duration_ms": 150,
    "metadata": {
        "team_id": 76073,
        "ip_address": "REDACTED"
    }
}
```

### 8.2 Logged Events

| Event Type | Description | Retention |
|------------|-------------|-----------|
| `AUTH_SUCCESS` | Successful authentication | 90 days |
| `AUTH_FAILURE` | Failed authentication attempt | 365 days |
| `API_CALL` | All API operations | 30 days |
| `RATE_LIMIT` | Rate limit triggered | 7 days |
| `ERROR` | Errors and exceptions | 90 days |
| `CONFIG_CHANGE` | Configuration modifications | 365 days |

### 8.3 Log Security

- NO sensitive data in logs (tokens, secrets, PII)
- Structured JSON format for SIEM ingestion
- Correlation IDs for request tracing
- Separate audit log file with restricted permissions

---

## 9. Dependency Security

### 9.1 Requirements

| Requirement | Implementation |
|-------------|----------------|
| Version pinning | Exact versions only (no ranges) |
| Hash verification | SHA256 hashes in requirements |
| Vulnerability scanning | Weekly automated scans |
| License compliance | MIT, Apache 2.0, BSD only |

### 9.2 Approved Dependencies

```
mcp==1.26.0
httpx==0.28.1
pydantic==2.12.5
python-dotenv==1.2.1
tenacity==8.2.3        # Retry logic
structlog==24.1.0      # Structured logging
```

---

## 10. Operational Security

### 10.1 Health Checks

```python
@mcp.tool()
def health_check() -> str:
    """
    Returns server health status.
    Does NOT expose sensitive configuration.
    """
    return {
        "status": "healthy",
        "version": "2.0.0",
        "uptime_seconds": get_uptime()
    }
```

### 10.2 Graceful Shutdown

- Complete in-flight requests
- Close connection pools
- Flush audit logs
- Clear sensitive data from memory

### 10.3 Resource Limits

| Resource | Limit |
|----------|-------|
| Memory | 512 MB max |
| Open files | 100 max |
| Threads | 10 max |
| Connection pool | 20 connections |

---

## 11. Security Testing Requirements

### 11.1 Static Analysis

```bash
# Required tools
bandit -r . -ll              # Security linter
mypy --strict .              # Type checking
ruff check .                 # Code quality
safety check                 # Dependency vulnerabilities
```

### 11.2 Pre-Commit Hooks

```yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    hooks:
      - id: bandit
        args: ['-ll', '-r', '.']
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: detect-secrets
      - id: check-added-large-files
```

---

## 12. Compliance Checklist

| Requirement | Status | Notes |
|-------------|--------|-------|
| No hardcoded secrets | ✅ | Env vars only |
| Token sanitization | ✅ | 20+ patterns |
| HTTPS enforced | ✅ | No HTTP |
| TLS 1.2+ | ✅ | Configurable |
| Input validation | ✅ | All inputs |
| Rate limiting | ⬜ | To implement |
| Audit logging | ⬜ | To implement |
| Circuit breaker | ⬜ | To implement |
| Retry with backoff | ⬜ | To implement |
| Health checks | ⬜ | To implement |
| Secrets manager integration | ⬜ | To implement |
| Structured logging | ⬜ | To implement |

---

## 13. Implementation Priority

### Phase 1: Critical (Immediate)
1. ✅ Token sanitization (20+ patterns)
2. ✅ Input validation (all endpoints)
3. ✅ SSL/TLS enforcement
4. ✅ Error handling (no info leak)
5. ⬜ Structured audit logging
6. ⬜ Rate limiting

### Phase 2: High (This Sprint)
7. ⬜ Circuit breaker pattern
8. ⬜ Retry with exponential backoff
9. ⬜ Health check endpoint
10. ⬜ Correlation IDs

### Phase 3: Medium (Next Sprint)
11. ⬜ Secrets manager integration
12. ⬜ Metrics/telemetry
13. ⬜ Pre-commit security hooks
14. ⬜ Automated security scanning

---

## 14. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01 | Security Team | Initial release |
| 2.0 | 2024-01 | Security Team | Enterprise upgrade |

**Approval Required:** Security Lead, Engineering Lead
