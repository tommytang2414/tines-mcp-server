# Crypto Security Development Standards

All code in this project MUST follow these security requirements for crypto industry compliance.

## Critical Rules (Violations = Immediate Fix Required)

1. **NEVER hardcode secrets** - Use environment variables only
2. **NEVER log sensitive data** - Sanitize all logs and errors
3. **NEVER disable SSL verification** - `verify=True` always
4. **NEVER expose stack traces** - Generic error messages to users
5. **NEVER use unpinned dependencies** - Pin exact versions

## Crypto-Specific Protection

Block and redact these patterns in ALL outputs:
- `mnemonic`, `seed_phrase`, `recovery_phrase`
- `private_key`, `signing_key`, `wallet_key`, `master_key`
- `xprv` (extended private key)
- Any 12/24 word phrases that look like mnemonics

## Required Security Features

Every API/service MUST implement:
- **Rate Limiting**: Token bucket, 60 req/min default
- **Circuit Breaker**: 5 failures → open, 60s timeout
- **Retry Logic**: Exponential backoff with jitter
- **Audit Logging**: Structured JSON with correlation IDs
- **Input Validation**: Length limits, injection prevention

## Error Handling Pattern

```python
try:
    result = operation()
except KnownError as e:
    return {"error": sanitize(str(e)), "error_code": e.code, "correlation_id": cid}
except Exception:
    logger.exception("Internal error")  # Full details internal only
    return {"error": "An unexpected error occurred", "correlation_id": cid}
```

## Dependency Rules

```txt
# CORRECT - Pinned exact versions
httpx==0.28.1
pydantic==2.12.5

# WRONG - Never use
httpx>=0.25.0
package~=1.0
```

## Before Committing Code

Verify:
- [ ] No secrets in code or logs
- [ ] All inputs validated
- [ ] Errors sanitized
- [ ] HTTPS/SSL enforced
- [ ] Rate limiting implemented
- [ ] Audit logging enabled
