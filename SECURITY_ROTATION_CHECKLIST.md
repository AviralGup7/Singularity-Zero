# Security Secret Rotation Checklist

Generated: 2026-06-16

## Critical Secrets Requiring Rotation

### 1. Application Secrets
- [ ] **APP_SECRET_KEY** - Flask/FastAPI session signing key
  - Current: `dev-secret-key-change-in-production-32chars-minimum-length` (placeholder)
  - Action: Generate new key: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
  - Priority: CRITICAL

### 2. JWT Secrets
- [ ] **SEC_JWT_SECRET** - JWT token signing secret
  - Current: `dev-jwt-secret-key-at-least-32-characters-long-for-hs256` (placeholder)
  - Action: Generate new key: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
  - Priority: CRITICAL
  - Impact: All existing tokens will be invalidated

### 3. Dashboard Credentials
- [ ] **GRAFANA_ADMIN_PASSWORD** - Grafana admin password
  - Current: `admin` (default)
  - Action: Set strong password in production
  - Priority: HIGH

### 4. Database Credentials
- [ ] **REDIS_PASSWORD** - Redis authentication password
  - Current: Not set (default)
  - Action: Set strong password in production
  - Priority: HIGH

### 5. Encryption Keys
- [ ] **SEC_ENCRYPTION_KEY** - Fernet encryption key
  - Current: Not set
  - Action: Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
  - Priority: MEDIUM

### 6. Audit Logging
- [ ] **SEC_AUDIT_HMAC_SECRET** - HMAC secret for tamper-evident logs
  - Current: Not set
  - Action: Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
  - Priority: MEDIUM

## Deployment Steps

1. **Pre-rotation**: Backup existing tokens/sessions
2. **Generate new secrets**: Use commands above
3. **Update environment variables**: Set new values in production
4. **Restart services**: All services must restart to pick up new secrets
5. **Verify**: Test authentication flows
6. **Monitor**: Watch for authentication failures in logs

## Monitoring After Rotation

- Watch for increased 401/403 errors
- Monitor JWT validation failures
- Check Grafana access logs
- Verify Redis connection success

## Notes

- The `.env` file contains development-only placeholders
- Never commit real secrets to version control
- Use a secrets manager (Vault, AWS Secrets Manager) in production
- Rotate secrets on a regular schedule (quarterly recommended)
