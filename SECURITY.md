# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of the Cyber Security Test Pipeline seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to [security@example.com](mailto:security@example.com) with the following information:

1. **Description** - A clear description of the vulnerability
2. **Impact** - What an attacker could achieve
3. **Reproduction steps** - Detailed steps to reproduce the issue
4. **Affected version(s)** - Which versions are affected
5. **Suggested fix** (optional) - If you have a fix in mind

## What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within **48 hours**
- **Assessment**: We will assess the vulnerability and provide an initial response within **5 business days**
- **Resolution**: We aim to resolve critical vulnerabilities within **30 days**
- **Disclosure**: We will coordinate public disclosure with you after a fix is available

## Scope

This policy applies to:
- The core pipeline application (`src/`)
- The dashboard and API (`src/dashboard/`)
- The worker and queue system (`src/infrastructure/queue/`)
- Docker images and Kubernetes manifests
- CI/CD pipeline configuration

## Out of Scope

- Vulnerabilities in third-party dependencies (report to the respective projects)
- Social engineering attacks
- Physical security vulnerabilities
- Denial of service attacks against hosted instances

## Security Best Practices for Contributors

1. Never commit secrets, API keys, or credentials
2. Use the `.env.example` file as a reference for required environment variables
3. Run `detect-secrets scan` before committing
4. Ensure all dependencies are up to date
5. Follow the security guidelines in the contributing documentation
