"""Dockerfile / CI config secret scanner."""

_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"GH_TOKEN|GITHUB_TOKEN|GITHUB_PAT", "GitHub token"),
    (r"DOCKER_PASSWORD|DOCKERHUB_TOKEN", "Docker Hub token"),
    (r"NPM_TOKEN|NODE_AUTH_TOKEN", "NPM token"),
    (r"PYPI_TOKEN|TWINE_PASSWORD", "PyPI / Twine credential"),
    (r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY", "AWS credential"),
    (r"AZURE_CLIENT_SECRET|AZURE_STORAGE_KEY", "Azure credential"),
    (r"GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_SERVICE_KEY", "GCP credential"),
    (r"PASSWD|PASSWORD|SECRET|API_KEY", "Generic secret keyword"),
    (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Private key"),
]


def scan_for_secrets(paths: list[str]) -> list[dict]:
    """Scan *paths* (Dockerfile, .dockerignore, docker-compose.yml, .gitlab-ci.yml)
    for hard-coded secrets.

    Returns a list of findings with keys: file, line, match, kind, value.
    """
    import os
    import re

    findings: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    for pattern, kind in _SECRET_PATTERNS:
                        for m in re.finditer(pattern, line, re.IGNORECASE):
                            key = (path, lineno, m.group(0))
                            if key in seen:
                                continue
                            seen.add(key)
                            value = line.strip()[:200]
                            findings.append(
                                {
                                    "file": path,
                                    "line": lineno,
                                    "match": m.group(0),
                                    "kind": kind,
                                    "value": value,
                                }
                            )
        except OSError:
            continue

    return findings
