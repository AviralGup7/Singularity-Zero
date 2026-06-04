#!/usr/bin/env bash

set -euo pipefail

INNGEST_CONFIG=".config/inngest/inngest.yaml"
AUTOMATION_PORT="${AUTOMATION_PORT:-5000}"
INNGEST_PORT="${PORT:-3000}"

# Try to store Inngest data in Postgres if it's available. Otherwise, put it in SQLite.
if [[ ! -f "${INNGEST_CONFIG}" ]]; then
    mkdir -p "$(dirname "${INNGEST_CONFIG}")"
    if [[ -n "${DATABASE_URL:-}" ]]; then
        # SECURITY: write the URL with a literal ``%s`` placeholder and
        # a separate ``printf`` so the ``DATABASE_URL`` value is treated
        # as data, not as a format string. The previous form
        # ``printf '...: "%s"' "${DATABASE_URL}"`` is safe with ``%s``
        # but using a heredoc eliminates the entire class of format
        # string issues if a maintainer ever changes the template.
        cat > "${INNGEST_CONFIG}" <<EOF
postgres-uri: "${DATABASE_URL}"
EOF
    else
        cat > "${INNGEST_CONFIG}" <<'EOF'
sqlite-dir: "/home/runner/workspace/.local/share/inngest"
EOF
    fi
fi
exec inngest-cli dev -u "http://localhost:${AUTOMATION_PORT}/api/inngest" --host 127.0.0.1 --port "${INNGEST_PORT}" --config "${INNGEST_CONFIG}"
