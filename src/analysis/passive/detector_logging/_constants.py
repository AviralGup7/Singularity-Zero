"""Constants and patterns for security logging failure detection."""

import re

__all__ = [
    "SENSITIVE_QUERY_PARAMS",
    "SENSITIVE_VALUE_PATTERNS",
    "STACK_TRACE_PATTERNS",
    "DEBUG_INDICATORS",
    "SQL_ERROR_PATTERNS",
    "INTERNAL_IP_PATTERN",
    "FILE_PATH_PATTERNS",
    "ENV_VAR_PATTERNS",
    "DB_CONN_PATTERNS",
    "API_SECRET_PATTERNS",
]

# Sensitive query parameter names that should never appear in URLs
SENSITIVE_QUERY_PARAMS = {
    "password",
    "passwd",
    "pwd",
    "pass",
    "token",
    "access_token",
    "refresh_token",
    "auth_token",
    "api_token",
    "bearer_token",
    "api_key",
    "apikey",
    "api_secret",
    "secret",
    "secret_key",
    "access_key",
    "ssn",
    "social_security",
    "social_security_number",
    "credit_card",
    "cc",
    "card_number",
    "cardnumber",
    "cc_number",
    "creditcard",
    "cvv",
    "cvc",
    "card_cvv",
    "card_cvc",
    "private_key",
    "privatekey",
    "authorization",
    "auth",
    "session_id",
    "sessionid",
    "sid",
    "client_secret",
}

# Patterns for sensitive data values in URLs or responses
SENSITIVE_VALUE_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn_pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card_pattern": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "api_key_pattern": re.compile(r"\b(?:sk|pk|ak|api)[-_]?[a-z0-9]{20,}\b", re.IGNORECASE),
    "aws_key_pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret_pattern": re.compile(
        r"\b(?:secret|key|token)\s*[:=]\s*[A-Za-z0-9+/=_\-]{16,}\b", re.IGNORECASE
    ),
}

# Stack trace and error message patterns
STACK_TRACE_PATTERNS: dict[str, re.Pattern[str]] = {
    "java_trace": re.compile(
        r"(?i)(?:at\s+\S+\.\w+\([^)]*\)|Caused by:|Exception in thread|java\.lang\.)"
    ),
    "python_trace": re.compile(
        r"(?i)(?:Traceback \(most recent call last\)|File\s+\"[^\"]+\", line \d+|[\w.]+Error:|[\w.]+Exception:)"
    ),
    "nodejs_trace": re.compile(
        r"(?i)(?:at\s+\S+\s+\([^)]+\)|TypeError:|ReferenceError:|SyntaxError:|Error:\s+\S+|unhandled\s+rejection)"
    ),
    "dotnet_trace": re.compile(
        r"(?i)(?:at\s+\S+<\S+>|System\.\w+Exception|System\.\w+Error|HttpException|NullReferenceException)"
    ),
    "php_trace": re.compile(
        r"(?i)(?:Fatal error:|Warning:|Parse error:|Notice:|Deprecated:|Stack trace:|PHP\s+\d+\.\d+\.\d+)"
    ),
    "generic_trace": re.compile(
        r"(?i)(?:stack\s*trace|call\s*stack|backtrace|exception\s*thrown|error\s*details|internal\s*error)"
    ),
}

# Debug mode indicators
DEBUG_INDICATORS: dict[str, re.Pattern[str]] = {
    "debug_flag": re.compile(
        r"(?i)(?:debug\s*=\s*true|debug\s*mode|development\s*server|werkzeug|flask\.debug)"
    ),
    "verbose_errors": re.compile(
        r"(?i)(?:verbose\s*error|detailed\s*error|full\s*stack|show\s*errors\s*=\s*true)"
    ),
    "dev_server": re.compile(
        r"(?i)(?:running on http|serving on|development mode|hot reload|live reload)"
    ),
    "debug_toolbar": re.compile(r"(?i)(?:django.*debug.*toolbar|debug-toolbar|toolbar.*debug)"),
}

# SQL-related patterns in error responses
SQL_ERROR_PATTERNS: dict[str, re.Pattern[str]] = {
    "sql_syntax": re.compile(
        r"(?i)(?:SQL syntax|sqlstate|syntax error.*sql|unexpected.*token.*sql)"
    ),
    "mysql_error": re.compile(r"(?i)(?:MySQL|mysql_fetch|mysqli_query|PDO.*MySQL|mysql_error)"),
    "postgres_error": re.compile(
        r"(?i)(?:PostgreSQL|pg_query|psycopg2|PG::Error|ActiveRecord.*PostgreSQL)"
    ),
    "oracle_error": re.compile(r"(?i)(?:ORA-\d+|ociexecute|oci_error|Oracle.*error)"),
    "sqlserver_error": re.compile(r"(?i)(?:SQL Server|MSSQL|SqlException|System\.Data\.SqlClient)"),
    "sql_query_leak": re.compile(
        r"(?i)(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE)"
    ),
}

# Internal IP address patterns
INTERNAL_IP_PATTERN = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"localhost(?::\d+)?"
    r")\b"
)

# File path patterns
FILE_PATH_PATTERNS: dict[str, re.Pattern[str]] = {
    "unix_path": re.compile(
        r"(?i)(?:/[a-z0-9_.\-]+){3,}/[a-z0-9_.\-]+\.(?:py|js|rb|java|php|go|cs|ts|html|css|conf|cfg|ini|yml|yaml|xml|json|log|env)"
    ),
    "windows_path": re.compile(
        r"(?i)[A-Z]:\\(?:[a-zA-Z0-9_.\-]+\\){2,}[a-zA-Z0-9_.\-]+\.(?:py|js|rb|java|php|go|cs|ts|html|css|conf|cfg|ini|yml|yaml|xml|json|log|env)"
    ),
    "config_path": re.compile(
        r"(?i)(?:/etc/|/var/|/tmp/|/opt/|/home/|/usr/|C:\\Windows\\|C:\\Program Files\\|C:\\Users\\)"
    ),
}

# Environment variable patterns
ENV_VAR_PATTERNS: dict[str, re.Pattern[str]] = {
    "env_var_ref": re.compile(
        r"(?i)\$\{?[A-Z_]+(?:_SECRET|_KEY|_PASSWORD|_TOKEN|_DB|_DATABASE|_CONN|_URL|_URI|_HOST|_PORT)\}?"
    ),
    "env_var_value": re.compile(
        r"(?i)(?:DATABASE_URL|DB_PASSWORD|SECRET_KEY|API_KEY|AWS_SECRET|PRIVATE_KEY|ENCRYPTION_KEY)\s*[:=]\s*\S+"
    ),
    "dotenv_leak": re.compile(r"(?i)(?:\.env|dotenv|env file|environment file)"),
}

# Database connection string patterns
DB_CONN_PATTERNS: dict[str, re.Pattern[str]] = {
    "mongodb": re.compile(r"(?i)mongodb(?:\+srv)?://[^\s\"']+"),
    "postgresql": re.compile(r"(?i)(?:postgresql|postgres|pg)://[^\s\"']+"),
    "mysql": re.compile(r"(?i)mysql://[^\s\"']+"),
    "redis": re.compile(r"(?i)redis://[^\s\"']+"),
    "mssql": re.compile(r"(?i)(?:mssql|sqlserver)://[^\s\"']+"),
    "generic_dsn": re.compile(r"(?i)(?:dsn|connection_string|conn_str|database_url)\s*[:=]\s*\S+"),
}

# API key/secret patterns in responses
API_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "generic_api_key": re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9]{16,}"),
    "aws_secret": re.compile(
        r"(?i)(?:aws[_-]?secret|aws_secret_access_key)\s*[:=]\s*[A-Za-z0-9/+=]{40}"
    ),
    "stripe_key": re.compile(r"(?i)(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}"),
    "github_token": re.compile(r"(?i)gh[pousr]_[A-Za-z0-9]{36,}"),
    "slack_token": re.compile(r"(?i)xox[baprs]-[A-Za-z0-9\-]+"),
    "jwt_in_response": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
}
