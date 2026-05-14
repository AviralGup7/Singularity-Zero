DEFAULT_NEXT_STEP = "Compare baseline and variant responses and confirm whether authorization or object boundaries shift."
DEFAULT_METHOD = "GET"
DEFAULT_TITLE = "API test plan"
DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; API-Test-Script)",
    "Accept": "application/json",
}

DEFAULT_KEY_LOCATIONS = [
    {"name": "Header (X-API-Key)", "headers": {"X-API-Key": "{api_key}"}},
    {"name": "Header (Authorization: Bearer)", "headers": {"Authorization": "Bearer {api_key}"}},
    {"name": "Header (Authorization: Token)", "headers": {"Authorization": "Token {api_key}"}},
    {"name": "Query Parameter", "params": {"apikey": "{api_key}"}},
]

DEFAULT_SENSITIVE_ENDPOINTS = [
    "users",
    "users/me",
    "orders",
    "admin",
    "admin/users",
    "profile",
    "billing",
]
