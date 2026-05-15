VALIDATOR_ORDER: tuple[str, ...] = (
    "redirect",
    "ssrf",
    "token_reuse",
    "idor",
    "csrf",
    "xss",
    "ssti",
    "file_upload",
)

VALIDATOR_RESULT_KEYS: dict[str, str] = {
    "redirect": "open_redirect_validation",
    "ssrf": "ssrf_validation",
    "token_reuse": "token_reuse_validation",
    "idor": "idor_validation",
    "csrf": "csrf_validation",
    "xss": "xss_validation",
    "ssti": "ssti_validation",
    "file_upload": "file_upload_validation",
}
