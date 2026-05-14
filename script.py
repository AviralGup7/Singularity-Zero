import re

with open("src/execution/validators/runtime.py", encoding="utf-8") as f:
    text = f.read()

text = re.sub(
    r'(idor_results = results\.get\("idor_validation"\)) or validate_idor_candidates\(analysis_results, token_replay\)',
    r"\1\n    if idor_results is None:\n        idor_results = validate_idor_candidates(analysis_results, token_replay)",
    text,
)

text = re.sub(
    r'(csrf_results = results\.get\("csrf_validation"\)) or validate_csrf_candidates\(analysis_results, callback_context\)',
    r"\1\n    if csrf_results is None:\n        csrf_results = validate_csrf_candidates(analysis_results, callback_context)",
    text,
)

text = re.sub(
    r'(xss_results = results\.get\("xss_validation"\)) or validate_xss_candidates\(analysis_results, callback_context\)',
    r"\1\n    if xss_results is None:\n        xss_results = validate_xss_candidates(analysis_results, callback_context)",
    text,
)

with open("src/execution/validators/runtime.py", "w", encoding="utf-8") as f:
    f.write(text)
