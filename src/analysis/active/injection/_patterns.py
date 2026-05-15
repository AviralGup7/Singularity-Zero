"""Compiled regex patterns for active injection probe detection."""

import re

__all__ = [
    "PATH_TRAVERSAL_ERROR_RE",
    "ETC_PASSWD_RE",
    "BOOT_INI_RE",
    "WIN_INI_RE",
    "CMD_OUTPUT_RE",
    "CMD_ERROR_RE",
    "XXE_ERROR_RE",
    "SSRF_INTERNAL_IP_RE",
    "CLOUD_METADATA_RE",
    "CRLF_HEADER_RE",
    "SSTI_MATH_PROBES",
    "SSTI_ERROR_RE",
    "NOSQL_ERROR_RE",
    "LDAP_ERROR_RE",
    "DESER_ERROR_RE",
    "CLASS_NAME_RE",
    "ERROR_STACK_TRACE_RE",
]

PATH_TRAVERSAL_ERROR_RE = re.compile(
    r"(?i)(?:no\s*file|file\s*not\s*found|cannot\s*open|permission\s*denied|"
    r"invalid\s*path|directory\s*traversal|access\s*denied|forbidden\s*path|"
    r"realpath\(\)|include\(\)|fopen\(\)|readfile\(\)|file_get_contents\(\))"
)

ETC_PASSWD_RE = re.compile(r"(?i)root:[x*]?:0:0:")
BOOT_INI_RE = re.compile(r"(?i)\[boot\s*loader\]|\[operating\s*systems\]")
WIN_INI_RE = re.compile(r"(?i);\s*for\s*16-bit\s*app\s*support|^\[fonts\]", re.MULTILINE)

CMD_OUTPUT_RE = re.compile(
    r"(?i)(?:uid=\d+|gid=\d+|groups=\d+|/bin/|/usr/bin|root\s+:.*:\d+:\d+:|"
    r"total\s+\d+|[drwx-]{10}\s|rw-rw-rw|Linux\s+\S+|Microsoft\sWindows\s+\[|"
    r"C:\\Users|C:\\Windows|sh-?\d+\.\d+#|/bin/sh-|\# id$|admin:.*:\d+:)"
)

CMD_ERROR_RE = re.compile(
    r"(?i)(?:sh:\s*|bash:\s*|cmd\.exe|command\s*not\s*found|illegal\s*option|"
    r"unexpected\s*token|syntax\s*error.*near|/bin/sh:)"
)

XXE_ERROR_RE = re.compile(
    r"(?i)(?:xml\s*parse\s*error|entity\s*(?:expansion|reference)|DOCTYPE|"
    r"SAXParseException|XMLParser|ExternalEntity|SYSTEM\s*entity|"
    r"XXE|entity\s*resolution|failed\s*to\s*load\s*external)"
)

SSRF_INTERNAL_IP_RE = re.compile(
    r"(?i)(?:127\.0\.0\.|10\.\d{1,3}\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|"
    r"localhost|\[::1\]|0\.0\.0\.0|169\.254\.169\.254|metadata\.google|"
    r"instance-data|ec2\.internal|azure\.metadata)"
)

CLOUD_METADATA_RE = re.compile(
    r"(?i)(?:ami-id|instance-id|local-ipv4|public-ipv4|hostname|iam/security|"
    r"metadata.google.internal|computeMetadata)"
)

CRLF_HEADER_RE = re.compile(
    r"(?i)^(?:x-crlf-test|set-cookie|x-forwarded-for|x-custom-test):", re.MULTILINE
)

SSTI_MATH_PROBES = {
    49,  # 7*7
    64,  # 8*8
    81,  # 9*9
    121,  # 11*11
    144,  # 12*12
}
# Dynamic SSTI detection: require 2+ math results in response

SSTI_ERROR_RE = re.compile(
    r"(?i)(?:template\s*(?:syntax\s*)?error|jinja2|freemarker|twig|velocity|"
    r"mustache|handlebars|thymeleaf|erb|ejs|pug|jade|undefined\s*variable|"
    r"unexpected\s*'|TemplateSyntaxError|UndefinedError)"
)

NOSQL_ERROR_RE = re.compile(
    r"(?i)(?:mongo|mongodb|bson|NoSQL|E11000|MongoError|MongoServerError|"
    r"CastError|QueryFailure|unrecognized\s*operator|unknown\s*top\s*level\s*operator)"
)

DESER_ERROR_RE = re.compile(
    r"(?i)(?:deserializ|unserializ|unmarshal|unpickle|ObjectInputStream|"
    r"InvalidClassException|StreamCorruptedException|ClassNotFoundException|"
    r"java\.io\.|pickle|UnpicklingError|yaml\.|PHP\s*Serialize|"
    r"unserialize\(\)|NotSerializableException|InvalidObjectException)"
)

CLASS_NAME_RE = re.compile(r"(?i)(?:java\.[a-z.]+|javax\.[a-z.]+|org\.[a-z.]+|com\.[a-z.]+|O:\d+:)")

ERROR_STACK_TRACE_RE = re.compile(
    r"(?i)(?:traceback|stack\s*trace|stacktrace|at\s+\w+\.\w+\.\w+\("
    r"|File\s+\"[^\"]+\", line\s+\d+|in\s+\w+|Caused\s+by:|at\s+\S+\.\S+\(\S+\))"
)

LDAP_ERROR_RE = re.compile(
    r"(?i)(?:ldap|LDAP|Active\s*Directory|sAMAccountName|memberOf|"
    r"Invalid\s*DN\s*Syntax|LDAPException|NamingException|"
    r"javax\.naming\.|System\.DirectoryServices|"
    r"LDAP_OPERATIONS_ERROR|LDAP_INSUFFICIENT_ACCESS|"
    r"LDAP_NO_SUCH_OBJECT|LDAP_INVALID_CREDENTIALS|"
    r"Bad\s*search\s*filter|Invalid\s*search\s*filter|"
    r"Unwilling\s*To\s*Perform|Constraint\s*Violation|"
    r"LDAPError|ldap_err2str|ldap_errno)"
)
