"""Shared SQL injection detection signals used across analysis and exploitation layers."""

import re

SQL_ERROR_RE = re.compile(
    r"(?i)(?:sql\s*syntax|sqlstate|mysql_fetch|mysqli?|pg_query|postgres(?:ql)?|"
    r"psycopg2|sqlite|ora-\d{4,}|ociexecute|odbc|jdbc|sql\s*server|"
    r"unclosed\s+quotation|unterminated\s+string|syntax\s+error\s+at\s+or\s+near|"
    r"you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax|"
    r"warning:\s*(?:mysql|pg_|oci)|invalid\s+column|invalid\s+object|"
    r"invalid\s+table|duplicate\s+key|integrity\s+constraint|foreign\s+key|"
    r"traceback|stack\s*trace|exception|syntax\s*error|unexpected\s+token|"
    r"unterminated|string\s+literal|division\s+by\s+zero|out\s+of\s+range)"
)

SQL_PARAM_NAMES = {
    "id",
    "uid",
    "user_id",
    "account_id",
    "search",
    "query",
    "q",
    "s",
    "term",
    "keyword",
    "filter",
    "sort",
    "order",
    "where",
    "where_clause",
    "having",
    "group_by",
    "criteria",
    "conditions",
    "expression",
    "expr",
    "column",
    "select",
    "sql",
    "db",
    "table",
    "raw",
    "native_query",
    "lookup",
    "match",
    "$filter",
}
