from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check
from src.fuzzing.generators.graphql_payloads import generate_graphql_introspection_payloads

logger = logging.getLogger(__name__)

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                }
              }
            }
          }
        }
      }
    }
  }
}
"""

_graphql_error_patterns_re = re.compile(r'"errors"\s*:\s*\[', re.IGNORECASE)


def _detect_graphql_introspection(body: str) -> bool:
    # Limit search to first 10000 chars to avoid ReDoS on large responses
    return bool(re.search(r'(?:__schema|__type|data\.__schema|data\.__type)', body[:10000]))


async def run_graphql_fuzzing_campaign(
    url: str,
    client: httpx.AsyncClient | None = None,
    *,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not is_safe_url_with_dns_check(url):
        logger.warning("GraphQL fuzzer: URL failed SSRF safety check, skipping: %s", url)
        return findings

    endpoint_key = endpoint_signature(url)
    endpoint_base = endpoint_base_key(url)
    endpoint_type = classify_endpoint(url)

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
        close_client = True

    try:
        try:
            resp = await client.post(url, json={"query": _INTROSPECTION_QUERY})
            body = resp.text
        except Exception as exc:
            logger.debug("GraphQL introspection request failed for %s: %s", url, exc)
            return findings

        if _detect_graphql_introspection(body):
            # Only report once — introspection enabled is the actual vulnerability
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base,
                    "endpoint_type": endpoint_type,
                    "issues": ["graphql_introspection_enabled"],
                    "probe_type": "graphql_fuzzer",
                    "severity": "high",
                    "confidence": 0.95,
                    "evidence": {
                        "status_code": resp.status_code,
                        "body_preview": body[:500],
                        "reason": "GraphQL introspection query returned schema data",
                    },
                }
            )

        mutation_payloads = generate_graphql_introspection_payloads(url)
        for payload_item in mutation_payloads:
            try:
                mut_resp = await client.post(url, json=payload_item["payload"])
                mut_body = mut_resp.text
            except Exception as exc:
                logger.debug("GraphQL mutation request failed for %s: %s", url, exc)
                continue

            if _graphql_error_patterns_re.search(mut_body[:50000]):
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base,
                        "endpoint_type": endpoint_type,
                        "issues": ["graphql_query_error"],
                        "probe_type": "graphql_fuzzer",
                        "severity": "medium",
                        "confidence": 0.8,
                        "evidence": {
                            "field": payload_item.get("field"),
                            "mutation_type": payload_item.get("mutation_type"),
                            "status_code": mut_resp.status_code,
                            "body_preview": mut_body[:500],
                            "reason": "GraphQL mutation returned errors",
                        },
                    }
                )
            elif mut_resp.status_code == 200:
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base,
                        "endpoint_type": endpoint_type,
                        "issues": ["graphql_unauthorized_mutation_accepted"],
                        "probe_type": "graphql_fuzzer",
                        "severity": "high",
                        "confidence": 0.85,
                        "evidence": {
                            "field": payload_item.get("field"),
                            "mutation_type": payload_item.get("mutation_type"),
                            "status_code": mut_resp.status_code,
                            "payload": payload_item.get("payload"),
                            "reason": "GraphQL mutation accepted without errors",
                        },
                    }
                )
    finally:
        if close_client:
            await client.aclose()

    return findings
