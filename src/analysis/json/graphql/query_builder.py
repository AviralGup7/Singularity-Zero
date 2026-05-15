"""GraphQL introspection query building utilities.

Contains predefined introspection queries, depth test payloads,
batch/alias attack payloads, and mutation test queries.
"""

from typing import Any

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type { name kind ofType { name kind } }
        }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

MINIMAL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types { name }
  }
}
"""

TYPE_INTROSPECTION_QUERY = """
{
  __type(name: "Query") {
    name
    fields {
      name
      args { name type { name } }
      type { name }
    }
  }
}
"""

DEPTH_TEST_QUERIES: list[dict[str, Any]] = [
    {
        "depth": 5,
        "query": """
{
  a: __typename
  b: __typename
  c: __typename
  d: __typename
  e: __typename
}
""",
    },
    {
        "depth": 10,
        "query": """
{
  a1: __typename
  a2: __typename
  a3: __typename
  a4: __typename
  a5: __typename
  a6: __typename
  a7: __typename
  a8: __typename
  a9: __typename
  a10: __typename
}
""",
    },
    {
        "depth": 15,
        "query": """
{
  l1: __typename
  l2: __typename
  l3: __typename
  l4: __typename
  l5: __typename
  l6: __typename
  l7: __typename
  l8: __typename
  l9: __typename
  l10: __typename
  l11: __typename
  l12: __typename
  l13: __typename
  l14: __typename
  l15: __typename
}
""",
    },
]

BATCH_ALIAS_PAYLOADS: list[list[dict[str, str]]] = [
    [
        {"query": "{ __typename }"},
        {"query": "{ __schema { queryType { name } } }"},
        {"query": '{ __type(name: "Query") { name } }'},
    ],
    [
        {"query": "{ a1: __typename }"},
        {"query": "{ a2: __typename }"},
        {"query": "{ a3: __typename }"},
        {"query": "{ a4: __typename }"},
        {"query": "{ a5: __typename }"},
    ],
]

ALIAS_ABUSE_QUERY = """
{
  t1: __typename
  t2: __typename
  t3: __typename
  t4: __typename
  t5: __typename
  t6: __typename
  t7: __typename
  t8: __typename
  t9: __typename
  t10: __typename
  t11: __typename
  t12: __typename
  t13: __typename
  t14: __typename
  t15: __typename
  t16: __typename
  t17: __typename
  t18: __typename
  t19: __typename
  t20: __typename
}
"""

MUTATION_TEST_QUERIES: list[dict[str, str]] = [
    {"name": "typename_mutation", "query": "mutation { __typename }"},
    {"name": "introspection_mutation", "query": "mutation { __schema { types { name } } }"},
]

DANGEROUS_MUTATION_NAMES: set[str] = {
    "createuser",
    "deleteuser",
    "updateuser",
    "createaccount",
    "deleteaccount",
    "transfer",
    "withdraw",
    "deposit",
    "createorder",
    "cancelorder",
    "updatepayment",
    "grantpermission",
    "revokpermission",
    "setrole",
    "execute",
    "run",
    "deploy",
    "publish",
    "sendemail",
    "sendnotification",
    "createwebhook",
    "delete",
    "updatepassword",
    "resetpassword",
    "impersonate",
    "loginas",
}


def build_typename_probe() -> dict[str, str]:
    """Build a minimal __typename probe query."""
    return {"query": "{ __typename }"}


def build_introspection_queries() -> list[tuple[str, str]]:
    """Return all introspection query variants to try."""
    return [
        ("full", INTROSPECTION_QUERY),
        ("minimal", MINIMAL_INTROSPECTION_QUERY),
        ("type", TYPE_INTROSPECTION_QUERY),
    ]


def build_depth_test_payloads(max_depth: int = 10) -> list[dict[str, Any]]:
    """Filter depth test queries to those within the max depth."""
    return [t for t in DEPTH_TEST_QUERIES if t["depth"] <= max_depth]


def build_batch_payloads() -> list[list[dict[str, str]]]:
    """Return batch alias attack payloads."""
    return list(BATCH_ALIAS_PAYLOADS)


def build_alias_abuse_query() -> str:
    """Return the alias abuse query string."""
    return ALIAS_ABUSE_QUERY


def build_mutation_test_queries() -> list[dict[str, str]]:
    """Return mutation test query payloads."""
    return list(MUTATION_TEST_QUERIES)
