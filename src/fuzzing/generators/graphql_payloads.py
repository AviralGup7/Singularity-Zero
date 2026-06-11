from typing import Any, cast

_GRAPHQL_INTROSPECTION_QUERY = """
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

_MUTATION_TEMPLATES = {
    "login": {
        "query": "mutation Login($username: String!, $password: String!) { login(username: $username, password: $password) { token user { id } } }",
        "operationName": "Login",
        "variables": {"username": "test", "password": "test"},
    },
    "updateProfile": {
        "query": "mutation UpdateProfile($input: UpdateProfileInput!) { updateProfile(input: $input) { id name email } }",
        "operationName": "UpdateProfile",
        "variables": {"input": {"name": "test", "email": "test@example.com"}},
    },
    "createOrder": {
        "query": "mutation CreateOrder($input: CreateOrderInput!) { createOrder(input: $input) { id total status } }",
        "operationName": "CreateOrder",
        "variables": {"input": {"amount": 1, "productId": 1}},
    },
}


def _build_alias_bomb(mutation_key: str) -> dict[str, Any]:
    template = _MUTATION_TEMPLATES[mutation_key]
    base_query: str = template["query"]
    base_vars = cast(dict[str, Any], template["variables"])
    operation_name = template["operationName"]
    selection_set = base_query.split("{", 1)[1].rsplit("}", 1)[0].strip()
    aliases = "".join(f"alias{i}: {selection_set} " for i in range(5))
    bomb_query = f"mutation {operation_name}AliasBomb {{ {aliases}}}"
    return {
        "field": mutation_key,
        "mutation_type": "alias_bomb",
        "payload": {
            "query": bomb_query,
            "operationName": f"{operation_name}AliasBomb",
            "variables": base_vars,
        },
        "strategy": "alias_bomb",
        "reason": f"Alias bomb GraphQL mutation for {mutation_key}",
    }


def _build_fragment_duplication(mutation_key: str) -> dict[str, Any]:
    template = _MUTATION_TEMPLATES[mutation_key]
    base_query: str = template["query"]
    base_vars = cast(dict[str, Any], template["variables"])
    operation_name = template["operationName"]
    selection_set = base_query.split("{", 1)[1].rsplit("}", 1)[0].strip()
    fragments = "".join(f"fragment F{i} on Query {{ __typename }} " for i in range(3))
    dup_query = f"mutation {operation_name}FragmentDup {{ {fragments}{selection_set} }}"
    return {
        "field": mutation_key,
        "mutation_type": "fragment_duplication",
        "payload": {
            "query": dup_query,
            "operationName": f"{operation_name}FragmentDup",
            "variables": base_vars,
        },
        "strategy": "fragment_duplication",
        "reason": f"Fragment duplication GraphQL mutation for {mutation_key}",
    }


def _build_directive_injection(mutation_key: str) -> dict[str, Any]:
    template = _MUTATION_TEMPLATES[mutation_key]
    base_query: str = template["query"]
    base_vars = cast(dict[str, Any], template["variables"])
    operation_name = template["operationName"]
    injected_query = base_query.replace("mutation", "mutation @skip(if: true)")
    return {
        "field": mutation_key,
        "mutation_type": "directive_injection",
        "payload": {
            "query": injected_query,
            "operationName": operation_name,
            "variables": base_vars,
        },
        "strategy": "directive_injection",
        "reason": f"Directive injection GraphQL mutation for {mutation_key}",
    }


def _build_recursive_input(mutation_key: str) -> dict[str, Any]:
    template = _MUTATION_TEMPLATES[mutation_key]
    base_query: str = template["query"]
    base_vars = cast(dict[str, Any], template["variables"])
    operation_name = template["operationName"]
    if mutation_key == "login":
        recursive_query = "mutation RecursiveLogin($username: String!, $password: String!) { login(username: {username: $username, password: {password: $password}}, password: $password) { token } }"
    elif mutation_key == "updateProfile":
        recursive_query = "mutation RecursiveUpdate($input: UpdateProfileInput!) { updateProfile(input: {input: $input}) { id } }"
    else:
        recursive_query = "mutation RecursiveCreate($input: CreateOrderInput!) { createOrder(input: {input: $input}) { id } }"
    return {
        "field": mutation_key,
        "mutation_type": "recursive_input",
        "payload": {
            "query": recursive_query,
            "operationName": f"Recursive{operation_name}",
            "variables": base_vars,
        },
        "strategy": "recursive_input",
        "reason": f"Recursive input GraphQL mutation for {mutation_key}",
    }


def generate_graphql_introspection_payloads(endpoint: str) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for mutation_key in _MUTATION_TEMPLATES:
        payloads.append(
            {
                "field": mutation_key,
                "mutation_type": "introspection_query",
                "payload": {
                    "query": _GRAPHQL_INTROSPECTION_QUERY,
                    "operationName": "IntrospectionQuery",
                    "variables": {},
                },
                "strategy": "introspection_query",
                "reason": "Standard GraphQL introspection query",
            }
        )
        payloads.append(_build_alias_bomb(mutation_key))
        payloads.append(_build_fragment_duplication(mutation_key))
        payloads.append(_build_directive_injection(mutation_key))
        payloads.append(_build_recursive_input(mutation_key))
    return payloads
