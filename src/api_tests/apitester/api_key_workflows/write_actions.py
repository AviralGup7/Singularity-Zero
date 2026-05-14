from datetime import datetime
from typing import Any

from .shared import (
    base_headers,
    display_secret,
    key_locations,
    normalize_base_url,
    placement_request_parts,
    print_banner,
    print_section_header,
    print_summary_header,
    request,
    safe_json_keys,
)


def write_flexible_chaining_test(
    base_url: str,
    api_key: str,
    cookies: dict[str, Any] | None = None,
) -> None:
    import requests  # type: ignore[import-untyped]

    base_url = normalize_base_url(base_url)
    print_banner(
        "API KEY SECURITY TEST - PART 4",
        [
            f"Target Base : {base_url}",
            f"API Key     : {display_secret(api_key)}",
            f"Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        ],
        divider_width=95,
    )

    with requests.Session() as session:
        headers = base_headers("Mozilla/5.0 (API-Key-Write-Test)")
        placements = key_locations(api_key)
        results = []

        for placement in placements:
            print_section_header(f"Testing Key Location: {placement['name']}", divider_width=80)
            test_headers, test_params = placement_request_parts(headers, placement)

            print("1. Testing Write Actions (Create / Update / Delete)")
            write_tests: list[dict[str, Any]] = [
                {
                    "method": "POST",
                    "endpoint": "orders",
                    "data": {"product": "test_item", "quantity": 1},
                },
                {
                    "method": "POST",
                    "endpoint": "users",
                    "data": {"name": "testuser", "email": "test@example.com"},
                },
                {"method": "POST", "endpoint": "resources", "data": {"name": "test_resource"}},
                {
                    "method": "PUT",
                    "endpoint": "profile",
                    "data": {"bio": "Updated via API key test"},
                },
                {"method": "PUT", "endpoint": "users/123", "data": {"role": "admin"}},
                {"method": "DELETE", "endpoint": "orders/999", "data": None},
                {"method": "DELETE", "endpoint": "resources/test", "data": None},
            ]
            for test in write_tests:
                method = str(test["method"])
                try:
                    response = request(
                        session,
                        method,
                        f"{base_url}{test['endpoint']}",
                        headers=test_headers,
                        params=test_params,
                        cookies=cookies,
                        json_body=test["data"],
                        timeout=10,
                    )
                    status = response.status_code
                    if status in (200, 201, 204):
                        print(f"   WRITE SUCCESS: {method} /{test['endpoint']} -> {status}")
                    elif status in (401, 403):
                        print(f"   {method} /{test['endpoint']:<18} -> {status} (Blocked)")
                    else:
                        print(f"   {method} /{test['endpoint']:<18} -> {status}")
                    results.append(
                        {
                            "test": "write_action",
                            "location": placement["name"],
                            "method": method,
                            "endpoint": test["endpoint"],
                            "status": status,
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"   {method} /{test['endpoint']} -> Error: {str(exc)[:60]}")

            print("\n2. Testing Key in Headers vs Query Parameters (Flexibility)")
            for alt_placement in placements:
                alt_placement_headers: dict[str, Any] = (
                    alt_placement.get("headers", {})
                    if isinstance(alt_placement.get("headers"), dict)
                    else {}
                )
                alt_placement_params: dict[str, Any] = (
                    alt_placement.get("params", {})
                    if isinstance(alt_placement.get("params"), dict)
                    else {}
                )
                alt_headers = {**headers, **alt_placement_headers}
                alt_params: dict[str, Any] = alt_placement_params
                try:
                    response = request(
                        session,
                        "GET",
                        f"{base_url}users/me",
                        headers=alt_headers,
                        params=alt_params,
                        cookies=cookies,
                        timeout=8,
                    )
                    if response.status_code == 200:
                        print(f"   Key accepted in {alt_placement['name']}")
                    else:
                        print(f"   {alt_placement['name']:<25} -> {response.status_code}")
                except requests.exceptions.RequestException:
                    print(f"   {alt_placement['name']:<25} -> Connection error")
                except Exception as exc:
                    print(f"   {alt_placement['name']:<25} -> Error: {type(exc).__name__}")

            print("\n3. Chaining Parameters to Amplify Access (user_id, token, etc.)")
            chaining_tests = [
                {"params": {"user_id": "456"}},
                {"params": {"user_id": "admin"}},
                {"params": {"token": api_key}},
                {"params": {"user_id": "123", "role": "admin"}},
                {"params": {"id": "999", "include": "all"}},
                {"params": {"user_id": "123", "token": api_key}},
            ]
            for chain in chaining_tests:
                try:
                    combined_params = {**test_params, **dict(chain["params"])}
                    response = request(
                        session,
                        "GET",
                        f"{base_url}users/me",
                        headers=test_headers,
                        params=combined_params,
                        cookies=cookies,
                        timeout=10,
                    )
                    if response.status_code == 200:
                        print(f"   CHAINING SUCCESS: {list(chain['params'].keys())} -> 200 OK")
                        keys = safe_json_keys(response)
                        if keys:
                            print(f"      Returned keys: {keys[:6]}")
                    else:
                        print(
                            f"   Chaining {list(chain['params'].keys())} -> {response.status_code}"
                        )
                except Exception as exc:  # noqa: BLE001
                    print(f"   Chaining failed: {str(exc)[:50]}")

        print_summary_header("TEST SUMMARY - Write, Flexibility & Chaining", divider_width=95)
        write_success = sum(
            1
            for result in results
            if result.get("test") == "write_action" and result.get("status") in (200, 201, 204)
        )
        if write_success > 0:
            print(f"CRITICAL: Key allows {write_success} write operations (CREATE/UPDATE/DELETE)")
        else:
            print("No write actions succeeded with the key.")
        print("\nWrite Actions, Key Location Flexibility & Parameter Chaining tests completed.")
