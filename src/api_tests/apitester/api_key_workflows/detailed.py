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


def detailed_api_key_test(
    base_url: str, api_key: str, cookies: dict[str, str] | None = None
) -> None:
    import requests  # type: ignore[import-untyped]

    base_url = normalize_base_url(base_url)
    print_banner(
        "API KEY SECURITY TEST STARTED",
        [
            f"Target Base URL : {base_url}",
            f"API Key         : {display_secret(api_key)} (truncated for safety)\n",
        ],
        divider_width=90,
    )

    with requests.Session() as session:
        headers = base_headers("Mozilla/5.0 (API-Key-Security-Test)")
        placements = key_locations(api_key)[:5]
        results = []

        for placement in placements:
            print_section_header(f"Testing with key in: {placement['name']}", divider_width=70)
            test_headers, test_params = placement_request_parts(headers, placement)

            print("1. Direct request without login (/users/me or /profile)")
            for endpoint in ["users/me", "me", "profile", "account", "user"]:
                try:
                    response = request(
                        session,
                        "GET",
                        f"{base_url}{endpoint}",
                        headers=test_headers,
                        params=test_params,
                        cookies=cookies,
                        timeout=12,
                        allow_redirects=True,
                    )
                    print(
                        f"   GET {endpoint:<12} -> Status: {response.status_code} | Size: {len(response.text):,} bytes"
                    )
                    if response.status_code == 200:
                        keys = safe_json_keys(response)
                        if keys:
                            print(f"   SUCCESS: Key returned real data. Keys: {keys}")
                        else:
                            print("   SUCCESS: Key returned data")
                    results.append(
                        {
                            "test": "direct_no_login",
                            "placement": placement["name"],
                            "endpoint": endpoint,
                            "status": response.status_code,
                            "size": len(response.text),
                        }
                    )
                except requests.exceptions.RequestException as exc:
                    print(f"   Error accessing {endpoint}: {exc}")
                except Exception as exc:  # noqa: BLE001
                    print(f"   Unexpected error: {exc}")

            print("\n2. Accessing Sensitive Endpoints with the key")
            for endpoint in [
                "users",
                "users/",
                "orders",
                "orders/",
                "admin",
                "admin/",
                "admin/users",
                "admin/dashboard",
                "billing",
                "payments",
                "settings",
                "config",
                "logs",
                "api-keys",
            ]:
                try:
                    response = request(
                        session,
                        "GET",
                        f"{base_url}{endpoint}",
                        headers=test_headers,
                        params=test_params,
                        cookies=cookies,
                        timeout=10,
                    )
                    status = response.status_code
                    size = len(response.text)
                    if status == 200:
                        print(f"   HIGH RISK: {endpoint:<18} -> 200 OK")
                    elif status in (401, 403):
                        print(f"   {endpoint:<18} -> {status} (Access Denied)")
                    else:
                        print(f"   {endpoint:<18} -> {status} | Size: {size:,} bytes")
                    results.append(
                        {
                            "test": "sensitive_endpoint",
                            "placement": placement["name"],
                            "endpoint": endpoint,
                            "status": status,
                            "size": size,
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"   Error on {endpoint}: {str(exc)[:80]}")

            print("\n3. Testing key ALONE (without any cookies/session)")
            try:
                response_no_cookie = request(
                    session,
                    "GET",
                    f"{base_url}users/me",
                    headers=test_headers,
                    params=test_params,
                    timeout=10,
                )
                print(
                    "   Key alone (/users/me) -> "
                    f"Status: {response_no_cookie.status_code} | Size: {len(response_no_cookie.text):,} bytes"
                )
                if response_no_cookie.status_code == 200:
                    print("   CRITICAL: Key works completely without cookies/session")
                results.append(
                    {
                        "test": "key_alone",
                        "placement": placement["name"],
                        "endpoint": "users/me",
                        "status": response_no_cookie.status_code,
                        "size": len(response_no_cookie.text),
                        "cookies_used": False,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                print(f"   Error in key-alone test: {exc}")

            print("\n" + "=" * 70)

        print_summary_header("TEST SUMMARY", divider_width=90)
        success_count = sum(1 for result in results if result.get("status") == 200)
        print(f"Total tests run       : {len(results)}")
        print(f"Successful 200 OK     : {success_count}")
        if success_count > 0:
            print("\nPOTENTIAL ISSUES FOUND:")
            print("   - API key works without proper login")
            print("   - Sensitive endpoints accessible with key")
            print("   - Key works without session/cookies")
        print("\nDetailed API Key testing completed.")
