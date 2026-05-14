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
)


def subdomain_privilege_methods_test(
    base_url: str,
    api_key: str,
    cookies: dict[str, Any] | None = None,
) -> None:
    import requests  # type: ignore[import-untyped]  # type: ignore[import-untyped]

    base_url = normalize_base_url(base_url)
    print_banner(
        "API KEY SECURITY TEST - PART 3",
        [
            f"Target Base : {base_url}",
            f"API Key     : {display_secret(api_key)}",
            f"Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        ],
        divider_width=95,
    )

    with requests.Session() as session:
        headers = base_headers("Mozilla/5.0 (API-Key-Scope-Test)")
        results = []

        for placement in key_locations(api_key)[:2]:
            print_section_header(f"Key Placement: {placement['name']}", divider_width=85)
            test_headers, _ = placement_request_parts(headers, placement)

            print("\n1. Testing Key on Different Subdomains/Services (Scope Overreach)")
            subdomains = [
                "api",
                "app",
                "admin",
                "dashboard",
                "internal",
                "dev",
                "staging",
                "v1",
                "v2",
                "beta",
                "sandbox",
                "console",
                "portal",
            ]
            main_domain = base_url.replace("https://", "").replace("http://", "").split("/")[0]
            base_domain = ".".join(main_domain.split(".")[-2:])
            for sub in subdomains:
                test_url = f"https://{sub}.{base_domain}/"
                try:
                    response = request(
                        session,
                        "GET",
                        f"{test_url}users/me",
                        headers=test_headers,
                        cookies=cookies,
                        timeout=10,
                        allow_redirects=True,
                    )
                    if response.status_code == 200:
                        print(f"   SCOPE OVERREACH: https://{sub}.{base_domain} -> 200 OK")
                    elif response.status_code in (401, 403):
                        print(f"   {sub:<12} -> {response.status_code} (Access Denied)")
                    else:
                        print(f"   {sub:<12} -> Status: {response.status_code}")
                    results.append(
                        {
                            "test": "subdomain_scope",
                            "subdomain": sub,
                            "status": response.status_code,
                        }
                    )
                except requests.exceptions.RequestException:
                    print(f"   {sub:<12} -> Connection failed / Not found")
                except Exception as exc:
                    print(f"   {sub:<12} -> Error: {type(exc).__name__}")

            print("\n2. Testing Privilege Escalation Endpoints")
            escalation_endpoints = [
                "admin",
                "admin/users",
                "admin/settings",
                "admin/roles",
                "admin/upgrade",
                "admin/promote",
                "superuser",
                "elevate",
                "role",
                "permissions",
                "make-admin",
                "grant-access",
                "users?role=admin",
                "account/upgrade",
                "billing/plan",
            ]
            for endpoint in escalation_endpoints:
                try:
                    response_get = request(
                        session,
                        "GET",
                        f"{base_url}{endpoint}",
                        headers=test_headers,
                        cookies=cookies,
                        timeout=10,
                    )
                    if response_get.status_code == 200:
                        print(f"   PRIVILEGE ESCALATION: /{endpoint} -> 200 OK (GET)")
                    elif response_get.status_code in (401, 403):
                        print(f"   /{endpoint:<20} -> {response_get.status_code} (Good)")
                    else:
                        print(f"   /{endpoint:<20} -> {response_get.status_code}")

                    if any(token in endpoint for token in ("admin", "upgrade", "role")):
                        try:
                            response_post = request(
                                session,
                                "POST",
                                f"{base_url}{endpoint}",
                                headers=test_headers,
                                cookies=cookies,
                                json_body={"role": "admin", "user_id": "123"},
                                timeout=8,
                            )
                            if response_post.status_code in (200, 201, 204):
                                print(
                                    f"   CRITICAL: POST /{endpoint} succeeded -> Possible escalation"
                                )
                        except requests.exceptions.RequestException:
                            print(f"   WARNING: POST /{endpoint} failed: Connection error")
                        except Exception as exc:
                            print(
                                f"   WARNING: POST /{endpoint} failed: {type(exc).__name__}: {exc}"
                            )

                    results.append(
                        {
                            "test": "privilege_escalation",
                            "endpoint": endpoint,
                            "get_status": response_get.status_code,
                        }
                    )
                except requests.exceptions.RequestException:
                    print(f"   /{endpoint} -> Connection error")
                except Exception as exc:
                    print(f"   /{endpoint} -> Error: {type(exc).__name__}")

            print("\n3. Testing Key with Different HTTP Methods (GET/POST/PUT)")
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
            for method in methods:
                print(f"\n   Method: {method}")
                for endpoint in ["users/me", "orders", "profile", "settings"]:
                    try:
                        request_kwargs: dict[str, Any] = {
                            "headers": test_headers,
                            "cookies": cookies,
                            "timeout": 10,
                        }
                        if method in {"POST", "PUT", "PATCH"}:
                            request_kwargs["json_body"] = (
                                {"test": "data"} if method == "POST" else {"updated": True}
                            )
                            if method == "PATCH":
                                request_kwargs["json_body"] = {"field": "value"}
                        response = request(
                            session, method, f"{base_url}{endpoint}", **request_kwargs
                        )
                        status = response.status_code
                        print(f"      {method:<6} /{endpoint:<12} -> {status}")
                        if status == 200 and method in {"POST", "PUT", "DELETE"}:
                            print(f"         Key allows WRITE action with {method}")
                        results.append(
                            {
                                "test": "http_methods",
                                "method": method,
                                "endpoint": endpoint,
                                "status": status,
                            }
                        )
                    except requests.exceptions.RequestException:
                        print(f"      {method:<6} /{endpoint} -> Connection error")
                    except Exception as exc:
                        print(f"      {method:<6} /{endpoint} -> Error: {type(exc).__name__}")

        print_summary_header("TEST SUMMARY - Scope, Privilege & Methods", divider_width=95)
        scope_success = sum(
            1
            for result in results
            if result.get("test") == "subdomain_scope" and result.get("status") == 200
        )
        priv_success = sum(
            1
            for result in results
            if result.get("test") == "privilege_escalation" and result.get("get_status") == 200
        )
        write_success = sum(
            1
            for result in results
            if result.get("test") == "http_methods"
            and result.get("status") == 200
            and result.get("method") in {"POST", "PUT", "DELETE"}
        )
        if scope_success > 0:
            print(f"Scope Overreach Detected on {scope_success} subdomains")
        if priv_success > 0:
            print(f"Potential Privilege Escalation on {priv_success} endpoints")
        if write_success > 0:
            print(f"Key allows WRITE operations ({write_success} successful)")
        print("\nSubdomain, Privilege Escalation & HTTP Methods testing completed.")
