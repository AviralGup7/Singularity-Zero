import time
from datetime import datetime

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


def advanced_api_key_test(
    base_url: str,
    api_key: str,
    cookies: dict[str, str] | None = None,
    proxy: dict[str, str] | None = None,
) -> None:
    import requests  # type: ignore[import-untyped]  # type: ignore[import-untyped]

    base_url = normalize_base_url(base_url)
    print_banner(
        "ADVANCED API KEY SECURITY TESTS",
        [
            f"Target     : {base_url}",
            f"API Key    : {display_secret(api_key)}",
            f"Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        ],
        divider_width=100,
    )

    with requests.Session() as session:
        headers = base_headers("Mozilla/5.0 (Advanced-API-Key-Test)")
        placements = key_locations(api_key)[:2]
        results = []

        for placement in placements:
            print_section_header(f"Using key placement: {placement['name']}", divider_width=90)
            test_headers, test_params = placement_request_parts(headers, placement)

            print("\n1. Testing Key from Different IP/Device (Restriction Bypass)")
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
                "curl/7.88.1",
            ]
            for index, ua in enumerate(user_agents, 1):
                current_headers = {**test_headers, "User-Agent": ua}
                try:
                    response = request(
                        session,
                        "GET",
                        f"{base_url}users/me",
                        headers=current_headers,
                        params=test_params,
                        cookies=cookies,
                        proxies=proxy,
                        timeout=12,
                    )
                    print(
                        f"   Device/IP Simulation {index} -> Status: {response.status_code} | UA: {ua[:40]}..."
                    )
                    if response.status_code == 200:
                        print("      Key works from different device/simulation")
                    results.append(
                        {
                            "test": "different_ip_device",
                            "simulation": index,
                            "status": response.status_code,
                            "user_agent": ua[:50],
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"   Simulation {index} failed: {exc}")

            print("\n2. Modifying Request Parameters (IDOR / Other Users Data Exposure)")
            for test_id in ["123", "456", "789", "999999", "1", "0", "-1", "admin"]:
                try:
                    response = request(
                        session,
                        "GET",
                        f"{base_url}users/{test_id}",
                        headers=test_headers,
                        params=test_params,
                        cookies=cookies,
                        timeout=10,
                    )
                    size = len(response.text)
                    if response.status_code == 200:
                        print(
                            f"   POTENTIAL IDOR: /users/{test_id:<8} -> 200 OK | Size: {size:,} bytes"
                        )
                        keys = safe_json_keys(response)
                        if keys:
                            print(f"      Data keys: {keys[:6]}")
                    elif response.status_code in (403, 404):
                        print(f"   /users/{test_id:<8} -> {response.status_code} (Expected)")
                    else:
                        print(f"   /users/{test_id:<8} -> {response.status_code} | Size: {size:,}")
                    results.append(
                        {
                            "test": "idor_parameter_tampering",
                            "endpoint": f"users/{test_id}",
                            "status": response.status_code,
                            "size": size,
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"   Error testing ID {test_id}: {exc}")

            print("\n3. Replay Same Request Multiple Times (Rate Limit Abuse Test)")
            print("   Sending 25 rapid requests to /users/me ...")
            replay_count = 25
            success_count = 0
            blocked_count = 0
            start_time = time.time()
            for index in range(1, replay_count + 1):
                try:
                    response = request(
                        session,
                        "GET",
                        f"{base_url}users/me",
                        headers=test_headers,
                        params=test_params,
                        cookies=cookies,
                        timeout=8,
                    )
                    if response.status_code == 200:
                        success_count += 1
                    elif response.status_code in (403, 429):
                        blocked_count += 1
                        print(
                            f"   Request {index:2d}: Rate limited / Blocked (Status {response.status_code})"
                        )
                        break
                    time.sleep(0.15)
                except requests.exceptions.RequestException:
                    print(f"   Request {index:2d}: Network error")
                except Exception as exc:
                    print(f"   Request {index:2d}: Unexpected error: {type(exc).__name__}")
            duration = time.time() - start_time
            print("\n   Replay Summary:")
            print(f"      Total requests sent : {replay_count}")
            print(f"      Successful 200 OK   : {success_count}")
            print(f"      Rate limited        : {blocked_count}")
            print(f"      Duration            : {duration:.2f} seconds")
            if success_count > 15:
                print("      WARNING: Weak or missing rate limiting detected")
            results.append(
                {
                    "test": "rate_limit_replay",
                    "requests_sent": replay_count,
                    "success_200": success_count,
                    "rate_limited": blocked_count,
                    "duration_sec": round(duration, 2),
                }
            )

        print_summary_header("ADVANCED TEST SUMMARY", divider_width=100)
        print("Tests Completed: Different IP, IDOR Tampering, Rate Limit Replay")
        idor_success = sum(
            1
            for result in results
            if result.get("test") == "idor_parameter_tampering" and result.get("status") == 200
        )
        if idor_success > 2:
            print(f"HIGH RISK: {idor_success} IDs returned 200 OK -> Possible mass data exposure")
        print("\nAdvanced API Key testing completed.")
        print("Tip: Look for 200 OK on other user IDs or high success rate in replay test.")
