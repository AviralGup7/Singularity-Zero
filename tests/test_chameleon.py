from src.core.frontier.chameleon import RequestChameleon, wrap_polymorphic_request


def test_chameleon_mutate_headers():
    chameleon = RequestChameleon()
    base_headers = {"accept": "text/html"}
    mutated = chameleon.mutate_headers(base_headers)
    assert "User-Agent" in mutated
    # Ensure correct capitalization or presence
    assert any(k.lower() == "accept" for k in mutated.keys())
    assert len(mutated) >= 2


def test_wrap_polymorphic_request():
    base_headers = {"Host": "example.com"}
    req = wrap_polymorphic_request(base_headers)
    assert "headers" in req
    assert "User-Agent" in req["headers"]
    assert req["timeout"] >= 10.0


def test_chameleon_diverse_noise_headers():
    chameleon = RequestChameleon()
    base_headers = {"Host": "example.com"}

    noise_prefixes = {
        "X-Request-ID",
        "X-Correlation-ID",
        "X-Session-Token",
        "X-Trace-ID",
        "X-Flow-ID",
        "X-Client-Signature",
        "X-Frontend-ID",
        "X-Telemetry-ID",
    }

    found_any = False
    # Run multiple times to trigger the 30% random noise injection
    for _ in range(50):
        mutated = chameleon.mutate_headers(base_headers)
        # Find any keys that look like <prefix>-<num>
        for key in mutated.keys():
            if "-" in key:
                prefix = key.rsplit("-", 1)[0]
                if prefix in noise_prefixes:
                    found_any = True
                    break
        if found_any:
            break

    assert found_any, "Did not inject any polymorphic noise headers from the diverse pool"
