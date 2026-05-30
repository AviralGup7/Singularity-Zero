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


def test_chameleon_diverse_noise_headers(monkeypatch):
    # Mock secrets.randbelow to ensure noise_chance is exceeded (e.g. returns 8 > 6)
    # and choice is deterministic
    import secrets

    monkeypatch.setattr(
        secrets, "randbelow", lambda n: n - 1
    )  # always returns max possible, which is > 6

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

    mutated = chameleon.mutate_headers(base_headers)
    found_any = False
    for key in mutated.keys():
        if "-" in key:
            prefix = key.rsplit("-", 1)[0]
            if prefix in noise_prefixes:
                found_any = True
                break

    assert found_any, "Did not inject any polymorphic noise headers from the diverse pool"
