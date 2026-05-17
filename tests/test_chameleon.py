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
