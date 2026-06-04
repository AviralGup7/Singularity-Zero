import pathlib

# FIX-1: lateral_graph.py comment and limit validation (already done, ensure final state)
p = pathlib.Path(
    r"D:\cyber security test pipeline - Copy\src\analysis\intelligence\lateral_graph.py"
)
text = p.read_text(encoding="utf-8")
old = """class LateralGraph:\n    \"\"\"\n    Frontier Knowledge Graph.\n    Models the relationship between subdomains, URLs, vulnerabilities, and potential pivot points.\n    Enables automatic identification of multi-stage attack paths.\n    \"\"\"\n"""
new = """class LateralGraph:\n    \"\"\"\n    Frontier Knowledge Graph.\n    Models the relationship between subdomains, URLs, vulnerabilities, and potential pivot points.\n    Enables automatic identification of multi-stage attack paths.\n    \"\"\"\n\n    # @future-developer: Kuzu parameterized bindings ($param) are not confirmed for\n    # the installed kuzu version. User-controlled values (asset, fid, severity) are\n    # enforced through _cypher_string() before any Cypher interpolation happens.\n    # Never remove that guard or introduce new f-string queries without verified bindings.\n"""
if old in text:
    text = text.replace(old, new, 1)
else:
    # already transformed, verify
    pass
if "{int(limit)}" not in text:
    text = text.replace("LIMIT {limit}", "LIMIT {int(limit)}")
if "remaining = max(1, limit - len(nodes))" in text:
    text = text.replace(
        "remaining = max(1, limit - len(nodes))", "remaining = max(1, int(limit) - len(nodes))"
    )
if "LIMIT {limit * 2}" in text:
    text = text.replace("LIMIT {limit * 2}", "LIMIT {int(limit) * 2}")
p.write_text(text, encoding="utf-8")
