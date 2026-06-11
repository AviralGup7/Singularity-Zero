import ast
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path("src").resolve()

# Build adjacency list of module -> imported modules (only local src).
# Direct edges for circular import detection.
edges = {}

for py in sorted(ROOT.rglob("*.py")):
    try:
        tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        logger.debug("Failed to parse %s: %s", py, exc, exc_info=True)
        continue
    rel = py.relative_to(ROOT)
    parts = list(rel.parts)
    cur_module = ".".join(parts[:-1] + ([parts[-1][:-3]] if parts[-1] != "__init__.py" else []))
    if parts[-1] == "__init__.py":
        cur_module = ".".join(parts[:-1])
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.append(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module.split(".")[0] if node.module else ""
            if mod:
                imports.append(mod)
    # only local src top-level
    deps = {
        m
        for m in imports
        if m
        not in {
            "os",
            "sys",
            "typing",
            "pathlib",
            "collections",
            "itertools",
            "functools",
            "dataclasses",
            "datetime",
            "re",
            "json",
            "logging",
            "math",
            "time",
            "threading",
            "multiprocessing",
            "subprocess",
            "hashlib",
            "hmac",
            "secrets",
            "random",
            "statistics",
            "string",
            "struct",
            "io",
            "contextlib",
            "decimal",
            "enum",
            "abc",
            "copy",
            "pprint",
            "warnings",
            "inspect",
            "textwrap",
            "traceback",
            "types",
            "typing_extensions",
            "importlib",
            "asyncio",
            "concurrent",
            "http",
            "urllib",
            "email",
            "xml",
            "csv",
            "configparser",
            "sqlite3",
            "socket",
            "ssl",
            "select",
            "signal",
            "mmap",
            "tempfile",
            "shutil",
            "glob",
            "fnmatch",
            "getopt",
            "optparse",
            "argparse",
            "pdb",
            "profile",
            "pstats",
            "timeit",
            "doctest",
            "unittest",
            "pkgutil",
            "runpy",
            "site",
            "sysconfig",
            "platform",
            "getpass",
            "grp",
            "pwd",
            "resource",
            "tty",
            "termios",
            "fcntl",
            "spwd",
            "base64",
            "binascii",
            "quopri",
            "uu",
            "codecs",
            "pydantic",
            "fastapi",
            "starlette",
            "uvicorn",
            "httpx",
            "requests",
            "aiohttp",
            "sqlalchemy",
            "celery",
            "redis",
            "pika",
            "kafka",
            "grpc",
            "protobuf",
            "msgpack",
            "cryptography",
            "pycryptodome",
            "bcrypt",
            "argon2",
            "passlib",
            "paramiko",
            "boto3",
            "botocore",
            "azure",
            "google",
            "jwt",
            "pyjwt",
            "dateutil",
            "croniter",
            "websockets",
            "aiofiles",
            "yaml",
            "toml",
            "prometheus_client",
            "opentelemetry",
            "sentry_sdk",
            "loguru",
            "pytest",
            "coverage",
            "mypy",
            "watchdog",
            "psutil",
            "dnspython",
            "scapy",
            "mitmproxy",
            "h2",
            "hpack",
            "hyperframe",
            "graphql_core",
            "graphene",
            "nltk",
            "spacy",
            "transformers",
            "torch",
            "tensorflow",
            "xgboost",
            "lightgbm",
            "catboost",
            "pydash",
            "toolz",
            "cytoolz",
            "boltons",
            "stdnum",
            "phonenumbers",
            "email_validator",
            "reportlab",
            "structlog",
            "dns",
        }
    }
    if deps:
        edges[cur_module] = deps

print(f"Module graph size: {len(edges)}\n")

# Detect direct cycles A -> B and B -> A.
seen = set()
for a, deps in edges.items():
    for b in deps:
        if b in edges and a in edges[b] and (b, a) not in seen:
            seen.add((a, b))
            print(f"Circular import: {a} <-> {b}")
