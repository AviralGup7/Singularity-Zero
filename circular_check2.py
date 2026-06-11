import ast
from collections import defaultdict
from pathlib import Path

ROOT = Path("src").resolve()

all_py = sorted(ROOT.rglob("*.py"))

# Build mapping directory -> set of child directories / child files that are imported from this directory.
# We only track imports where the imported file actually exists under src.

# Map of existing module paths
module_exists = {}  # dotted -> bool


def path_exists(*parts):
    return (ROOT / Path(*parts)).exists()


def module_file_exists(dotted):
    # check dotted as a package (__init__) or module (.py)
    as_py = ROOT.joinpath(*dotted.split(".")).with_suffix(".py")
    if as_py.exists():
        return True
    as_pkg = ROOT.joinpath(*dotted.split("."), "__init__.py")
    if as_pkg.exists():
        return True
    return False


# Build adjacency based on relative imports only
_adj = defaultdict(set)

for py in all_py:
    try:
        tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        continue
    rel = py.relative_to(ROOT)
    cur_pkg_parts = rel.parts[:-1]
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        module = (node.module or "").split(".")
        if not module:
            continue
        top = module[0]
        if top in {
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
        }:
            continue
        # Only relative imports
        if node.level == 0:
            continue
        # module here is relative module path without attribute attributes.
        # We're checking if the target package exists.
        target_parts = cur_pkg_parts[: max(0, len(cur_pkg_parts) - node.level + 1)] + list(module)
        target = ".".join(target_parts)
        if module_file_exists(target):
            src_dotted = ".".join(cur_pkg_parts)
            _adj[src_dotted].add(target)

# Detect simple mutual dependencies.
seen = set()
for a, deps in list(_adj.items()):
    for b in deps:
        if b in _adj and a in _adj[b] and (a, b) not in seen:
            seen.add((a, b))
            print(f"Circular dependency detected: {a} <-> {b}")

if not seen:
    print("No direct circular dependencies detected.")
