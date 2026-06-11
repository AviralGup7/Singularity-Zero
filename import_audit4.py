import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path("src").resolve()
REPO_ROOT = ROOT.parent.resolve()
PYTHONPATH = str(REPO_ROOT)

# Ensure repo root on sys.path so we can resolve "src.xxx"
if PYTHONPATH not in sys.path:
    sys.path.insert(0, PYTHONPATH)

issues = []


def add_issue(path_str, lineno, msg):
    issues.append((path_str, lineno, msg))


file_list = sorted(ROOT.rglob("*.py"))

# Build dotted module -> absolute path mapping
module_name_to_path = {}
path_to_module_name = {}
for py in file_list:
    rel = py.relative_to(ROOT)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        dotted = ".".join(parts[:-1])
    else:
        dotted = ".".join(parts[:-1] + [parts[-1][:-3]])
    module_name_to_path[dotted] = py.resolve()
    path_to_module_name[py.resolve().as_posix()] = dotted


# Use find_spec to validate all imports.
KNOWN_TOP = {
    # stdlib qualifiers where submodule itself is a package (allow any depth).
    # We will check existence by find_spec for unknowns.
}

for py in file_list:
    try:
        src = py.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        add_issue(str(py.resolve()), 0, f"Cannot read file: {e}")
        continue
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        add_issue(str(py.resolve()), e.lineno or 0, f"SyntaxError: {e.msg}")
        continue

    rel = py.relative_to(ROOT)
    cur_pkg_parts = rel.parts[:-1]  # directories under src
    if rel.name == "__init__.py":
        cur_module_name = ".".join(cur_pkg_parts)
    else:
        cur_module_name = ".".join(cur_pkg_parts + [rel.stem])

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in {
                    "os",
                    "sys",
                    "typing",
                    "pathlib",
                    "collections",
                    "collections.abc",
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
                    "fractions",
                    "numbers",
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
                    "asyncio",
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
                    "cProfile",
                    "timeit",
                    "doctest",
                    "unittest",
                    "doctest",
                    "pkgutil",
                    "modulefinder",
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
                    "crypt",
                    "hashlib",
                    "base64",
                    "binascii",
                    "quopri",
                    "uu",
                    "codecs",
                    "codeop",
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
                    "pydantic_settings",
                    "reportlab",
                    "structlog",
                }:
                    continue
                spec = importlib.util.find_spec(alias.name)
                if spec is None:
                    # also maybe it's a local src prefixed module that we already know is missing
                    add_issue(
                        str(py.resolve()),
                        node.lineno,
                        f"Import of unknown module/package '{alias.name}' (importlib.util.find_spec returned None)",
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            parts = module.split(".") if module else []
            top = parts[0] if parts else ""
            # skip stdlib/third-party by top-level
            if node.level == 0 and top in {
                "os",
                "sys",
                "typing",
                "pathlib",
                "collections",
                "collections.abc",
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
                "fractions",
                "numbers",
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
                "cProfile",
                "timeit",
                "doctest",
                "unittest",
                "doctest",
                "pkgutil",
                "modulefinder",
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
                "crypt",
                "hashlib",
                "base64",
                "binascii",
                "quopri",
                "uu",
                "codecs",
                "codeop",
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
                "pydantic_settings",
                "reportlab",
                "structlog",
            }:
                continue
            try:
                abs_name = None
                if node.level == 0:
                    abs_name = module
                else:
                    cur_parts = cur_module_name.split(".")
                    # calculate base for relative import; go up level-1 packages: parent is level-1
                    # In absolute terms, level=1 -> current package (parent directory of current module)
                    base = cur_parts[: max(0, len(cur_parts) - node.level + 1)]
                    # from . import x means target is base + x
                    abs_name = ".".join(base + parts)
                # debug
                if abs_name == "":
                    continue
                spec = importlib.util.find_spec(abs_name)
                if spec is None:
                    label = module if module else "(relative)"
                    add_issue(
                        str(py.resolve()),
                        node.lineno,
                        f"Import of unknown module/package '{label}' (importlib.util.find_spec returned None)",
                    )
            except (ImportError, ModuleNotFoundError, ValueError) as e:
                label = module if module else "(relative)"
                add_issue(
                    str(py.resolve()), node.lineno, f"Import resolution error for '{label}': {e}"
                )

# dedupe
seen = set()
uniq = []
for item in issues:
    if item not in seen:
        seen.add(item)
        uniq.append(item)

print("\n=== Import existence issues (importlib) ===\n")
for fp, lineno, msg in uniq:
    print(f"{fp}:{lineno}: {msg}")

print(f"\n[Count] {len(uniq)} issue(s).\n")
