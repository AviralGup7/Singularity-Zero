import ast
from pathlib import Path

ROOT = Path("src").resolve()
issues = []
file_list = sorted(ROOT.rglob("*.py"))

# Skip known stdlib and common third-party top-level module names.
STD_AND_THIRD_PARTY = {
    "abc",
    "argparse",
    "asyncio",
    "base64",
    "binascii",
    "collections",
    "copy",
    "csv",
    "datetime",
    "difflib",
    "enum",
    "fnmatch",
    "functools",
    "getopt",
    "glob",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "inspect",
    "io",
    "itertools",
    "json",
    "logging",
    "math",
    "multiprocessing",
    "os",
    "pathlib",
    "pickle",
    "platform",
    "pprint",
    "random",
    "re",
    "secrets",
    "shutil",
    "signal",
    "socket",
    "sqlite3",
    "ssl",
    "statistics",
    "string",
    "struct",
    "subprocess",
    "sys",
    "tempfile",
    "textwrap",
    "threading",
    "time",
    "traceback",
    "types",
    "typing",
    "uuid",
    "urllib",
    "warnings",
    "wave",
    "xml",
    "zipfile",
    "zoneinfo",
    "dataclasses",
    "typing_extensions",
    "contextlib",
    "decimal",
    "queue",
    "weakref",
    "array",
    "bisect",
    "codecs",
    "codecs",
    "concurrent",
    "configparser",
    "contextvars",
    "ctypes",
    "dataclasses",
    "email",
    "ensurepip",
    "errno",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "graphlib",
    "grp",
    "gzip",
    "imaplib",
    "imghdr",
    "imp",
    "importlib",
    "ipaddress",
    "keyword",
    "linecache",
    "locale",
    "lzma",
    "mailbox",
    "mimetypes",
    "mmap",
    "modulefinder",
    "netrc",
    "nis",
    "nntplib",
    "optparse",
    "parser",
    "pdb",
    "pickle",
    "pip",
    "pipes",
    "pkgutil",
    "plistlib",
    "posix",
    "posixpath",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "py_compile",
    "pyclbr",
    "pydoc",
    "quopri",
    "readline",
    "reprlib",
    "resource",
    "rlcompleter",
    "runpy",
    "sched",
    "select",
    "selectors",
    "shelve",
    "shlex",
    "site",
    "smtpd",
    "smtplib",
    "sndhdr",
    "socketserver",
    "spwd",
    "sre_compile",
    "sre_constants",
    "sre_parse",
    "stat",
    "stringprep",
    "sunau",
    "symbol",
    "symtable",
    "sysconfig",
    "tabnanny",
    "tarfile",
    "telnetlib",
    "termios",
    "test",
    "timeit",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "trace",
    "tracemalloc",
    "tty",
    "turtle",
    "turtledemo",
    "unicodedata",
    "unittest",
    "uu",
    "venv",
    "warnings",
    "weakref",
    "webbrowser",
    "winreg",
    "winsound",
    "wsgiref",
    "xdrlib",
    "xmlrpc",
    "zipapp",
    "zlib",
    "_thread",
    "__future__",
    "requests",
    "httpx",
    "httptools",
    "starlette",
    "fastapi",
    "uvicorn",
    "django",
    "sqlalchemy",
    "pydantic",
    "numpy",
    "pandas",
    "scrapy",
    "selenium",
    "beautifulsoup4",
    "bs4",
    "lxml",
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
    "psycopg2",
    "mysqlclient",
    "paramiko",
    "fabric",
    "ansible",
    "boto3",
    "botocore",
    "google",
    "azure",
    "jwt",
    "croniter",
    "dateutil",
    "websockets",
    "aiohttp",
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
    "scikit_learn",
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
}

# Build package directories set for quick check.
package_dirs = set()
for py in file_list:
    if py.name == "__init__.py":
        package_dirs.add(py.parent.resolve())

file_exists_cache = {}


def exists(path: Path) -> bool:
    path = path.resolve()
    try:
        return file_exists_cache[path]
    except KeyError:
        file_exists_cache[path] = path.exists()
        return file_exists_cache[path]


def resolve_target(module_parts, rel_level, cur_pkg_parts):
    """Return a Path if the module being imported exists under ROOT, else None."""
    if rel_level > 0:
        # base = current package go up `rel_level` levels.
        base_parts = cur_pkg_parts[: max(0, len(cur_pkg_parts) - rel_level + 1)]
        target_parts = base_parts + module_parts
    else:
        target_parts = list(module_parts)
    if not target_parts:
        return None
    candidate = ROOT.joinpath(*target_parts)
    if exists(candidate.with_suffix(".py")):
        return candidate.with_suffix(".py")
    if exists(candidate / "__init__.py"):
        return candidate / "__init__.py"
    return None


for py in file_list:
    try:
        src_text = py.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        issues.append((str(py), 0, f"Cannot read file: {e}"))
        continue
    try:
        tree = ast.parse(src_text)
    except SyntaxError as e:
        issues.append((str(py), e.lineno or 0, f"SyntaxError: {e.msg}"))
        continue

    rel_parts = list(py.relative_to(ROOT).parts)
    # For __init__.py, the current package is its parent directory.
    # For module.py, the current package is its parent directory.
    cur_pkg_parts = rel_parts[:-1]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] in STD_AND_THIRD_PARTY:
                    continue
                if resolve_target(parts, 0, cur_pkg_parts) is None:
                    issues.append(
                        (
                            str(py),
                            node.lineno,
                            f"Import of unknown module/package '{alias.name}' (no matching src/ file or package)",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module_parts = node.module.split(".") if node.module else []
            rel_level = node.level
            top = (module_parts or [""])[0]
            if rel_level == 0 and top in STD_AND_THIRD_PARTY:
                continue
            for alias in node.names:
                if alias.name == "*":
                    target = resolve_target(module_parts, rel_level, cur_pkg_parts)
                    if target is None:
                        label = node.module or "(relative)"
                        issues.append(
                            (
                                str(py),
                                node.lineno,
                                f"Star import from unresolved module '{label}' (no matching src/ file or package)",
                            )
                        )
                else:
                    target = resolve_target(
                        module_parts + alias.name.split("."), rel_level, cur_pkg_parts
                    )
                    if target is None:
                        full = (node.module or "") + ("." if node.module else "") + alias.name
                        issues.append(
                            (
                                str(py),
                                node.lineno,
                                f"Import of unknown module/package '{full}' (no matching src/ file or package)",
                            )
                        )

print("\n=== Import Audit Report ===\n")
if not issues:
    print("No obvious import existence issues detected.")
else:
    for fp, lineno, msg in issues:
        print(f"{fp}:{lineno}: {msg}")
