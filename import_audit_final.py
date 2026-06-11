import ast
from pathlib import Path

ROOT = Path("src").resolve()
issues = []
file_list = sorted(ROOT.rglob("*.py"))

# Top-level names to skip (stdlib + common third-party).
# For third-party we mostly care about the root package name,
# since submodules still need to resolve from originally installed packages.
SKIP_TOP = {
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
    "concurrent",
    "configparser",
    "contextvars",
    "ctypes",
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
    "reportlab",
    "structlog",
    "dns",
}

# Build package dirs set.
package_dirs = set()
for py in file_list:
    if py.name == "__init__.py":
        package_dirs.add(py.parent.resolve())

# Map path -> dotted module
path_to_dotted = {}
for py in file_list:
    rel = py.relative_to(ROOT)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        dotted = ".".join(parts[:-1])
    else:
        dotted = ".".join(parts[:-1] + [parts[-1][:-3]])
    path_to_dotted[py.resolve().as_posix()] = dotted

file_cache = {}


def exists(path: Path) -> bool:
    p = path.resolve()
    try:
        return file_cache[p]
    except KeyError:
        file_cache[p] = p.exists()
        return file_cache[p]


def resolve_candidate(module_parts, rel_level, cur_pkg_parts):
    if rel_level > 0:
        if not cur_pkg_parts:
            base_parts = []
        else:
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
        issues.append((str(py.resolve()), 0, f"Cannot read file: {e}"))
        continue
    try:
        tree = ast.parse(src_text)
    except SyntaxError as e:
        issues.append((str(py.resolve()), e.lineno or 0, f"SyntaxError: {e.msg}"))
        continue

    rel_parts = list(py.relative_to(ROOT).parts)
    cur_pkg_parts = rel_parts[:-1]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts and parts[0] in SKIP_TOP:
                    continue
                if resolve_candidate(parts, 0, cur_pkg_parts) is None:
                    issues.append(
                        (
                            str(py.resolve()),
                            node.lineno,
                            f"Import of unknown module/package '{alias.name}' (no matching src/ file or package)",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            parts = module.split(".") if module else []
            top = parts[0] if parts else ""
            if node.level == 0 and top in SKIP_TOP:
                continue
            rel_level = node.level
            for alias in node.names:
                if alias.name == "*":
                    target = resolve_candidate(parts, rel_level, cur_pkg_parts)
                    if target is None:
                        label = module or "(relative)"
                        issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Star import from unresolved module '{label}' (no matching src/ file or package)",
                            )
                        )
                else:
                    target = resolve_candidate(
                        parts + alias.name.split("."), rel_level, cur_pkg_parts
                    )
                    if target is None:
                        full_name = ((module + ".") if module else "") + alias.name
                        issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Import of unknown module/package '{full_name}' (no matching src/ file or package)",
                            )
                        )

# dedupe
seen = set()
out = []
for item in issues:
    if item not in seen:
        seen.add(item)
        out.append(item)

print("\n=== Import Audit Report ===\n")
count = 0
for fp, lineno, msg in out:
    print(f"{fp}:{lineno}: {msg}")
    count += 1
print(f"\n[Count] {count} issue(s).")
