import ast
import importlib.util
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path("src").resolve()
REPO_ROOT = ROOT.parent.resolve()
issues = []

STD_AND_THIRD_PARTY_FIRST = {
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
}

# Only process files whose imports start with 'src.'.
CANDIDATE_FILES = []
for py in sorted(ROOT.rglob("*.py")):
    try:
        txt = py.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.debug("Skipping unreadable file %s: %s", py, e)
        continue
    # quick prefilter on raw text line prefixes (faster than AST)
    if any((ln.startswith("from src.") or ln.startswith("import src.")) for ln in txt.splitlines()):
        CANDIDATE_FILES.append(py)

print(f"Candidate files with top-level src imports: {len(CANDIDATE_FILES)}", flush=True)


def file_module(py):
    rel = py.relative_to(ROOT)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        return ".".join(parts[:-1])
    return ".".join(parts[:-1] + [parts[-1][:-3]])


def abs_spec_for_from(module, level, cur_module):
    if level == 0:
        return module
    cur_parts = cur_module.split(".")
    base = cur_parts[: max(0, len(cur_parts) - level + 1)]
    return ".".join(base + (module.split(".") if module else []))


if REPO_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, REPO_ROOT.as_posix())

count = 0
for py in CANDIDATE_FILES:
    count += 1
    if count % 200 == 0:
        print(f"Scanning {count}/{len(CANDIDATE_FILES)} ...", flush=True)
    src_text = py.read_text(encoding="utf-8", errors="ignore")
    try:
        tree = ast.parse(src_text)
    except SyntaxError as e:
        issues.append((str(py.resolve()), e.lineno or 0, f"SyntaxError: {e.msg}"))
        continue
    cur_module = file_module(py)
    for node in tree.body if hasattr(tree, "body") else []:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("src."):
                    spec = importlib.util.find_spec(alias.name)
                    if spec is None:
                        issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Import of unknown module/package '{alias.name}' (__init__ py missing?)",
                            )
                        )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if not (
                module.startswith("src.")
                or (
                    node.level > 0
                    and (module == "" or module.split(".")[0] not in STD_AND_THIRD_PARTY_FIRST)
                )
            ):
                continue
            for alias in node.names:
                if alias.name == "*":
                    abs_name = abs_spec_for_from(module, node.level, cur_module)
                    if abs_name:
                        spec = importlib.util.find_spec(abs_name)
                        if spec is None:
                            issues.append(
                                (
                                    str(py.resolve()),
                                    node.lineno,
                                    f"Star import from unresolved source '{module or '(relative)'}'",
                                )
                            )
                else:
                    abs_name = abs_spec_for_from(module + "." + alias.name, node.level, cur_module)
                    if abs_name:
                        spec = importlib.util.find_spec(abs_name)
                        if spec is None:
                            issues.append(
                                (
                                    str(py.resolve()),
                                    node.lineno,
                                    f"Import of unknown module/package '{module + '.' + alias.name if module else alias.name}'",
                                )
                            )

print("\n=== Import issues for src.* imports ===\n")
seen = set()
uniq = []
for item in issues:
    if item not in seen:
        seen.add(item)
        uniq.append(item)
for fp, lineno, msg in uniq:
    print(f"{fp}:{lineno}: {msg}")
print(f"\n[Count] {len(uniq)} issue(s).\n")
