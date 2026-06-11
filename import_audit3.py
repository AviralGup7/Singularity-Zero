import ast
from collections import defaultdict
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
}

file_exists_cache = {}


def exists(path: Path) -> bool:
    path = path.resolve()
    try:
        return file_exists_cache[path]
    except KeyError:
        file_exists_cache[path] = path.exists()
        return file_exists_cache[path]


def resolve_target(module_parts, rel_level, cur_pkg_parts):
    """Return a Path if the imported module exists under ROOT, else None."""
    if rel_level > 0:
        if not cur_pkg_parts:
            # absolute top-level relative shouldn't go above project root; be lenient
            base_parts = []
        else:
            # relative level 1 means package containing current module.
            # Example: src.a.b.c.py -> cur_pkg=src.a.b
            # level 1 -> base=src.a.b, level 2 -> base=src.a, level 3 -> base=src
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


# Build dependency graph: src dotted module path -> set of src dotted module paths it imports from.
graph = {}

# Map from Resolved Path -> dotted module path (best-effort, used for graph entries)
path_to_dotted = {}  # absolute path string -> dotted module path
for py in file_list:
    path_to_dotted[py.resolve().as_posix()] = None  # fill later

# Build dotted module name mapping
for py in file_list:
    rel = py.relative_to(ROOT)
    parts = list(rel.parts)
    # remove filename
    if parts[-1] == "__init__.py":
        dotted = ".".join(parts[:-1]) if parts[:-1] else ""
    else:
        dotted = (
            ".".join(parts[:-1] + [parts[-1].replace(".py", "")])
            if parts[:-1]
            else parts[-1].replace(".py", "")
        )
    path_to_dotted[py.resolve().as_posix()] = dotted if dotted else ""

# Quick scan result container
audit_issues = []  # (path_str, lineno, issue_text)


for py in file_list:
    try:
        src_text = py.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        audit_issues.append((str(py.resolve()), 0, f"Cannot read file: {e}"))
        continue
    try:
        tree = ast.parse(src_text)
    except SyntaxError as e:
        audit_issues.append((str(py.resolve()), e.lineno or 0, f"SyntaxError: {e.msg}"))
        continue

    rel_parts = list(py.relative_to(ROOT).parts)
    cur_pkg_parts = rel_parts[:-1]  # directory path components under src

    imports_from = defaultdict(set)  # target dotted -> source dotted

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] in STD_AND_THIRD_PARTY:
                    continue
                target = resolve_target(parts, 0, cur_pkg_parts)
                if target is None:
                    audit_issues.append(
                        (
                            str(py.resolve()),
                            node.lineno,
                            f"Import of unknown module/package '{alias.name}' (no matching src/ file or package)",
                        )
                    )
                else:
                    t_dotted = path_to_dotted.get(target.resolve().as_posix(), "")
                    if t_dotted:
                        imports_from[t_dotted].add(alias.name)
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
                        audit_issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Star import from unresolved module '{label}' (no matching src/ file or package)",
                            )
                        )
                    else:
                        t_dotted = path_to_dotted.get(target.resolve().as_posix(), "")
                        if t_dotted:
                            imports_from[t_dotted].add((node.module or "(relative)") + ".*")
                else:
                    target = resolve_target(
                        module_parts + alias.name.split("."), rel_level, cur_pkg_parts
                    )
                    if target is None:
                        full = (node.module or "") + ("." if node.module else "") + alias.name
                        audit_issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Import of unknown module/package '{full}' (no matching src/ file or package)",
                            )
                        )
                    else:
                        t_dotted = path_to_dotted.get(target.resolve().as_posix(), "")
                        if t_dotted:
                            imports_from[t_dotted].add(
                                (node.module or "(relative)") + "." + alias.name
                            )

    # Store only intrinsic name of source file as key in graph
    src_dotted = path_to_dotted.get(py.resolve().as_posix(), "")
    if src_dotted:
        graph[src_dotted] = {t.split(".")[0] for t in imports_from.keys() if t}

# Detect simple directed cycles using DFS.
# Weights only src.* imports. Reported per file in cycle as easy readout.
cycle_issues = []
visited = {}
rec_stack = set()
chain = []


def dfs(node, path):
    visited[node] = True
    rec_stack.add(node)
    chain.append(node)
    for nxt in sorted(graph.get(node, [])):
        if nxt in rec_stack:
            idx = path.index(nxt)
            cycle_nodes = path[idx:] + [nxt]
            cycle_issues.append(cycle_nodes)
        elif not visited.get(nxt, False):
            dfs(nxt, path + [nxt])
    chain.pop()
    rec_stack.remove(node)


for node in sorted(graph.keys()):
    if node and not visited.get(node, False):
        dfs(node, [node])

# --- __init__.py and missing __init__.py checks ---
package_issues = []
package_init_dirs = set()
for py in file_list:
    if py.name == "__init__.py":
        package_init_dirs.add(py.parent.resolve())

# Look for packages (directories with .py files inside and subdir-packages)
all_pkg_dirs = set()
for py in file_list:
    d = py.parent.resolve()
    if d != ROOT:
        all_pkg_dirs.add(d)

for pkg in all_pkg_dirs:
    if pkg not in package_init_dirs:
        # Print missing __init__.py for directory containing a .py (e.g. src/x/y.py -> src/x).
        pass  # skip noise from __pycache__ maybe
# Actually many dirs may not be packages; only report if there's a relative import into/outof it.
# For simplicity skip per-directory init audit for now and just concentrate on import issues and cycles.

print("\n=== Import existence issues ===\n")
seen = set()
for fp, lineno, msg in audit_issues:
    key = (fp, lineno, msg)
    if key in seen:
        continue
    seen.add(key)
    print(f"{fp}:{lineno}: {msg}")

print(f"\n[Count] {len(seen)} import existence issue(s).")

print("\n=== Potential circular dependencies (src import graph) ===\n")
if not cycle_issues:
    print("None detected.")
else:
    seen_cycles = set()
    for c in cycle_issues:
        key = tuple(c)
        if key in seen_cycles:
            continue
        seen_cycles.add(key)
        print(" -> ".join(c))

print(f"\n[Count] {len(seen_cycles)} cycle(s).")

print("\nDone.")
