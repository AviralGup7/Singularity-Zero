import ast
from pathlib import Path

ROOT = Path("src").resolve()
issues = []


def main():
    # Build module map: full module name -> absolute file path
    # map lowercase module parts to actual paths for fuzzy match
    module_map = {}  # dotted name -> file path

    for py in sorted(ROOT.rglob("*.py")):
        rel = py.relative_to(ROOT)
        parts = list(rel.with_suffix("").parts)
        if parts == ["__init__"]:
            # package init maps to package name = parent dir
            if len(rel.parent.parts) == 0:
                module_name = ""
            else:
                module_name = ".".join(rel.parent.parts)
        else:
            module_name = ".".join(parts)
        module_map[module_name] = py.resolve()

    # Also map package names themselves (without any submodule) to __init__.py
    # e.g. src.recon -> src/recon/__init__.py
    for name, path in list(module_map.items()):
        if name and not module_map.get(name):
            pass  # already there

    # Analyze every Python file
    for py in sorted(ROOT.rglob("*.py")):
        rel = py.relative_to(ROOT)
        try:
            src = py.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            issues.append((str(py), 0, f"Cannot read file: {e}"))
            continue

        try:
            tree = ast.parse(src, filename=str(py))
        except SyntaxError as e:
            issues.append((str(py), e.lineno or 0, f"SyntaxError: {e.msg}"))
            continue

        pkg_parts = list(rel.parent.parts)
        # Determine current module's dotted name (for resolving relative imports).
        # For __init__.py, current module is the package name.
        if rel.name == "__init__.py":
            cur_module_dotted = ".".join(pkg_parts) if pkg_parts else ""
        else:
            cur_module_dotted = ".".join(pkg_parts + [rel.stem])

        def visit_node(node):
            imports = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append((alias.name.split("."), node.lineno, "import"))
            elif isinstance(node, ast.ImportFrom):
                module_parts = node.module.split(".") if node.module else []
                for alias in node.names:
                    imports.append((module_parts + alias.name.split("."), node.lineno, "from"))
            return imports

        # Walk AST to get all imports with line numbers
        nodes = []
        for child in ast.walk(tree):
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                nodes.append(child)

        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    full = alias.name.split(".")
                    check_import(py, node.lineno, full, cur_module_dotted, module_map, "import")
            else:
                # ImportFrom
                mod_parts = node.module.split(".") if node.module else []
                level = node.level  # relative import level
                if level > 0:
                    # absolute module that the relative import resolves to
                    abs_parts = (
                        cur_module_dotted.split(".")[:-level]
                        if cur_module_dotted.split(".")
                        else []
                    )
                    abs_parts = abs_parts + ["__package__placeholder__"]
                    actual_module_parts = cur_module_dotted.split(".")[
                        : max(0, len(cur_module_dotted.split(".")) - level)
                    ]
                    module_prefix = ".".join(actual_module_parts) if actual_module_parts else ""
                    module_prefix_parts = actual_module_parts
                else:
                    module_prefix = node.module or ""
                    module_prefix_parts = mod_parts

                for alias in node.names:
                    full = list(module_prefix_parts) + alias.name.split(".")
                    check_import(
                        py,
                        node.lineno,
                        full,
                        cur_module_dotted,
                        module_map,
                        "from",
                        relative_level=level,
                        relative_module=module_prefix,
                    )

    print("\n=== Import Audit Report ===\n")
    if not issues:
        print("No obvious import issues detected.")
    else:
        for fp, lineno, msg in issues:
            print(f"{fp}:{lineno}: {msg}")


def check_import(
    py,
    lineno,
    full_parts,
    cur_module_dotted,
    module_map,
    kind,
    relative_level=0,
    relative_module="",
):
    if not full_parts or full_parts[0] == "":
        return

    top = full_parts[0]

    # Check for standard library / third-party (don't audit them here)
    stdlib_modules = {
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
        "codeop",
        "collections",
        "concurrent",
        "configparser",
        "contextvars",
        "ctypes",
        "curses",
        "dataclasses",
        "datetime",
        "email",
        "ensurepip",
        "errno",
        "faulthandler",
        "fcntl",
        "filecmp",
        "fileinput",
        "formatter",
        "graphlib",
        "grp",
        "gzip",
        "hashlib",
        "heapq",
        "imaplib",
        "imghdr",
        "imp",
        "importlib",
        "inspect",
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
        "platform",
        "plistlib",
        "posix",
        "posixpath",
        "pprint",
        "profile",
        "pstats",
        "pty",
        "pwd",
        "py_compile",
        "pyclbr",
        "pydoc",
        "queue",
        "quopri",
        "random",
        "readline",
        "reprlib",
        "resource",
        "rlcompleter",
        "runpy",
        "sched",
        "secrets",
        "select",
        "selectors",
        "shelve",
        "shlex",
        "signal",
        "site",
        "smtpd",
        "smtplib",
        "sndhdr",
        "socket",
        "socketserver",
        "spwd",
        "sqlite3",
        "sre_compile",
        "sre_constants",
        "sre_parse",
        "ssl",
        "stat",
        "statistics",
        "string",
        "stringprep",
        "struct",
        "subprocess",
        "sunau",
        "symbol",
        "symtable",
        "sys",
        "sysconfig",
        "tabnanny",
        "tarfile",
        "telnetlib",
        "tempfile",
        "termios",
        "test",
        "textwrap",
        "threading",
        "time",
        "timeit",
        "tkinter",
        "token",
        "tokenize",
        "tomllib",
        "trace",
        "traceback",
        "tracemalloc",
        "tty",
        "turtle",
        "turtledemo",
        "types",
        "typing",
        "unicodedata",
        "unittest",
        "urllib",
        "uu",
        "uuid",
        "venv",
        "warnings",
        "wave",
        "weakref",
        "webbrowser",
        "winreg",
        "winsound",
        "wsgiref",
        "xdrlib",
        "xml",
        "xmlrpc",
        "zipapp",
        "zipfile",
        "zlib",
        "_thread",
        "__future__",
        # Third-party commonly used (non-exhaustive)
        "requests",
        "httpx",
        "httptools",
        "starlette",
        "fastapi",
        "uvicorn",
        "flask",
        "django",
        "sqlalchemy",
        "pydantic",
        "numpy",
        "pandas",
        "scrapy",
        "selenium",
        "playwright",
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
        "pyjwt",
        "jwt",
        "croniter",
        "python_dateutil",
        "dateutil",
        "websockets",
        "aiohttp",
        "aiofiles",
        "pyyaml",
        "yaml",
        "toml",
        "configparser",
        "prometheus_client",
        "opentelemetry",
        "sentry_sdk",
        "loguru",
        "typing_extensions",
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
        "more_itertools",
        "stdnum",
        "phonenumbers",
        "email_validator",
        "pydantic_settings",
    }

    # Optimization: for big codebases, only check local "src." prefixed or relative imports.
    # But also catch obvious typos by checking existance for any non-stdlib top-level.
    # We'll check existence for anything that doesn't start with stdlib set.

    # Only analyze imports that are candidates for internal packages.
    # Start with src.* and anything that resolves under src/.
    # For robustness, check existence for all non-stdlib.

    # Quick check: treat dotted prefix as candidate if first segment maps to something under src
    # OR if relative (level > 0).
    check_existence = True

    if kind == "import" and top in stdlib_modules:
        check_existence = False

    if kind == "from":
        # If it's an absolute import (level == 0)
        if relative_level == 0:
            # Check first segment
            if top in stdlib_modules:
                # Could still be stdlib with submodule (e.g. collections.abc)
                pass
            else:
                check_existence = True
        else:
            # Relative import: must resolve to a file under src
            check_existence = True
    else:
        # plain import top-level
        if top in stdlib_modules:
            check_existence = False
        else:
            check_existence = True

    if not check_existence:
        return

    # Build absolute dotted name candidate
    if kind == "import":
        candidate = ".".join(full_parts)
    else:
        if relative_level == 0:
            candidate = ".".join(full_parts)
        else:
            candidate = ".".join(full_parts)

    # The candidate represents top-level equivalent under root, e.g.
    # from .config import X -> candidate could be "recon.config.X"
    # Actually, we only care about existence of the pointed-to file/folder.

    # Resolve candidate:
    # 1) direct lookup in module_map
    # 2) directory (package) -> __init__.py owned by parent? actually map stores __init__.py under parent dotted? Let's check.
    # module_map keys: package paths have key like "recon", module has "recon.pipeline"

    # Determine the base dotted path to check for a .py file.
    # If importing X.Y.Z, check module_map for X.Y.Z.
    # Also if X.Y is a package, and Z is submodule, it's okay as long as package exists.
    # For imports where full_parts contains more than module_map key,
    # we can truncate until we find a parent.

    def exists_under_src(dotted):
        if dotted in module_map:
            return module_map[dotted]
        # Try truncating
        parts = dotted.split(".")
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[:i])
            if parent in module_map:
                return module_map[parent]  # package exists
        return None

    target = exists_under_src(candidate)
    if target is None:
        # Maybe import is of form from . import x where x is a local file in same package.
        # candidate should handle that already.
        # Another case: __init__.py imports use same package; should match.
        if kind == "import" and len(full_parts) == 1:
            issues.append(
                (
                    str(py),
                    lineno,
                    "Import of unknown module/package '{}' (no matching src/ file or package)".format(
                        ".".join(full_parts)
                    ),
                )
            )
        else:
            issues.append(
                (
                    str(py),
                    lineno,
                    "Import of unknown module/package '{}' (no matching src/ file or package)".format(
                        ".".join(full_parts)
                    ),
                )
            )


if __name__ == "__main__":
    main()
