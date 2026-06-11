import ast
import importlib.util
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT = Path("src").resolve()
REPO_ROOT = ROOT.parent.resolve()
issues = []

KNOWN_TOP = {
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
}

# Only process files whose imports start with 'src.'.
CANDIDATE_FILES = []
for py in sorted(ROOT.rglob("*.py")):
    try:
        txt = py.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.debug("Failed to read %s: %s", py, e)
        continue
    if any((ln.startswith("from src.") or ln.startswith("import src.")) for ln in txt.splitlines()):
        CANDIDATE_FILES.append(py)

print(f"Candidate files with top-level src imports: {len(CANDIDATE_FILES)}", flush=True)


def file_module(py):
    rel = py.relative_to(ROOT)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        return ".".join(parts[:-1])
    return ".".join(parts[:-1] + [parts[-1][:-3]])


def spec_exists(mod):
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


def abs_module_for_from(module, level, cur_module):
    """Resolve absolute module name to check via find_spec (no attribute names)."""
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
                    if not spec_exists(alias.name):
                        issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Import of unknown module/package '{alias.name}' (__init__ py missing?)",
                            )
                        )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            # skip third-party / stdlib
            if node.level == 0 and module.split(".")[0] in KNOWN_TOP:
                continue
            if not (module.startswith("src.") or node.level > 0):
                continue
            # For rel_level>0 and module started by stdlib already filtered above.
            # Determine the target module (without attribute name).
            target_mod = abs_module_for_from(module, node.level, cur_module)
            if node.level == 0 and not target_mod:
                # from . import X where module is None handled below
                pass
            if node.level == 0 and target_mod and target_mod in KNOWN_TOP:
                continue
            for alias in node.names:
                if alias.name == "*":
                    if not target_mod:
                        issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Star import from unresolved source '{module or '(relative)'}'",
                            )
                        )
                    elif not spec_exists(target_mod):
                        issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Star import from unresolved source '{module or '(relative)'}'",
                            )
                        )
                else:
                    full_name = ((module + ".") if module else "") + alias.name
                    # check existence of top-level module prefix first
                    if node.level == 0 and module and module.split(".")[0] in KNOWN_TOP:
                        continue
                    if node.level > 0 and not module:
                        # from . import X -> target_mod already contains X if module empty?
                        # In that case, target_mod would be broken from above. Skip.
                        if not target_mod:
                            issues.append(
                                (
                                    str(py.resolve()),
                                    node.lineno,
                                    f"Import of unresolved relative '{alias.name}'",
                                )
                            )
                            continue
                    if not spec_exists(target_mod or full_name):
                        issues.append(
                            (
                                str(py.resolve()),
                                node.lineno,
                                f"Import of unknown module/package '{full_name}'",
                            )
                        )

print("\n=== Import issues for src.* and relative imports ===\n")
seen = set()
uniq = []
for item in issues:
    if item not in seen:
        seen.add(item)
        uniq.append(item)
for fp, lineno, msg in uniq:
    print(f"{fp}:{lineno}: {msg}")
print(f"\n[Count] {len(uniq)} issue(s).\n")
