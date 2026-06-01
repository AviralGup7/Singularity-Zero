"""Automated binary downloader for ProjectDiscovery security tools.

Auto-detects the host operating system and CPU architecture, downloads precompiled
releases of nuclei, httpx, and subfinder, and extracts them into the local
 VFS path (.tools/bin) with proper execution permissions.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Pinned stable versions of the required tools
STABLE_VERSIONS = {
    "nuclei": "3.3.5",
    "httpx": "1.6.8",
    "subfinder": "2.6.7",
}


def detect_os_arch() -> tuple[str, str]:
    """Detect operating system and CPU architecture.

    Returns:
        Tuple of (os_name, arch_name) compatible with ProjectDiscovery release assets.
    """
    sys_plat = sys.platform.lower()
    if sys_plat.startswith("win"):
        os_name = "windows"
    elif sys_plat.startswith("darwin"):
        os_name = "macOS"
    elif sys_plat.startswith("linux"):
        os_name = "linux"
    else:
        logger.warning("Unsupported OS detected: %s. Defaulting to linux.", sys_plat)
        os_name = "linux"

    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        arch_name = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch_name = "arm64"
    elif machine in ("386", "i386", "i686"):
        arch_name = "386"
    else:
        logger.warning("Unsupported CPU architecture: %s. Defaulting to amd64.", machine)
        arch_name = "amd64"

    return os_name, arch_name


def get_download_url(tool_name: str, version: str, os_name: str, arch_name: str) -> str:
    """Construct the ProjectDiscovery GitHub release download URL.

    Args:
        tool_name: Name of the tool (nuclei, httpx, subfinder).
        version: Version string (e.g. 3.3.5).
        os_name: Operating system name (windows, macOS, linux).
        arch_name: CPU architecture (amd64, arm64, 386).

    Returns:
        The direct download URL.
    """
    ext = "zip"
    # Modern ProjectDiscovery releases use .zip across all three operating systems
    # but we can fallback if needed.
    return f"https://github.com/projectdiscovery/{tool_name}/releases/download/v{version}/{tool_name}_{version}_{os_name}_{arch_name}.{ext}"


def download_and_extract_tool(
    tool_name: str,
    version: str,
    dest_dir: Path,
    os_name: str | None = None,
    arch_name: str | None = None,
    console_print: bool = False,
) -> Path | None:
    """Download and extract a specific security tool binary.

    Args:
        tool_name: Name of the tool (nuclei, httpx, subfinder).
        version: Version string.
        dest_dir: Destination directory to install the binary to.
        os_name: Optional custom OS override.
        arch_name: Optional custom architecture override.
        console_print: Whether to write user-friendly messages to stdout.

    Returns:
        The Path to the installed binary, or None on failure.
    """
    if os_name is None or arch_name is None:
        detected_os, detected_arch = detect_os_arch()
        os_name = os_name or detected_os
        arch_name = arch_name or detected_arch

    url = get_download_url(tool_name, version, os_name, arch_name)
    bin_name = f"{tool_name}.exe" if os_name == "windows" else tool_name
    dest_path = dest_dir / bin_name

    message = f"Installing {tool_name} v{version} ({os_name}/{arch_name})..."
    logger.info(message)
    if console_print:
        print(f"\n[*] {message}")

    dest_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Request with a standard User-Agent header
        req = urllib.request.Request(  # nosec B310 noqa: S310
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_archive_path = Path(tmpdir) / "archive.zip"

            if console_print:
                print("  └─ Downloading from GitHub...")

            with (
                urllib.request.urlopen(req, timeout=60) as response,  # nosec B310 noqa: S310
                open(tmp_archive_path, "wb") as out_file,
            ):
                shutil.copyfileobj(response, out_file)

            if console_print:
                print("  └─ Unpacking archive and resolving binary...")

            # Extract archive
            # Most modern ProjectDiscovery releases are in ZIP format, but let's be robust
            if zipfile.is_zipfile(tmp_archive_path):
                with zipfile.ZipFile(tmp_archive_path) as z:
                    for name in z.namelist():
                        # Binary could be at root or inside subfolders
                        if Path(name).name == bin_name:
                            with z.open(name) as source, open(dest_path, "wb") as target:
                                shutil.copyfileobj(source, target)
                            break
            else:
                # Fallback to TarFile if ever required
                try:
                    with tarfile.open(tmp_archive_path, "r:gz") as t:
                        for member in t.getmembers():
                            if Path(member.name).name == bin_name:
                                extracted_file = t.extractfile(member)
                                if extracted_file:
                                    with open(dest_path, "wb") as target:
                                        shutil.copyfileobj(extracted_file, target)
                                    break
                except Exception as exc:
                    raise ValueError(
                        "Downloaded archive is not a valid zip or tar.gz file."
                    ) from exc

            if not dest_path.exists():
                raise FileNotFoundError(
                    f"Binary '{bin_name}' was not found in the downloaded archive."
                )

            # Set executable permissions on Unix systems
            if os_name != "windows":
                os.chmod(dest_path, 0o755)  # nosec B103 noqa: S103

            success_msg = f"Successfully installed {tool_name} to {dest_path}"
            logger.info(success_msg)
            if console_print:
                print(f"  └─ [✓] {success_msg}")

            return dest_path

    except Exception as exc:
        err_msg = f"Failed to download or install {tool_name}: {exc}"
        logger.error(err_msg)
        if console_print:
            print(f"  └─ [✗] Error: {exc}")
        return None


def setup_all_tools(
    dest_dir: Path | None = None, console_print: bool = False
) -> dict[str, Path | None]:
    """Auto-detect host and install all required ProjectDiscovery tools.

    Args:
        dest_dir: Optional destination directory override. Defaults to workspace .tools/bin.
        console_print: Whether to print progress to console.

    Returns:
        Dict mapping tool name to installed binary Path or None.
    """
    if dest_dir is None:
        # Default destination path matches tool_execution.py search paths: workspace_root / ".tools" / "bin"
        workspace_root = Path(__file__).resolve().parents[3]
        dest_dir = workspace_root / ".tools" / "bin"

    os_name, arch_name = detect_os_arch()
    results = {}

    for tool_name, version in STABLE_VERSIONS.items():
        bin_path = download_and_extract_tool(
            tool_name=tool_name,
            version=version,
            dest_dir=dest_dir,
            os_name=os_name,
            arch_name=arch_name,
            console_print=console_print,
        )
        results[tool_name] = bin_path

    return results
