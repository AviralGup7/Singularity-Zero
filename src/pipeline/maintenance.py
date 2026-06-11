import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from src.core.logging.pipeline_logging import emit_info
from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.cache_backend import PersistentCache
from src.reporting import build_dashboard_index, list_run_dirs

logger = get_pipeline_logger(__name__)

RUN_DIR_NAME_RE = re.compile(r"^\d{8}-\d{6}$")


class RetentionPolicy:
    """Policy rules determining whether to keep, archive, or aggressively prune runs."""

    def __init__(
        self,
        *,
        keep_target_runs: int = 2,
        keep_launcher_runs: int = 5,
        min_significance_score: int = 5,
        breach_notification_retention_days: int = 365,
    ) -> None:
        self.keep_target_runs = keep_target_runs
        self.keep_launcher_runs = keep_launcher_runs
        self.min_significance_score = min_significance_score
        self.breach_notification_retention_days = breach_notification_retention_days

    def calculate_significance(self, run_summary: dict[str, Any]) -> int:
        """Compute significance score based on run contents."""
        # If it's a dry-run, score is 0
        if run_summary.get("dry_run") or run_summary.get("is_dry_run"):
            return 0

        score = 0
        counts = run_summary.get("counts", {})
        findings = run_summary.get("findings", [])

        # Process severity-based findings
        for finding in findings:
            if isinstance(finding, dict):
                sev = str(finding.get("severity", "")).lower()
                if sev == "critical":
                    score += 15
                elif sev == "high":
                    score += 10
                elif sev == "medium":
                    score += 5
                elif sev == "low":
                    score += 1
                elif sev == "info":
                    score += 0

        # Process simple finding counts if findings list is empty
        if score == 0 and isinstance(counts, dict):
            # Try parsing from counts
            score += int(counts.get("critical", 0)) * 15
            score += int(counts.get("high", 0)) * 10
            score += int(counts.get("medium", 0)) * 5
            score += int(counts.get("low", 0)) * 1
            score += int(counts.get("findings", 0)) * 2

        # Compliance elements boost significance
        if "compliance" in run_summary and run_summary["compliance"]:
            score += 10

        # Validated exploits boost significance significantly
        if (
            counts.get("validated_leads", 0) > 0
            or len(run_summary.get("verified_exploits", [])) > 0
        ):
            score += 50

        return score

    def should_keep_unconditionally(self, score: int) -> bool:
        """Keep high-significance runs unconditionally."""
        return score >= self.min_significance_score


def _get_run_age_days(run_dir: Path, run_summary: dict[str, Any]) -> int:
    """Calculate the age of a run in days."""
    gen_time_str = run_summary.get("generated_at_utc") or run_summary.get("generated_at_ist")
    if gen_time_str:
        try:
            # Simple ISO parsing or prefix slicing
            # "2026-06-06T05:09:53+05:30" or similar
            dt_str = str(gen_time_str).split(".")[0].split("+")[0].rstrip("Z")
            dt = datetime.datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=datetime.UTC
            )
            delta = datetime.datetime.now(datetime.UTC) - dt
            return max(0, delta.days)
        except (ValueError, TypeError) as exc:
            logger.debug("ISO date parse failed for run %s: %s", run_dir, exc)

    # Fallback to directory stamp name
    # Format: 20260329-010101 -> YYYYMMDD
    dir_name = run_dir.name
    if len(dir_name) >= 8 and dir_name[:8].isdigit():
        try:
            dt = datetime.datetime.strptime(dir_name[:8], "%Y%m%d").replace(tzinfo=datetime.UTC)
            delta = datetime.datetime.now(datetime.UTC) - dt
            return max(0, delta.days)
        except (ValueError, TypeError) as exc:
            logger.debug("YYYYMMDD directory stamp parse failed for %s: %s", dir_name, exc)

    # Fallback to filesystem mtime
    try:
        mtime = run_dir.stat().st_mtime
        delta = datetime.datetime.now(datetime.UTC) - datetime.datetime.fromtimestamp(
            mtime, tz=datetime.UTC
        )
        return max(0, delta.days)
    except (OSError, ValueError) as exc:
        logger.warning("Failed to determine run age for %s: %s", run_dir, exc)
        return 0


def _prune_launcher_dirs(launcher_root: Path, keep_launcher_runs: int) -> list[tuple[float, str, Path]]:
    if not launcher_root.exists():
        return []
    job_dirs: list[tuple[float, str, Path]] = []
    for path in launcher_root.iterdir():
        if path.is_dir():
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            job_dirs.append((mtime, path.name, path))
    job_dirs.sort(key=lambda x: (x[0], x[1]))
    if keep_launcher_runs <= 0:
        stale_dirs = list(job_dirs)
    elif len(job_dirs) > keep_launcher_runs:
        stale_dirs = job_dirs[: len(job_dirs) - keep_launcher_runs]
    else:
        stale_dirs = []
    for item in stale_dirs:
        _remove_tree(item[2])
    return stale_dirs


def _list_generated_run_dirs(target_root: Path) -> list[Path]:
    if not target_root.exists():
        return []
    return sorted(
        path
        for path in target_root.iterdir()
        if path.is_dir() and RUN_DIR_NAME_RE.fullmatch(path.name)
    )


def _remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError as exc:
        logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001


def run_cache_maintenance(cache: PersistentCache | None = None) -> dict[str, Any]:
    """Run cache cleanup and return stats.

    Args:
        cache: Cache instance. If None, creates a default one.

    Returns:
        Dict with cleaned_entries, stats, and status.
    """
    if cache is None:
        cache = PersistentCache()

    stats_before = cache.get_cache_stats()
    cleaned = cache.cleanup_expired()
    stats_after = cache.get_cache_stats()

    result: dict[str, Any] = {
        "status": "ok",
        "cleaned_entries": cleaned,
        "stats_before": stats_before,
        "stats_after": stats_after,
    }
    logger.info(
        "Cache maintenance: cleaned %d expired entries, %d active remaining",
        cleaned,
        stats_after.get("active_entries", 0),
    )
    return result


class MaintenanceLock:
    """SQLite advisory lock to prevent concurrent maintenance execution.

    Safer than PID file locks in container/K8s environments where
    PIDs can be recycled quickly.  Falls back to PID-file semantics
    if SQLite is unavailable.
    """

    def __init__(self, lockfile_path: Path) -> None:
        self.lockfile_path = lockfile_path
        self._sqlite_path = lockfile_path.with_suffix(".sqlite-lock")
        self._fd: int | None = None
        self._use_sqlite: bool = True

    def __enter__(self) -> "MaintenanceLock":
        self.lockfile_path.parent.mkdir(parents=True, exist_ok=True)
        if self._use_sqlite:
            conn = None
            try:
                import sqlite3

                conn = sqlite3.connect(str(self._sqlite_path), timeout=1)
                cur = conn.execute("BEGIN EXCLUSIVE")
                cur.fetchone()
                self._conn = conn
                self.lockfile_path.write_text("sqlite-lock\n", encoding="utf-8")
                return self
            except Exception as exc:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception as exc:
                        logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
                import sqlite3

                if isinstance(exc, sqlite3.OperationalError) and any(
                    k in str(exc).lower() for k in ("lock", "busy")
                ):
                    raise RuntimeError("Maintenance task already running.") from exc
                if self.lockfile_path.exists():
                    try:
                        content = self.lockfile_path.read_text().strip()
                        if content == "sqlite-lock":
                            raise RuntimeError("Maintenance task already running.") from exc
                    except Exception as exc:
                        logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
                self._use_sqlite = False
        return self._acquire_pid_lock()

    def _acquire_pid_lock(self) -> "MaintenanceLock":
        try:
            self._fd = os.open(self.lockfile_path, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
            os.write(self._fd, f"{os.getpid()}\n".encode())
        except OSError:
            if self.lockfile_path.exists():
                try:
                    pid = int(self.lockfile_path.read_text().strip())
                    if self._is_pid_running(pid):
                        raise RuntimeError(f"Maintenance task already running with PID {pid}")
                except Exception as exc:
                    logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
            try:
                if self.lockfile_path.exists():
                    self.lockfile_path.unlink()
                self._fd = os.open(self.lockfile_path, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
                os.write(self._fd, f"{os.getpid()}\n".encode())
            except OSError as exc:
                raise RuntimeError("Failed to acquire maintenance lockfile.") from exc
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if hasattr(self, "_conn") and self._conn is not None:
            try:
                self._conn.rollback()
                self._conn.close()
            except Exception as exc:
                logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
            self._conn = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError as exc:
                logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
            self._fd = None
        if self.lockfile_path.exists():
            try:
                self.lockfile_path.unlink()
            except OSError as exc:
                logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
        if hasattr(self, "_sqlite_path") and self._sqlite_path.exists():
            try:
                self._sqlite_path.unlink()
            except OSError as exc:
                logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001

    @staticmethod
    def _is_pid_running(pid: int) -> bool:
        if pid <= 0:
            return False
        if sys.platform == "win32":
            import ctypes

            PROCESS_QUERY_INFORMATION = 0x0400
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return exit_code.value == STILL_ACTIVE
        else:
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                return False


def prune_output_history(
    output_root: Path,
    *,
    keep_target_runs: int = 2,
    keep_launcher_runs: int = 5,
    min_significance_score: int = 5,
    breach_notification_retention_days: int = 365,
    cache: PersistentCache | None = None,
) -> dict[str, Any]:
    if keep_target_runs < 1:
        raise ValueError("keep_target_runs must be at least 1.")
    if keep_launcher_runs < 0:
        raise ValueError("keep_launcher_runs must be at least 0.")

    policy = RetentionPolicy(
        keep_target_runs=keep_target_runs,
        keep_launcher_runs=keep_launcher_runs,
        min_significance_score=min_significance_score,
        breach_notification_retention_days=breach_notification_retention_days,
    )

    root = output_root.resolve()
    summary: dict[str, Any] = {
        "output_root": str(root),
        "keep_target_runs": keep_target_runs,
        "keep_launcher_runs": keep_launcher_runs,
        "removed_target_run_dirs": [],
        "removed_launcher_dirs": [],
        "updated_target_indexes": [],
        "tiered_warm_runs": [],
        "tiered_cold_runs": [],
        "invalidated_cache_keys_count": 0,
    }
    if not root.exists():
        return summary

    if cache is None:
        cache = PersistentCache()

    for entry in sorted(
        (path for path in root.iterdir() if path.is_dir()), key=lambda path: path.name.lower()
    ):
        if entry.name == "_launcher":
            removed = _prune_launcher_dirs(entry, keep_launcher_runs)
            summary["removed_launcher_dirs"].extend(str(path) for path in removed)
            continue
        if entry.name.startswith("_"):
            continue

        run_dirs = _list_generated_run_dirs(entry)
        if not run_dirs:
            continue

        target_name = entry.name

        # 1. Parse significance & classify runs
        run_summaries = {}
        for run_dir in run_dirs:
            summary_file = run_dir / "run_summary.json"
            run_data = {}
            if summary_file.exists():
                try:
                    run_data = json.loads(summary_file.read_text(encoding="utf-8"))
                except Exception as exc:
                    logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
            run_summaries[run_dir] = run_data

        # Sort run directories by age/name (oldest first)
        sorted_runs = sorted(run_dirs, key=lambda rd: rd.name)

        # Runs to evaluate for pruning (we preserve keep_target_runs newest runs regardless of score)
        candidate_runs = (
            sorted_runs[:-keep_target_runs] if len(sorted_runs) > keep_target_runs else []
        )

        runs_to_remove = []
        for run_dir in candidate_runs:
            run_data = run_summaries.get(run_dir, {})
            score = policy.calculate_significance(run_data)
            age_days = _get_run_age_days(run_dir, run_data)

            # Drop dry-run immediately or if below score threshold
            if not policy.should_keep_unconditionally(score):
                runs_to_remove.append(run_dir)
            elif age_days > policy.breach_notification_retention_days:
                # Exceeded breach notification period
                runs_to_remove.append(run_dir)

        # 2. Storage Tiering on Remaining Runs (which are not to be pruned)
        remaining_runs = [r for r in sorted_runs if r not in runs_to_remove]
        for run_dir in remaining_runs:
            run_data = run_summaries.get(run_dir, {})
            age_days = _get_run_age_days(run_dir, run_data)

            if age_days > 90:
                # Cold Tier: Archive to zip file, remove local dir
                archive_dir = root / "_archive"
                archive_dir.mkdir(parents=True, exist_ok=True)
                zip_path = archive_dir / f"{target_name}_{run_dir.name}.zip"
                try:
                    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                        for root_dir, _, files in os.walk(run_dir):
                            for file in files:
                                file_path = Path(root_dir) / file
                                zipf.write(file_path, file_path.relative_to(run_dir))
                    # Remove local run dir
                    _remove_tree(run_dir)
                    summary["tiered_cold_runs"].append(str(run_dir))
                except Exception as e:
                    logger.error("Failed to cold-tier archive run %s: %s", run_dir, e)

            elif age_days > 7:
                # Warm Tier: Strip large blobs (screenshots)
                screenshots_file = run_dir / "screenshots.json"
                if screenshots_file.exists():
                    try:
                        screenshots_file.unlink()
                        summary["tiered_warm_runs"].append(str(run_dir))
                    except OSError as exc:
                        logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001
                # If there are actual screenshot images/files, strip them
                for ext in ("*.png", "*.jpg", "*.jpeg", "*.webp"):
                    for img_file in run_dir.glob(ext):
                        try:
                            img_file.unlink()
                        except OSError as exc:
                            logger.warning(
                                "Operation failed in maintenance.py: %s", exc, exc_info=True
                            )  # noqa: BLE001

        # 3. Perform actual pruning / removal
        for run_dir in runs_to_remove:
            _remove_tree(run_dir)
            summary["removed_target_run_dirs"].append(str(run_dir))

            # Auto-invalidate all cache keys prefixed with that target's run id or job id
            prefix = f"{target_name}:{run_dir.name}"
            try:
                deleted_count = cache.prune_prefix(prefix)
                # Also prune general historical scores if this was a significant target key
                deleted_count += cache.prune_prefix(f"historical_scores:{prefix}")
                deleted_count += cache.prune_prefix(f"historical_scores:{target_name}")
                summary["invalidated_cache_keys_count"] += deleted_count
            except Exception as e:
                logger.debug("Failed to prune cache keys for prefix %s: %s", prefix, e)

        # 4. Rebuild Index
        remaining_runs_after_pruning = list_run_dirs(entry)
        if remaining_runs_after_pruning:
            build_dashboard_index(entry)
            summary["updated_target_indexes"].append(str(entry / "index.html"))
        else:
            index_file = entry / "index.html"
            if index_file.exists():
                try:
                    index_file.unlink()
                except OSError as exc:
                    logger.warning("Operation failed in maintenance.py: %s", exc, exc_info=True)  # noqa: BLE001

    return summary


def register_scheduler_task(
    task_name: str = "PipelineMaintenance", output_root: str = "output"
) -> bool:
    """Register daily maintenance task with the OS scheduler."""
    script_path = Path(__file__).resolve()
    python_exe = sys.executable

    if sys.platform == "win32":
        # Windows Task Scheduler registration via schtasks CLI
        tr_value = f"{python_exe} {script_path} --output-root {output_root}"
        try:
            ret = subprocess.run(  # noqa: S603
                [  # noqa: S607
                    "schtasks",
                    "/create",
                    "/tn",
                    task_name,
                    "/tr",
                    tr_value,
                    "/sc",
                    "daily",
                    "/st",
                    "02:00",
                    "/f",
                ],
                capture_output=True,
                timeout=30,
            )
            return ret.returncode == 0
        except Exception as e:
            logger.error("Failed to register Windows Task Scheduler job: %s", e)
            return False
    else:
        # Unix cron registration
        cron_job = (
            f"0 2 * * * {python_exe} {script_path} --output-root {output_root} > /dev/null 2>&1\n"
        )
        try:
            # Simple cron integration using crontab cli
            temp_cron = tempfile.NamedTemporaryFile(delete=False)
            temp_cron.write(cron_job.encode("utf-8"))
            temp_cron.close()
            try:
                ret = subprocess.run(  # noqa: S603
                    ["crontab", temp_cron.name],  # noqa: S607
                    capture_output=True,
                    timeout=30,
                )
                return ret.returncode == 0
            finally:
                os.unlink(temp_cron.name)
        except Exception as e:
            logger.error("Failed to register cron job: %s", e)
            return False


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prune stale generated output history.")
    parser.add_argument("--output-root", default="output", help="Path to the output directory.")
    parser.add_argument(
        "--keep-target-runs",
        type=int,
        default=2,
        help="How many recent target runs to keep per target.",
    )
    parser.add_argument(
        "--keep-launcher-runs",
        type=int,
        default=5,
        help="How many recent launcher job directories to keep.",
    )
    parser.add_argument(
        "--min-significance-score",
        type=int,
        default=5,
        help="Runs scoring below this will be pruned (except latest keep_target_runs).",
    )
    parser.add_argument(
        "--breach-notification-retention",
        type=int,
        default=365,
        help="Max retention in days for significant breach notification runs.",
    )
    parser.add_argument(
        "--schedule",
        action="store_true",
        help="Register the daily maintenance script with the OS scheduler (Task Scheduler or Cron).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.schedule:
        success = register_scheduler_task(output_root=args.output_root)
        if success:
            emit_info("Successfully registered daily maintenance with OS scheduler.")
            return 0
        else:
            emit_info("Failed to register maintenance task with OS scheduler.")
            return 1

    lock_file = Path(args.output_root) / "maintenance.lock"
    try:
        with MaintenanceLock(lock_file):
            cache = PersistentCache()
            summary = prune_output_history(
                Path(args.output_root),
                keep_target_runs=args.keep_target_runs,
                keep_launcher_runs=args.keep_launcher_runs,
                min_significance_score=args.min_significance_score,
                breach_notification_retention_days=args.breach_notification_retention,
                cache=cache,
            )
            # Run general cache maintenance as well
            run_cache_maintenance(cache)
            emit_info(str(summary))
    except RuntimeError as e:
        logger.error("Maintenance task aborted: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
