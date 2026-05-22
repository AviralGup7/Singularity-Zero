import os
import shutil
import tempfile
import threading
from unittest.mock import MagicMock

from src.core.frontier.ghost_vfs import GhostVFS
from src.decision.priority_queue import CorrelationPriorityQueue, ScanTarget
from src.infrastructure.queue.models import ResourceProfile, WorkerInfo
from src.infrastructure.scheduling.resource_aware import ResourceAwareScheduler
from src.learning.signal_quality import score_signal_quality
from src.learning.threshold_tuner import ThresholdConfig, ThresholdTuner


def test_scheduler_thread_safety():
    """Verify ResourceAwareScheduler is thread-safe under concurrent worker updates."""
    scheduler = ResourceAwareScheduler()
    num_threads = 10
    updates_per_thread = 100

    def worker_updater(thread_id: int):
        for i in range(updates_per_thread):
            worker_id = f"worker_{thread_id}_{i}"
            info = WorkerInfo(
                id=worker_id,
                status="online",
                active_jobs=[],
                resources=ResourceProfile(available_ram_mb=2048),
            )
            scheduler.update_worker(worker_id, info)
            # Retrieve load (should be protected by RLock)
            scheduler.get_worker_load(worker_id)
            scheduler.get_all_workers_summary()

    threads = []
    for t in range(num_threads):
        thread = threading.Thread(target=worker_updater, args=(t,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Total registered workers should be the product of threads and updates per thread
    assert len(scheduler.workers) == num_threads * updates_per_thread


def test_ghost_vfs_atomic_flush():
    """Verify that GhostVFS.flush_to_disk writes files atomically."""
    vfs = GhostVFS()
    vfs.write_file("nested/file.txt", "confidential information")

    export_dir = tempfile.mkdtemp()
    master_key = "secure-master-password"
    expected_file = os.path.join(export_dir, "nested", "file.txt")

    try:
        # 1. Normal atomic flush
        vfs.flush_to_disk(export_dir, master_key)
        assert os.path.exists(expected_file)

        # 2. Mock path write error to simulate sudden failure during write
        # We will create a directory in place of the file to trigger write failure
        os.remove(expected_file)
        os.makedirs(expected_file)  # directory at target path prevents writing as file

        # Should handle gracefully, and temp file should be cleaned up
        vfs.flush_to_disk(export_dir, master_key)

        # The directory should remain (as our failure mode) and no junk temp files left in it
        files_in_nested = os.listdir(os.path.join(export_dir, "nested"))
        # Only the directory exists, no temporary .vfs_tmp_ files
        for f in files_in_nested:
            assert not f.startswith(".vfs_tmp_")

    finally:
        shutil.rmtree(export_dir)


def test_priority_queue_adjudication_boost_cap():
    """Verify that CorrelationPriorityQueue prevents infinite priority inflation past cap."""
    targets = [
        ScanTarget(url="http://example.com/api/user", base_priority=10.0, current_priority=10.0),
        ScanTarget(url="http://example.com/api/admin", base_priority=20.0, current_priority=20.0),
    ]

    pq = CorrelationPriorityQueue(targets, boost_factor=2.0)

    # Base priority 10.0: cap should be max(5.0 * 10.0, 50.0) = 50.0
    # Base priority 20.0: cap should be max(5.0 * 20.0, 50.0) = 100.0

    # Apply multiple massive boosts to user endpoint
    for _ in range(5):
        pq.boost_url("http://example.com/api/user", factor=3.0, reason="cascade")

    # Apply multiple massive boosts to admin endpoint
    for _ in range(5):
        pq.boost_url("http://example.com/api/admin", factor=3.0, reason="cascade")

    user_target = pq._url_map["http://example.com/api/user"]
    admin_target = pq._url_map["http://example.com/api/admin"]

    # Verify they converged exactly to their respective caps
    assert user_target.current_priority == 50.0
    assert admin_target.current_priority == 100.0


def test_threshold_tuner_active_learning():
    """Verify ThresholdTuner active learning SGD loop and custom weights in signal quality scoring."""
    store_mock = MagicMock()
    config = ThresholdConfig(learning_rate=0.05)
    tuner = ThresholdTuner(store_mock, config)

    # Initial weights
    initial_weights = dict(tuner.weights)

    # Simulate labeled findings feedback
    labeled_findings = [
        {
            "confidence": 0.9,
            "true_positive_probability": 0.95,
            "false_positive_probability": 0.05,
            "response_status": 200,
            "feedback": "tp",  # should push weights higher for confidence & model_tp
            "evidence": {
                "confirmed": True,
                "reproducible": True,
            },
        },
        {
            "confidence": 0.2,
            "true_positive_probability": 0.1,
            "false_positive_probability": 0.9,
            "response_status": 429,
            "feedback": "fp",  # should push weights lower
            "evidence": {
                "body_snippet": "rate limit",
            },
        },
    ]

    # Perform active learning weight updates
    updated_weights = tuner.active_learning_weight_update(labeled_findings)

    # Verify weights changed
    assert updated_weights != initial_weights
    assert updated_weights["confidence"] != initial_weights["confidence"]

    # Verify score_signal_quality uses the customized weights and yields a different true positive probability
    finding = {
        "confidence": 0.8,
        "true_positive_probability": 0.85,
        "false_positive_probability": 0.15,
        "evidence": {},
    }

    result_default = score_signal_quality(finding)
    result_custom = score_signal_quality(finding, weights=updated_weights)

    assert result_custom.true_positive_probability != result_default.true_positive_probability
