"""Queue system throughput benchmarks.

Measures enqueue, claim, complete, and end-to-end throughput of the
distributed job queue (queue_system package).
"""

import asyncio
import time

import pytest

from src.core.contracts.task_envelope import TaskEnvelope


class TestQueueEnqueue:
    """Benchmark job enqueue operations."""

    def test_enqueue_single_latency(self, job_queue, benchmark):
        """Measure time to enqueue a single job."""

        async def _enqueue():
            return await job_queue.enqueue(
                TaskEnvelope(type="benchmark", payload={"data": "test"}),
                priority=5,
            )

        result = benchmark(lambda: asyncio.run(_enqueue()))
        assert result is not None

    def test_enqueue_with_metadata(self, job_queue, benchmark):
        """Measure enqueue time with full metadata."""

        async def _enqueue():
            return await job_queue.enqueue(
                TaskEnvelope(
                    type="scan",
                    payload={"target": "example.com", "urls": 100},
                    metadata={"source": "benchmark", "version": "1.0"},
                ),
                priority=8,
                max_retries=5,
            )

        result = benchmark(lambda: asyncio.run(_enqueue()))
        assert result is not None

    def test_enqueue_batch_100(self, job_queue, benchmark):
        """Measure time to enqueue 100 jobs."""
        NUM_JOBS = 100

        async def _enqueue_batch():
            ids = []
            for i in range(NUM_JOBS):
                job_id = await job_queue.enqueue(
                    TaskEnvelope(type="benchmark", payload={"index": i}),
                    priority=i % 10 + 1,
                )
                ids.append(job_id)
            return ids

        start = time.perf_counter()
        result = benchmark(lambda: asyncio.run(_enqueue_batch()))
        elapsed = time.perf_counter() - start

        assert len(result) == NUM_JOBS
        jobs_per_sec = NUM_JOBS / elapsed
        print(f"\nEnqueue rate: {jobs_per_sec:.0f} jobs/sec")

    def test_enqueue_batch_1000(self, job_queue, benchmark):
        """Measure time to enqueue 1000 jobs (throughput test)."""
        NUM_JOBS = 1000

        async def _enqueue_batch():
            ids = []
            for i in range(NUM_JOBS):
                job_id = await job_queue.enqueue(
                    TaskEnvelope(type="benchmark", payload={"index": i}),
                    priority=i % 10 + 1,
                )
                ids.append(job_id)
            return ids

        start = time.perf_counter()
        result = benchmark(lambda: asyncio.run(_enqueue_batch()))
        elapsed = time.perf_counter() - start

        assert len(result) == NUM_JOBS
        jobs_per_sec = NUM_JOBS / elapsed
        print(f"\nEnqueue throughput: {jobs_per_sec:.0f} jobs/sec")
        assert jobs_per_sec > 100  # SLA: > 100 jobs/sec

    @pytest.mark.parametrize("priority", [1, 5, 10])
    def test_enqueue_priority_impact(self, job_queue, benchmark, priority):
        """Measure if priority affects enqueue time."""

        async def _enqueue():
            return await job_queue.enqueue(
                TaskEnvelope(type="benchmark", payload={"priority_test": True}),
                priority=priority,
            )

        result = benchmark(lambda: asyncio.run(_enqueue()))
        assert result is not None


class TestQueueClaim:
    """Benchmark job claim operations."""

    def test_claim_empty_queue(self, job_queue, benchmark):
        """Measure claim time on empty queue."""

        async def _claim():
            return await job_queue.claim_job("benchmark_worker")

        result = benchmark(lambda: asyncio.run(_claim()))
        assert result is None

    def test_claim_single(self, job_queue, benchmark):
        """Measure claim time with jobs available."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:

            async def _claim():
                await job_queue.enqueue(TaskEnvelope(type="benchmark", payload={"data": "test"}))
                return await job_queue.claim_job("benchmark_worker")

            result = benchmark(lambda: loop.run_until_complete(_claim()))
        finally:
            asyncio.set_event_loop(None)
            loop.close()

        assert result is not None

    def test_claim_batch_50(self, job_queue, benchmark):
        """Measure claim throughput for 50 jobs."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:

            async def _claim_batch():
                for i in range(50):
                    await job_queue.enqueue(TaskEnvelope(type="benchmark", payload={"index": i}))

                claimed = []
                for _ in range(50):
                    job = await job_queue.claim_job("benchmark_worker")
                    if job:
                        claimed.append(job)
                return claimed

            start = time.perf_counter()
            result = benchmark(lambda: loop.run_until_complete(_claim_batch()))
        finally:
            asyncio.set_event_loop(None)
            loop.close()

        elapsed = time.perf_counter() - start

        claims_per_sec = len(result) / elapsed if elapsed > 0 else 0
        print(f"\nClaim rate: {claims_per_sec:.0f} jobs/sec")
        assert len(result) > 0


class TestQueueComplete:
    """Benchmark job completion operations."""

    def test_complete_single(self, job_queue, benchmark):
        """Measure time to complete a single job."""
        job_id = asyncio.run(
            job_queue.enqueue(TaskEnvelope(type="benchmark", payload={"data": "test"}))
        )
        asyncio.run(job_queue.claim_job("worker_1"))

        async def _complete():
            return await job_queue.complete_job(job_id, "worker_1", {"result": "success"})

        result = benchmark(lambda: asyncio.run(_complete()))
        assert result is True

    def test_complete_batch_50(self, job_queue, benchmark):
        """Measure completion throughput."""
        job_ids = []
        for i in range(50):
            job_id = asyncio.run(
                job_queue.enqueue(TaskEnvelope(type="benchmark", payload={"index": i}))
            )
            asyncio.run(job_queue.claim_job("worker_1"))
            job_ids.append(job_id)

        async def _complete_batch():
            completed = 0
            for job_id in job_ids:
                success = await job_queue.complete_job(job_id, "worker_1", {"result": "ok"})
                if success:
                    completed += 1
            return completed

        start = time.perf_counter()
        result = benchmark(lambda: asyncio.run(_complete_batch()))
        elapsed = time.perf_counter() - start

        completes_per_sec = result / elapsed if elapsed > 0 else 0
        print(f"\nComplete rate: {completes_per_sec:.0f} jobs/sec")
        assert result > 0


class TestQueueEndToEnd:
    """Benchmark full job lifecycle throughput."""

    def test_lifecycle_10_jobs(self, job_queue, benchmark):
        """Measure full lifecycle for 10 jobs."""
        NUM_JOBS = 10

        async def _lifecycle():
            job_ids = []
            for i in range(NUM_JOBS):
                job_id = await job_queue.enqueue(
                    TaskEnvelope(type="benchmark", payload={"index": i})
                )
                job_ids.append(job_id)

            completed = 0
            for job_id in job_ids:
                job = await job_queue.claim_job("lifecycle_worker")
                if job:
                    success = await job_queue.complete_job(job_id, "lifecycle_worker")
                    if success:
                        completed += 1
            return completed

        start = time.perf_counter()
        result = benchmark(lambda: asyncio.run(_lifecycle()))
        elapsed = time.perf_counter() - start

        jobs_per_min = (result / elapsed) * 60
        print(f"\nEnd-to-end throughput: {jobs_per_min:.0f} jobs/min")
        assert jobs_per_min > 100  # SLA: > 100 jobs/min

    def test_lifecycle_100_jobs(self, job_queue, benchmark):
        """Measure full lifecycle for 100 jobs."""
        NUM_JOBS = 100

        async def _lifecycle():
            job_ids = []
            for i in range(NUM_JOBS):
                job_id = await job_queue.enqueue(
                    TaskEnvelope(type="benchmark", payload={"index": i})
                )
                job_ids.append(job_id)

            completed = 0
            for job_id in job_ids:
                job = await job_queue.claim_job("lifecycle_worker")
                if job:
                    success = await job_queue.complete_job(job_id, "lifecycle_worker")
                    if success:
                        completed += 1
            return completed

        start = time.perf_counter()
        result = benchmark(lambda: asyncio.run(_lifecycle()))
        elapsed = time.perf_counter() - start

        jobs_per_min = (result / elapsed) * 60
        print(f"\nEnd-to-end throughput (100): {jobs_per_min:.0f} jobs/min")

    def test_queue_metrics_overhead(self, job_queue, benchmark):
        """Measure overhead of retrieving queue metrics."""
        for i in range(100):
            asyncio.run(job_queue.enqueue(TaskEnvelope(type="benchmark", payload={"index": i})))

        async def _get_metrics():
            return await job_queue.get_metrics()

        result = benchmark(lambda: asyncio.run(_get_metrics()))
        assert "queue_length" in result


class TestQueueOperations:
    """Benchmark auxiliary queue operations."""

    def test_get_job_latency(self, job_queue, benchmark):
        """Measure time to retrieve a job by ID."""
        job_id = asyncio.run(
            job_queue.enqueue(TaskEnvelope(type="benchmark", payload={"data": "test"}))
        )

        async def _get_job():
            return await job_queue.get_job(job_id)

        result = benchmark(lambda: asyncio.run(_get_job()))
        assert result is not None

    def test_queue_length(self, job_queue, benchmark):
        """Measure time to get queue length."""
        for i in range(100):
            asyncio.run(job_queue.enqueue(TaskEnvelope(type="benchmark", payload={"index": i})))

        async def _get_length():
            return await job_queue.get_queue_length()

        result = benchmark(lambda: asyncio.run(_get_length()))
        assert result == 100

    def test_cancel_job(self, job_queue, benchmark):
        """Measure time to cancel a pending job."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:

            async def _cancel():
                job_id = await job_queue.enqueue(
                    TaskEnvelope(type="benchmark", payload={"data": "test"})
                )
                return await job_queue.cancel_job(job_id)

            result = benchmark(lambda: loop.run_until_complete(_cancel()))
        finally:
            asyncio.set_event_loop(None)
            loop.close()

        assert result is True

    def test_dead_letter_count(self, job_queue, benchmark):
        """Measure time to get dead-letter queue count."""

        async def _get_dlq_count():
            return await job_queue.get_dead_letter_count()

        result = benchmark(lambda: asyncio.run(_get_dlq_count()))
        assert result >= 0
