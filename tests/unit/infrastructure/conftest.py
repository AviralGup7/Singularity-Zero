"""Shared fixtures for infrastructure unit tests."""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from src.infrastructure.cache.config import CacheConfig
from src.infrastructure.execution_engine.config import ExecutionConfig
from src.infrastructure.execution_engine.models import Task, TaskPriority
from src.infrastructure.execution_engine.resource_pool import ResourcePool as ResourcePoolImpl
from src.infrastructure.queue.job_queue import JobQueue, RetryPolicy
from src.infrastructure.queue.models import Job, JobState, QueueConfig
from src.infrastructure.security.config import SecurityConfig


@pytest.fixture
def queue_config() -> QueueConfig:
    return QueueConfig()


@pytest.fixture
def job() -> Job:
    return Job(id="test-job-1", type="scan", payload={"target": "example.com"})


@pytest.fixture
def completed_job() -> Job:
    return Job(
        id="test-job-2",
        type="scan",
        payload={"target": "example.com"},
        state=JobState.COMPLETED,
    )


@pytest.fixture
def retry_policy() -> RetryPolicy:
    return RetryPolicy(max_retries=3, jitter=False)


@pytest.fixture
def mock_redis_client():
    client = MagicMock()
    client._use_fallback = True
    client.client = None
    client.execute_command.return_value = None
    client.execute_script.return_value = None
    client.register_script.return_value = None
    return client


@pytest.fixture
def job_queue(mock_redis_client) -> JobQueue:
    return JobQueue(redis_client=mock_redis_client, queue_name="test-queue")


@pytest.fixture
def cache_config(tmp_path) -> CacheConfig:
    return CacheConfig(
        enabled=True,
        enable_l1=True,
        enable_l2=True,
        enable_l3=False,
        l2_backend="sqlite",
        sqlite_db_path=str(tmp_path / "test_cache.db"),
        cache_dir=str(tmp_path / "cache_files"),
        default_ttl=3600,
        max_entries=1000,
        warm_on_init=False,
        log_cache_ops=False,
    )


@pytest.fixture
def security_config() -> SecurityConfig:
    with patch.object(SecurityConfig, "model_post_init", return_value=None):
        config = SecurityConfig.model_construct()
        config.jwt = MagicMock()
        config.jwt.secret = "test-secret-key-for-unit-tests"
        config.jwt.algorithm = "HS256"
        config.jwt.access_token_expiry_minutes = 30
        config.jwt.refresh_token_expiry_days = 7
        config.jwt.issuer = "cyber-security-pipeline"
        config.jwt.audience = "pipeline-dashboard"
        config.api_key = MagicMock()
        config.api_key.header_name = "X-API-Key"
        config.api_key.key_prefix = "csp_"
        config.api_key.rotation_days = 90
        config.api_key.max_keys_per_user = 5
        config.session = MagicMock()
        config.session.timeout_minutes = 60
        config.rate_limit = MagicMock()
        config.rate_limit.window_seconds = 60
        config.rate_limit.default_requests_per_minute = 60
        config.rate_limit.jobs_requests_per_minute = 10
        config.rate_limit.admin_requests_per_minute = 20
        config.rate_limit.replay_requests_per_minute = 30
        config.rate_limit.bypass_tokens = []
        config.rate_limit.redis_url = None
        config.cors = MagicMock()
        config.headers = MagicMock()
        config.encryption = MagicMock()
        config.audit = MagicMock()
        config.audit.log_path = os.path.join(tempfile.gettempdir(), "test_audit.log")
        config.audit.retention_days = 90
        config.audit.tamper_evident = True
        config.audit.hmac_secret = "test-hmac-secret"
        config.audit.max_log_size_mb = 100
        config.audit.rotate_on_size = True
        config.audit.export_format = "json"
        config.input_validation = MagicMock()
        config.input_validation.max_url_length = 2048
        config.input_validation.max_target_name_length = 255
        config.input_validation.max_payload_size_bytes = 1024 * 1024
        config.input_validation.max_request_body_bytes = 10 * 1024 * 1024
        config.input_validation.allowed_url_schemes = ["http", "https"]
        config.input_validation.blocked_target_patterns = [r"\.\.", r"/etc/"]
        config.input_validation.allowed_content_types = ["application/json"]
        return config


@pytest.fixture
def execution_config() -> ExecutionConfig:
    return ExecutionConfig(
        max_workers=4,
        max_cpu_workers=2,
        default_timeout_seconds=30.0,
        default_retries=1,
        enable_load_balancing=False,
        enable_progress_callbacks=False,
        cancel_on_first_error=False,
    )


@pytest.fixture
def resource_pool() -> ResourcePoolImpl:
    return ResourcePoolImpl(name="test-pool", max_concurrent=5, acquire_timeout=5.0)


@pytest.fixture
def sample_task():
    def dummy_fn():
        return "done"

    return Task(name="test-task", fn=dummy_fn)


@pytest.fixture
def high_priority_task():
    def dummy_fn():
        return "high"

    return Task(name="high-priority-task", fn=dummy_fn, priority=TaskPriority.HIGH)
