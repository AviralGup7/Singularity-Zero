"""Concurrent execution engine for the cyber security test pipeline.

Provides DAG-based task scheduling, resource-pool-backed concurrency limiting,
dynamic load balancing, and support for both CPU-bound and I/O-bound workloads.

Public API exports:
    - Task, TaskResult, TaskStatus, TaskPriority, ResourcePool, ExecutionConfig
    - ResourcePoolManager
    - ConcurrentExecutor, ExecutionSummary
    - LoadBalancer, WorkerStats
    - DEFAULT_EXECUTION_CONFIG, load_execution_config
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

_LAZY_IMPORTS: dict[str, str] = {
    "ConcurrentExecutor": "src.infrastructure.execution_engine.concurrent_executor",
    "ExecutionSummary": "src.infrastructure.execution_engine.concurrent_executor",
    "DEFAULT_EXECUTION_CONFIG": "src.infrastructure.execution_engine.config",
    "ExecutionConfig": "src.infrastructure.execution_engine.config",
    "load_execution_config": "src.infrastructure.execution_engine.config",
    "LoadBalancer": "src.infrastructure.execution_engine.load_balancer",
    "WorkerStats": "src.infrastructure.execution_engine.load_balancer",
    "ResourcePool": "src.infrastructure.execution_engine.resource_pool",
    "ResourcePoolManager": "src.infrastructure.execution_engine.resource_pool",
    "Task": "src.infrastructure.execution_engine.models",
    "TaskPriority": "src.infrastructure.execution_engine.models",
    "TaskResult": "src.infrastructure.execution_engine.models",
    "TaskStatus": "src.infrastructure.execution_engine.models",
    "ExecutionConfigModel": "src.infrastructure.execution_engine.models",
    "ResourcePoolModel": "src.infrastructure.execution_engine.models",
}

__all__ = [
    "Task",
    "TaskResult",
    "TaskStatus",
    "TaskPriority",
    "ResourcePool",
    "ResourcePoolModel",
    "ExecutionConfig",
    "ExecutionConfigModel",
    "ResourcePool",
    "ResourcePoolManager",
    "ConcurrentExecutor",
    "ExecutionSummary",
    "LoadBalancer",
    "WorkerStats",
    "DEFAULT_EXECUTION_CONFIG",
    "load_execution_config",
]


def __getattr__(name: str) -> ModuleType | object:
    module_path = _LAZY_IMPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_path)
    attr = getattr(module, name)
    globals()[name] = attr
    return attr
