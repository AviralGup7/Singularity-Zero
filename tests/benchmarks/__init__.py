"""Benchmark test suite for the cyber security test pipeline.

This package contains comprehensive performance benchmarks for all
newly created pipeline components:

- test_queue_benchmarks.py: queue_system throughput and latency
- test_cache_benchmarks.py: cache_layer multi-tier performance
- test_api_benchmarks.py: fastapi_dashboard endpoint latency
- test_execution_benchmarks.py: execution_engine concurrency and DAG scheduling
- conftest.py: shared fixtures and configuration
- load_test.py: Locust load testing scripts

Run all benchmarks:
    pytest benchmarks/ --benchmark-only -v

Run specific component:
    pytest benchmarks/test_queue_benchmarks.py --benchmark-only -v

Compare with baseline:
    pytest benchmarks/ --benchmark-compare=baseline --benchmark-histogram

Load test with Locust:
    locust -f benchmarks/load_test.py --host=http://localhost:8000
"""
