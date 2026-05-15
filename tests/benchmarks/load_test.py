"""Locust load test script for the Cyber Security Test Pipeline Dashboard.

Simulates realistic user behavior patterns including:
- Dashboard viewing (stats, targets, findings)
- Health monitoring
- Detection gap analysis
- Mixed workload patterns

Usage:
    # Web UI mode
    locust -f benchmarks/load_test.py --host=http://localhost:8080

    # Headless mode
    locust -f benchmarks/load_test.py \
        --host=http://localhost:8080 \
        --users 100 \
        --spawn-rate 10 \
        --run-time 5m \
        --headless \
        --csv=locust_results
"""

import random
import time

from locust import HttpUser, between, events, task


class DashboardViewer(HttpUser):
    """Simulates a user viewing the security dashboard."""

    wait_time = between(1, 5)

    @task(10)
    def view_dashboard_stats(self):
        """View dashboard statistics (most common action)."""
        with self.client.get(
            "/api/dashboard-stats",
            name="/api/dashboard-stats",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "pipeline_health_score" not in data:
                    response.failure("Missing pipeline health score")
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(5)
    def list_targets(self):
        """View list of scan targets."""
        with self.client.get(
            "/api/targets",
            name="/api/targets",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")

    @task(3)
    def view_findings(self):
        """View findings summary."""
        with self.client.get(
            "/api/findings",
            name="/api/findings",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")

    @task(2)
    def check_health(self):
        """Check API health."""
        with self.client.get(
            "/api/health",
            name="/api/health",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if data.get("status") != "ok":
                    response.failure("Health check not ok")
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(1)
    def check_detection_gap(self):
        """Check detection gap analysis."""
        with self.client.get(
            "/api/detection-gap",
            name="/api/detection-gap",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")


class SecurityAnalyst(HttpUser):
    """Simulates a security analyst performing detailed analysis."""

    wait_time = between(2, 8)

    @task(5)
    def analyze_targets(self):
        """Analyze scan targets in detail."""
        with self.client.get(
            "/api/targets",
            name="/api/targets",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                targets = response.json().get("targets", [])
                if targets:
                    target = random.choice(targets)
                    target_name = target.get("name", "")
                    if target_name:
                        self.client.get(
                            f"/api/detection-gap?target={target_name}",
                            name="/api/detection-gap?target=[name]",
                        )
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(3)
    def review_findings(self):
        """Review security findings."""
        with self.client.get(
            "/api/findings",
            name="/api/findings",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")

    @task(2)
    def monitor_health(self):
        """Monitor system health during analysis."""
        with self.client.get(
            "/api/health",
            name="/api/health",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")

    @task(1)
    def view_dashboard(self):
        """View full dashboard stats."""
        with self.client.get(
            "/api/dashboard-stats",
            name="/api/dashboard-stats",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")


class AutomatedMonitor(HttpUser):
    """Simulates an automated monitoring system polling the API."""

    wait_time = between(0.5, 2)

    @task(10)
    def health_poll(self):
        """Poll health endpoint frequently."""
        with self.client.get(
            "/api/health",
            name="/api/health",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")

    @task(5)
    def stats_poll(self):
        """Poll dashboard stats."""
        with self.client.get(
            "/api/dashboard-stats",
            name="/api/dashboard-stats",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"Status code: {response.status_code}")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Log test start information."""
    print("=" * 60)
    print("Load Test Started")
    print(f"Target: {environment.host}")
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Log test summary."""
    print("=" * 60)
    print("Load Test Completed")
    print(f"End time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    stats = environment.runner.stats
    print(f"Total requests: {stats.total.num_requests}")
    print(f"Total failures: {stats.total.num_failures}")
    if stats.total.num_requests > 0:
        failure_rate = (stats.total.num_failures / stats.total.num_requests) * 100
        print(f"Failure rate: {failure_rate:.2f}%")
        print(f"Average response time: {stats.total.avg_response_time:.0f}ms")
        print(f"Median response time: {stats.total.median_response_time:.0f}ms")
        print(f"95th percentile: {stats.total.get_response_time_percentile(0.95):.0f}ms")
        print(f"99th percentile: {stats.total.get_response_time_percentile(0.99):.0f}ms")
    print("=" * 60)


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    """Log slow requests."""
    if response_time > 500:
        print(f"SLOW REQUEST: {request_type} {name} took {response_time:.0f}ms")
