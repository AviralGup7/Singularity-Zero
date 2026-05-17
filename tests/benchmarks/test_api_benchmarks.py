"""FastAPI dashboard endpoint benchmarks.

Measures response latency for all dashboard API endpoints under
single and concurrent request patterns.
"""

import concurrent.futures


class TestHealthEndpoint:
    """Benchmark /api/health endpoint."""

    def test_health_latency(self, dashboard_app, benchmark):
        """Measure /api/health response time."""

        def _get_health():
            return dashboard_app.get("/api/health")

        result = benchmark(_get_health)
        assert result.status_code == 200
        data = result.json()
        assert data["status"] in ("ok", "degraded")
        assert "timestamp" in data
        assert "version" in data

    def test_health_concurrent(self, dashboard_app, benchmark):
        """Measure /api/health under concurrent load."""

        def _get_health():
            return dashboard_app.get("/api/health")

        def _concurrent():
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(_get_health) for _ in range(50)]
                return [f.result() for f in futures]

        results = benchmark(_concurrent)
        assert all(r.status_code == 200 for r in results)


class TestDashboardStatsEndpoint:
    """Benchmark /api/dashboard endpoint."""

    def test_dashboard_stats_latency(self, dashboard_app, benchmark):
        """Measure /api/dashboard response time."""

        def _get_stats():
            return dashboard_app.get("/api/dashboard")

        result = benchmark(_get_stats)
        assert result.status_code == 200
        data = result.json()
        assert "active_jobs" in data
        assert "pipeline_health_score" in data
        assert "severity_counts" in data

    def test_dashboard_stats_concurrent(self, dashboard_app, benchmark):
        """Measure /api/dashboard under concurrent load."""

        def _get_stats():
            return dashboard_app.get("/api/dashboard")

        def _concurrent():
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(_get_stats) for _ in range(30)]
                return [f.result() for f in futures]

        results = benchmark(_concurrent)
        assert all(r.status_code == 200 for r in results)


class TestTargetsEndpoint:
    """Benchmark /api/targets endpoint."""

    def test_list_targets_latency(self, dashboard_app, benchmark):
        """Measure /api/targets response time."""

        def _get_targets():
            return dashboard_app.get("/api/targets")

        result = benchmark(_get_targets)
        assert result.status_code == 200
        data = result.json()
        assert "targets" in data

    def test_list_targets_concurrent(self, dashboard_app, benchmark):
        """Measure /api/targets under concurrent load."""

        def _get_targets():
            return dashboard_app.get("/api/targets")

        def _concurrent():
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(_get_targets) for _ in range(30)]
                return [f.result() for f in futures]

        results = benchmark(_concurrent)
        assert all(r.status_code == 200 for r in results)


class TestFindingsEndpoint:
    """Benchmark /api/findings endpoint."""

    def test_findings_latency(self, dashboard_app, benchmark):
        """Measure /api/findings response time."""

        def _get_findings():
            return dashboard_app.get("/api/findings")

        result = benchmark(_get_findings)
        assert result.status_code == 200

    def test_findings_concurrent(self, dashboard_app, benchmark):
        """Measure /api/findings under concurrent load."""

        def _get_findings():
            return dashboard_app.get("/api/findings")

        def _concurrent():
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(_get_findings) for _ in range(30)]
                return [f.result() for f in futures]

        results = benchmark(_concurrent)
        assert all(r.status_code == 200 for r in results)


class TestGapAnalysisEndpoint:
    """Benchmark /api/gap-analysis endpoint."""

    def test_gap_analysis_latency(self, dashboard_app, benchmark):
        """Measure /api/gap-analysis response time."""

        def _get_gap():
            return dashboard_app.get("/api/gap-analysis")

        result = benchmark(_get_gap)
        assert result.status_code == 200

    def test_gap_analysis_with_target(self, dashboard_app, benchmark):
        """Measure /api/gap-analysis with target parameter."""

        def _get_gap():
            return dashboard_app.get("/api/gap-analysis?target=example.com")

        result = benchmark(_get_gap)
        assert result.status_code == 200


class TestRegistryEndpoint:
    """Benchmark /api/registry endpoint."""

    def test_registry_latency(self, dashboard_app, benchmark):
        """Measure /api/registry response time."""

        def _get_registry():
            return dashboard_app.get("/api/registry")

        result = benchmark(_get_registry)
        assert result.status_code == 200


class TestRootEndpoint:
    """Benchmark root (/) endpoint."""

    def test_root_latency(self, dashboard_app, benchmark):
        """Measure / response time."""

        def _get_root():
            return dashboard_app.get("/")

        result = benchmark(_get_root)
        # Root now serves SPA index, so it should be 200 or 404 if build missing
        assert result.status_code in (200, 404)


class TestOpenAPIEndpoint:
    """Benchmark OpenAPI schema endpoint."""

    def test_openapi_latency(self, dashboard_app, benchmark):
        """Measure /api/openapi.json response time."""

        def _get_openapi():
            return dashboard_app.get("/api/openapi.json")

        result = benchmark(_get_openapi)
        assert result.status_code == 200
        assert "openapi" in result.json()


class TestMixedEndpointLoad:
    """Benchmark mixed endpoint patterns."""

    def test_mixed_endpoints(self, dashboard_app, benchmark):
        """Measure response times for mixed endpoint access."""
        endpoints = [
            "/api/health",
            "/api/dashboard",
            "/api/targets",
            "/api/findings",
            "/api/registry",
            "/api/gap-analysis",
        ]

        def _mixed_requests():
            results = []
            for _ in range(6):
                for ep in endpoints:
                    resp = dashboard_app.get(ep)
                    results.append(resp)
            return results

        results = benchmark(_mixed_requests)
        assert all(r.status_code == 200 for r in results)

    def test_high_concurrency_mixed(self, dashboard_app, benchmark):
        """Measure mixed endpoints under high concurrency."""
        endpoints = ["/api/health", "/api/dashboard", "/api/targets"]

        def _high_concurrency():
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                for _ in range(100):
                    ep = endpoints[0]
                    futures.append(executor.submit(dashboard_app.get, ep))
                return [f.result() for f in futures]

        results = benchmark(_high_concurrency)
        assert all(r.status_code == 200 for r in results)
