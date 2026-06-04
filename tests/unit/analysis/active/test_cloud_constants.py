"""Unit tests for src.analysis.active.cloud_constants."""

import unittest

import pytest

from src.analysis.active.cloud_constants import (
    AZURE_METADATA_HEADER,
    CLOUD_METADATA_ENDPOINTS,
    CLOUD_STORAGE_PATHS,
    GCP_METADATA_HEADER,
    IMDSV2_TOKEN_HEADER,
    INFRASTRUCTURE_SERVICE_PATHS,
)


@pytest.mark.unit
class TestCloudMetadataEndpoints(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(CLOUD_METADATA_ENDPOINTS, dict)

    def test_contains_aws(self) -> None:
        self.assertIn("aws_imds", CLOUD_METADATA_ENDPOINTS)
        urls = CLOUD_METADATA_ENDPOINTS["aws_imds"]
        self.assertTrue(any("169.254.169.254" in u for u in urls))

    def test_contains_gcp(self) -> None:
        self.assertIn("gcp_metadata", CLOUD_METADATA_ENDPOINTS)
        urls = CLOUD_METADATA_ENDPOINTS["gcp_metadata"]
        self.assertTrue(any("metadata.google.internal" in u for u in urls))

    def test_contains_azure(self) -> None:
        self.assertIn("azure_imds", CLOUD_METADATA_ENDPOINTS)
        urls = CLOUD_METADATA_ENDPOINTS["azure_imds"]
        self.assertTrue(any("169.254.169.254/metadata/instance" in u for u in urls))

    def test_contains_digitalocean(self) -> None:
        self.assertIn("digitalocean_metadata", CLOUD_METADATA_ENDPOINTS)

    def test_contains_alibaba(self) -> None:
        self.assertIn("alibaba_metadata", CLOUD_METADATA_ENDPOINTS)
        urls = CLOUD_METADATA_ENDPOINTS["alibaba_metadata"]
        self.assertTrue(any("100.100.100.200" in u for u in urls))

    def test_all_values_are_lists_of_strings(self) -> None:
        for name, urls in CLOUD_METADATA_ENDPOINTS.items():
            self.assertIsInstance(urls, list)
            for url in urls:
                self.assertIsInstance(url, str)
                self.assertTrue(url.startswith("http"))


@pytest.mark.unit
class TestCloudStoragePaths(unittest.TestCase):
    def test_is_list(self) -> None:
        self.assertIsInstance(CLOUD_STORAGE_PATHS, list)

    def test_paths_start_with_slash(self) -> None:
        for path in CLOUD_STORAGE_PATHS:
            self.assertTrue(path.startswith("/"), f"{path} missing leading slash")

    def test_contains_common_storage_paths(self) -> None:
        for path in ("/s3", "/bucket", "/storage", "/blob"):
            self.assertIn(path, CLOUD_STORAGE_PATHS)

    def test_contains_sensitive_paths(self) -> None:
        for path in ("/backup", "/dump", "/export"):
            self.assertIn(path, CLOUD_STORAGE_PATHS)


@pytest.mark.unit
class TestInfrastructureServicePaths(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(INFRASTRUCTURE_SERVICE_PATHS, dict)

    def test_contains_docker(self) -> None:
        self.assertIn("docker_api", INFRASTRUCTURE_SERVICE_PATHS)
        paths = INFRASTRUCTURE_SERVICE_PATHS["docker_api"]
        self.assertIn("/containers/json", paths)

    def test_contains_kubernetes(self) -> None:
        self.assertIn("kubernetes_api", INFRASTRUCTURE_SERVICE_PATHS)
        paths = INFRASTRUCTURE_SERVICE_PATHS["kubernetes_api"]
        self.assertIn("/api/v1/pods", paths)

    def test_contains_elasticsearch(self) -> None:
        self.assertIn("elasticsearch", INFRASTRUCTURE_SERVICE_PATHS)
        paths = INFRASTRUCTURE_SERVICE_PATHS["elasticsearch"]
        self.assertIn("/_cat/indices", paths)

    def test_contains_redis(self) -> None:
        self.assertIn("redis_info", INFRASTRUCTURE_SERVICE_PATHS)

    def test_contains_jenkins(self) -> None:
        self.assertIn("jenkins", INFRASTRUCTURE_SERVICE_PATHS)
        self.assertIn("/script", INFRASTRUCTURE_SERVICE_PATHS["jenkins"])

    def test_contains_prometheus(self) -> None:
        self.assertIn("prometheus", INFRASTRUCTURE_SERVICE_PATHS)
        self.assertIn("/metrics", INFRASTRUCTURE_SERVICE_PATHS["prometheus"])

    def test_contains_rabbitmq(self) -> None:
        self.assertIn("rabbitmq", INFRASTRUCTURE_SERVICE_PATHS)

    def test_all_values_are_lists_of_strings(self) -> None:
        for name, paths in INFRASTRUCTURE_SERVICE_PATHS.items():
            self.assertIsInstance(paths, list)
            for path in paths:
                self.assertIsInstance(path, str)
                self.assertTrue(path.startswith("/"))


@pytest.mark.unit
class TestHeaderConstants(unittest.TestCase):
    def test_imdsv2_token_header_value(self) -> None:
        self.assertEqual(IMDSV2_TOKEN_HEADER, "X-aws-ec2-metadata-token")

    def test_gcp_metadata_header_value(self) -> None:
        self.assertEqual(GCP_METADATA_HEADER, "Metadata-Flavor")

    def test_azure_metadata_header_value(self) -> None:
        self.assertEqual(AZURE_METADATA_HEADER, "Metadata")


if __name__ == "__main__":
    unittest.main()
