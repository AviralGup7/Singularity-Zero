"""Asset inventory abstraction and cloud provider implementations."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class CloudAssetInventory(ABC):
    @abstractmethod
    async def discover_assets(self) -> set[str]: ...


class AWSAssetInventory(CloudAssetInventory):
    async def discover_assets(self) -> set[str]:
        try:
            import boto3
        except ImportError:
            logger.warning("boto3 not installed; skipping AWS asset discovery")
            return set()

        assets: set[str] = set()
        try:
            cf = boto3.client("cloudfront")
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                for dist in page.get("DistributionList", {}).get("Items", []):
                    domain = dist.get("DomainName")
                    if domain:
                        assets.add(f"https://{domain}")

            ec2 = boto3.client("ec2")
            regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
            for region in regions:
                elb = boto3.client("elbv2", region_name=region)
                paginator = elb.get_paginator("describe_load_balancers")
                for page in paginator.paginate():
                    for lb in page.get("LoadBalancers", []):
                        dns = lb.get("DNSName")
                        if dns:
                            assets.add(dns)

                ecs = boto3.client("ecs", region_name=region)
                clusters = ecs.list_clusters().get("clusterArns", [])
                for cluster_arn in clusters:
                    services = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
                    for svc_arn in services:
                        svc = ecs.describe_services(cluster=cluster_arn, services=[svc_arn]).get(
                            "services", [{}]
                        )[0]
                        tasks = ecs.list_tasks(
                            cluster=cluster_arn, serviceName=svc.get("serviceName", "")
                        ).get("taskArns", [])
                        for task_arn in tasks:
                            task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn]).get(
                                "tasks", [{}]
                            )[0]
                            for container in task.get("containers", []):
                                for net_if in container.get("networkInterfaces", []):
                                    ip = net_if.get("privateIpv4Address")
                                    if ip:
                                        assets.add(ip)

            apigw = boto3.client("apigateway")
            paginator = apigw.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    endpoint = api.get("endpointConfiguration", {}).get("types", [])
                    if endpoint:
                        assets.add(
                            f"https://{api['id']}.execute-api.{boto3.Session().region_name or 'us-east-1'}.amazonaws.com"
                        )
        except Exception as exc:
            logger.warning("AWS asset discovery failed: %s", exc)
        return assets


class GCPAssetInventory(CloudAssetInventory):
    async def discover_assets(self) -> set[str]:
        try:
            from google.cloud import compute_v1
        except ImportError:
            logger.warning("google-cloud-compute not installed; skipping GCP asset discovery")
            return set()

        assets: set[str] = set()
        try:
            instances_client = compute_v1.InstancesClient()
            compute_v1.ForwardingRulesClient()
            for zone in compute_v1.ZonesClient().list(
                project=compute_v1.ProjectsClient().get("").project
            ):
                for instance in instances_client.list(zone=zone.name, project=zone.project):
                    for nic in instance.network_interfaces:
                        for ip in nic.access_configs or []:
                            nat_ip = ip.get("nat_i_p")
                            if nat_ip:
                                assets.add(nat_ip)
        except Exception as exc:
            logger.warning("GCP asset discovery failed: %s", exc)
        return assets


class AzureAssetInventory(CloudAssetInventory):
    async def discover_assets(self) -> set[str]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
        except ImportError:
            logger.warning(
                "azure-identity or azure-mgmt-compute not installed; skipping Azure asset discovery"
            )
            return set()

        assets: set[str] = set()
        try:
            credential = DefaultAzureCredential()
            subscription_id = (
                credential.get_token("https://management.azure.com/.default").token or ""
            )
            compute_client = ComputeManagementClient(credential, subscription_id)
            for vm in compute_client.virtual_machines.list_all():
                for nic_ref in vm.network_profile.network_interfaces or []:
                    nic = compute_client.network_interfaces.get(
                        vm.id.split("/")[4], nic_ref.id.split("/")[-1]
                    )
                    for ip_config in nic.ip_configurations or []:
                        public_ip = ip_config.public_ip_address
                        if public_ip:
                            assets.add(public_ip.ip_address)
        except Exception as exc:
            logger.warning("Azure asset discovery failed: %s", exc)
        return assets


class AssetInventoryManager:
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._providers: dict[str, CloudAssetInventory] = {}

    def register_provider(self, name: str, provider: CloudAssetInventory) -> None:
        self._providers[name] = provider

    def _build_default_providers(self) -> None:
        providers_env = self._config.get("cloud_providers", "")
        for name in [p.strip() for p in providers_env.split(",") if p.strip()]:
            if name == "aws":
                self.register_provider("aws", AWSAssetInventory())
            elif name == "gcp":
                self.register_provider("gcp", GCPAssetInventory())
            elif name == "azure":
                self.register_provider("azure", AzureAssetInventory())

    async def discover_all(self) -> set[str]:
        if not self._providers:
            self._build_default_providers()
        assets: set[str] = set()
        for name, provider in self._providers.items():
            try:
                found = await provider.discover_assets()
                assets.update(found)
                logger.info("Asset inventory [%s] discovered %d assets", name, len(found))
            except Exception as exc:
                logger.warning("Asset inventory provider %s failed: %s", name, exc)
        return assets

    def diff_against_checkpoint(self, current_assets: set[str], checkpoint_mgr: Any) -> AssetDiff:
        previous_assets: set[str] = set()
        try:
            state = checkpoint_mgr.load()
            if state is not None:
                stored = getattr(state, "scanned_assets", None)
                if stored:
                    previous_assets = set(stored) if isinstance(stored, list) else set(stored)
        except Exception as exc:
            logger.warning("Failed to load previous assets from checkpoint: %s", exc)

        new_assets = current_assets - previous_assets
        removed_assets = previous_assets - current_assets
        unchanged_assets = current_assets & previous_assets
        return AssetDiff(new=new_assets, removed=removed_assets, unchanged=unchanged_assets)


class AssetDiff:
    new: set[str]
    removed: set[str]
    unchanged: set[str]

    def __init__(self, new: set[str], removed: set[str], unchanged: set[str]) -> None:
        self.new = new
        self.removed = removed
        self.unchanged = unchanged
