"""Cloud provider check modules."""

from src.recon.cloud_recon.providers.aws import (
    check_aws_bucket,
    probe_api_gateway,
    probe_aws_amplify,
    probe_aws_lambda_urls,
    probe_multi_region_s3,
    probe_s3_access_points,
)
from src.recon.cloud_recon.providers.azure import (
    check_azure_bucket,
    probe_azure_functions,
    probe_azure_logic_apps,
    probe_azure_static_web_apps,
)
from src.recon.cloud_recon.providers.backblaze import probe_backblaze_b2
from src.recon.cloud_recon.providers.digitalocean import probe_digitalocean_spaces
from src.recon.cloud_recon.providers.firebase import probe_firebase_hosting
from src.recon.cloud_recon.providers.gcp import (
    check_gcp_bucket,
    probe_gcp_app_engine,
    probe_gcp_cloud_functions,
)
from src.recon.cloud_recon.providers.generic import check_alibaba_bucket, check_tencent_bucket
from src.recon.cloud_recon.providers.oci import probe_oci_object_storage
from src.recon.cloud_recon.providers.wasabi import probe_wasabi

__all__ = [
    "check_aws_bucket",
    "check_azure_bucket",
    "check_gcp_bucket",
    "check_alibaba_bucket",
    "check_tencent_bucket",
    "probe_aws_amplify",
    "probe_aws_lambda_urls",
    "probe_api_gateway",
    "probe_azure_functions",
    "probe_azure_logic_apps",
    "probe_azure_static_web_apps",
    "probe_backblaze_b2",
    "probe_digitalocean_spaces",
    "probe_firebase_hosting",
    "probe_gcp_app_engine",
    "probe_gcp_cloud_functions",
    "probe_multi_region_s3",
    "probe_oci_object_storage",
    "probe_s3_access_points",
    "probe_wasabi",
]
