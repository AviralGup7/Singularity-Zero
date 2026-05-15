# Cyber Pipeline Terraform Module

Deploys the cyber pipeline dashboard and worker into an existing EKS or GKE cluster and provisions managed PostgreSQL plus Redis.

## AWS EKS Example

```hcl
module "cyber_pipeline" {
  source = "./deploy/terraform/cyber-pipeline"

  platform               = "aws"
  name                   = "cyber-pipeline"
  image                  = "ghcr.io/acme/cyber-pipeline:2.0.0"
  aws_vpc_id             = module.vpc.vpc_id
  aws_subnet_ids         = module.vpc.private_subnets
  aws_security_group_ids = [aws_security_group.cyber_pipeline_data.id]
  jaeger_url             = "https://jaeger.example.com"
}
```

## GKE Example

```hcl
module "cyber_pipeline" {
  source = "./deploy/terraform/cyber-pipeline"

  platform    = "gcp"
  name        = "cyber-pipeline"
  image       = "us-docker.pkg.dev/acme/security/cyber-pipeline:2.0.0"
  gcp_project = "acme-prod"
  gcp_region  = "us-central1"
  gcp_network = google_compute_network.private.self_link
  jaeger_url  = "https://jaeger.example.com"
}
```

Configure the `kubernetes` provider outside this module using your EKS or GKE cluster credentials. The module intentionally keeps cluster creation separate from application deployment so production networking, ingress, workload identity, and policy controls can stay owned by the platform layer.
