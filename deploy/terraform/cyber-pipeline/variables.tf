variable "platform" {
  description = "Target cloud platform. Supported values: aws or gcp."
  type        = string

  validation {
    condition     = contains(["aws", "gcp"], var.platform)
    error_message = "platform must be aws or gcp."
  }
}

variable "name" {
  description = "Deployment name prefix."
  type        = string
  default     = "cyber-pipeline"
}

variable "namespace" {
  description = "Kubernetes namespace for application workloads."
  type        = string
  default     = "cyber-pipeline"
}

variable "image" {
  description = "Container image for the dashboard and worker."
  type        = string
}

variable "replicas" {
  description = "Dashboard replica count."
  type        = number
  default     = 2
}

variable "worker_replicas" {
  description = "Worker replica count."
  type        = number
  default     = 2
}

variable "database_name" {
  description = "Application database name."
  type        = string
  default     = "cyber_pipeline"
}

variable "database_user" {
  description = "Application database user."
  type        = string
  default     = "cyber_pipeline"
}

variable "database_password" {
  description = "Application database password. If empty, a random password is generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "aws_vpc_id" {
  description = "AWS VPC id for RDS and ElastiCache."
  type        = string
  default     = ""
}

variable "aws_subnet_ids" {
  description = "Private AWS subnet ids for managed data services."
  type        = list(string)
  default     = []
}

variable "aws_security_group_ids" {
  description = "Security groups allowed to reach RDS and Redis."
  type        = list(string)
  default     = []
}

variable "aws_db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "aws_redis_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.small"
}

variable "gcp_project" {
  description = "GCP project id."
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region for Cloud SQL and Memorystore."
  type        = string
  default     = ""
}

variable "gcp_network" {
  description = "GCP VPC network self-link or name."
  type        = string
  default     = "default"
}

variable "gcp_sql_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-2-7680"
}

variable "gcp_redis_memory_gb" {
  description = "Memorystore Redis memory size in GB."
  type        = number
  default     = 1
}

variable "jaeger_url" {
  description = "Base URL for Jaeger deep links shown in the dashboard."
  type        = string
  default     = "http://jaeger-query.observability.svc.cluster.local:16686"
}

variable "resource_labels" {
  description = "Labels/tags for cloud and Kubernetes resources."
  type        = map(string)
  default     = {}
}
