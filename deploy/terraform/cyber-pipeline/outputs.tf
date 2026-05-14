output "namespace" {
  description = "Kubernetes namespace."
  value       = kubernetes_namespace.app.metadata[0].name
}

output "dashboard_service_name" {
  description = "Kubernetes Service name for the dashboard."
  value       = kubernetes_service.dashboard.metadata[0].name
}

output "redis_host" {
  description = "Managed Redis host."
  value       = local.redis_host
}

output "sql_host" {
  description = "Managed PostgreSQL host."
  value       = local.sql_host
}

output "database_name" {
  description = "Application database name."
  value       = var.database_name
}
