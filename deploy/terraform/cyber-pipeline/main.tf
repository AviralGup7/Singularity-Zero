locals {
  labels = merge(
    {
      app       = var.name
      component = "security-pipeline"
      managed   = "terraform"
    },
    var.resource_labels,
  )
  db_password = var.database_password != "" ? var.database_password : random_password.db_password.result

  redis_host = var.platform == "aws" ? one(aws_elasticache_replication_group.redis[*].primary_endpoint_address) : one(google_redis_instance.redis[*].host)
  redis_port = var.platform == "aws" ? 6379 : one(google_redis_instance.redis[*].port)
  sql_host   = var.platform == "aws" ? one(aws_db_instance.postgres[*].address) : one(google_sql_database_instance.postgres[*].private_ip_address)
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_db_subnet_group" "postgres" {
  count      = var.platform == "aws" ? 1 : 0
  name       = "${var.name}-postgres"
  subnet_ids = var.aws_subnet_ids
  tags       = local.labels
}

resource "aws_db_instance" "postgres" {
  count                      = var.platform == "aws" ? 1 : 0
  identifier                 = "${var.name}-postgres"
  engine                     = "postgres"
  engine_version             = "16"
  instance_class             = var.aws_db_instance_class
  allocated_storage          = 50
  max_allocated_storage      = 250
  db_name                    = var.database_name
  username                   = var.database_user
  password                   = local.db_password
  db_subnet_group_name       = aws_db_subnet_group.postgres[0].name
  vpc_security_group_ids     = var.aws_security_group_ids
  storage_encrypted          = true
  backup_retention_period    = 7
  deletion_protection        = true
  multi_az                   = true
  auto_minor_version_upgrade = true
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${var.name}-postgres-final"
  tags                       = local.labels
}

resource "aws_elasticache_subnet_group" "redis" {
  count      = var.platform == "aws" ? 1 : 0
  name       = "${var.name}-redis"
  subnet_ids = var.aws_subnet_ids
  tags       = local.labels
}

resource "aws_elasticache_replication_group" "redis" {
  count                      = var.platform == "aws" ? 1 : 0
  replication_group_id       = "${var.name}-redis"
  description                = "Redis for ${var.name}"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.aws_redis_node_type
  port                       = 6379
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  subnet_group_name          = aws_elasticache_subnet_group.redis[0].name
  security_group_ids         = var.aws_security_group_ids
  tags                       = local.labels
}

resource "google_sql_database_instance" "postgres" {
  count            = var.platform == "gcp" ? 1 : 0
  name             = "${var.name}-postgres"
  project          = var.gcp_project
  region           = var.gcp_region
  database_version = "POSTGRES_16"

  settings {
    tier              = var.gcp_sql_tier
    availability_type = "REGIONAL"
    disk_autoresize   = true
    disk_size         = 50
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.gcp_network
    }
  }

  deletion_protection = true
}

resource "google_sql_database" "app" {
  count    = var.platform == "gcp" ? 1 : 0
  name     = var.database_name
  project  = var.gcp_project
  instance = google_sql_database_instance.postgres[0].name
}

resource "google_sql_user" "app" {
  count    = var.platform == "gcp" ? 1 : 0
  name     = var.database_user
  project  = var.gcp_project
  instance = google_sql_database_instance.postgres[0].name
  password = local.db_password
}

resource "google_redis_instance" "redis" {
  count                   = var.platform == "gcp" ? 1 : 0
  name                    = "${var.name}-redis"
  project                 = var.gcp_project
  region                  = var.gcp_region
  tier                    = "STANDARD_HA"
  memory_size_gb          = var.gcp_redis_memory_gb
  redis_version           = "REDIS_7_0"
  authorized_network      = var.gcp_network
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  labels                  = local.labels
}

resource "kubernetes_namespace" "app" {
  metadata {
    name   = var.namespace
    labels = local.labels
  }
}

resource "kubernetes_secret" "app" {
  metadata {
    name      = "${var.name}-runtime"
    namespace = kubernetes_namespace.app.metadata[0].name
    labels    = local.labels
  }

  data = {
    DATABASE_URL = "postgresql://${var.database_user}:${local.db_password}@${local.sql_host}:5432/${var.database_name}"
    REDIS_URL    = "redis://${local.redis_host}:${local.redis_port}/0"
  }

  type = "Opaque"
}

resource "kubernetes_deployment" "dashboard" {
  metadata {
    name      = "${var.name}-dashboard"
    namespace = kubernetes_namespace.app.metadata[0].name
    labels    = merge(local.labels, { role = "dashboard" })
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        app  = var.name
        role = "dashboard"
      }
    }

    template {
      metadata {
        labels = merge(local.labels, { role = "dashboard" })
      }

      spec {
        container {
          name  = "dashboard"
          image = var.image
          args  = ["cyber", "start", "dashboard", "--host", "0.0.0.0", "--port", "8000"]

          env_from {
            secret_ref {
              name = kubernetes_secret.app.metadata[0].name
            }
          }

          env {
            name  = "CYBER_JAEGER_URL"
            value = var.jaeger_url
          }

          port {
            name           = "http"
            container_port = 8000
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1000m"
              memory = "1Gi"
            }
          }

          readiness_probe {
            http_get {
              path = "/api/health/live"
              port = "http"
            }
            initial_delay_seconds = 15
            period_seconds        = 10
          }

          liveness_probe {
            http_get {
              path = "/api/health/live"
              port = "http"
            }
            initial_delay_seconds = 30
            period_seconds        = 20
          }
        }
      }
    }
  }
}

resource "kubernetes_deployment" "worker" {
  metadata {
    name      = "${var.name}-worker"
    namespace = kubernetes_namespace.app.metadata[0].name
    labels    = merge(local.labels, { role = "worker" })
  }

  spec {
    replicas = var.worker_replicas

    selector {
      match_labels = {
        app  = var.name
        role = "worker"
      }
    }

    template {
      metadata {
        labels = merge(local.labels, { role = "worker" })
      }

      spec {
        container {
          name  = "worker"
          image = var.image
          args  = ["cyber-worker"]

          env_from {
            secret_ref {
              name = kubernetes_secret.app.metadata[0].name
            }
          }

          resources {
            requests = {
              cpu    = "500m"
              memory = "1Gi"
            }
            limits = {
              cpu    = "2000m"
              memory = "2Gi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "dashboard" {
  metadata {
    name      = "${var.name}-dashboard"
    namespace = kubernetes_namespace.app.metadata[0].name
    labels    = merge(local.labels, { role = "dashboard" })
  }

  spec {
    selector = {
      app  = var.name
      role = "dashboard"
    }

    port {
      name        = "http"
      port        = 80
      target_port = "http"
    }
  }
}
