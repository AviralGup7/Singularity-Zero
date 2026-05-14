terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.32"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
  }
}
