# Root terragrunt.hcl for multi-cloud Kubernetes infrastructure
# This file defines common configuration for all environments

# Configure Terragrunt to automatically retry on errors
retryable_errors = [
  "(?s).*Error installing provider.*tcp.*connection reset by peer.*",
  "(?s).*ssh_exchange_identification.*Connection closed by remote host.*",
  "(?s).*Client\\.Timeout exceeded while awaiting headers.*",
  "(?s).*connection reset by peer.*",
  "(?s).*TLS handshake timeout.*",
]

# Configure remote state
remote_state {
  backend = "s3"
  
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  
  config = {
    bucket = "multicloud-k8s-terraform-state-${get_env("TF_VAR_project_name", "default")}"
    key    = "${path_relative_to_include()}/terraform.tfstate"
    region = "us-west-2"
    
    # Enable versioning and encryption
    versioning                = true
    server_side_encryption_configuration = {
      rule = {
        apply_server_side_encryption_by_default = {
          sse_algorithm = "AES256"
        }
      }
    }
    
    # Enable state locking
    dynamodb_table = "multicloud-k8s-terraform-locks"
    
    # Skip bucket creation if it doesn't exist
    skip_bucket_versioning         = false
    skip_bucket_ssencryption      = false
    skip_bucket_root_access       = false
    skip_bucket_enforced_tls      = false
    skip_bucket_public_access_blocking = false
  }
}

# Generate provider configurations
generate "provider" {
  path      = "providers.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
# AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = var.owner
    }
  }
}

# Azure Provider
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

# Google Cloud Provider
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "google-beta" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Kubernetes Provider (will be configured after cluster creation)
provider "kubernetes" {
  alias = "aws"
  host  = try(module.aws_eks[0].cluster_endpoint, "")
  
  cluster_ca_certificate = try(
    base64decode(module.aws_eks[0].cluster_certificate_authority_data),
    ""
  )
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      try(module.aws_eks[0].cluster_name, ""),
      "--region",
      var.aws_region,
    ]
  }
}

provider "kubernetes" {
  alias = "azure"
  host  = try(module.azure_aks[0].kube_config.0.host, "")
  
  client_certificate = try(
    base64decode(module.azure_aks[0].kube_config.0.client_certificate),
    ""
  )
  client_key = try(
    base64decode(module.azure_aks[0].kube_config.0.client_key),
    ""
  )
  cluster_ca_certificate = try(
    base64decode(module.azure_aks[0].kube_config.0.cluster_ca_certificate),
    ""
  )
}

provider "kubernetes" {
  alias = "gcp"
  host  = try("https://${module.gcp_gke[0].endpoint}", "")
  
  cluster_ca_certificate = try(
    base64decode(module.gcp_gke[0].ca_certificate),
    ""
  )
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "gke-gcloud-auth-plugin"
  }
}

# Helm Provider
provider "helm" {
  alias = "aws"
  kubernetes {
    host = try(module.aws_eks[0].cluster_endpoint, "")
    
    cluster_ca_certificate = try(
      base64decode(module.aws_eks[0].cluster_certificate_authority_data),
      ""
    )
    
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        try(module.aws_eks[0].cluster_name, ""),
        "--region",
        var.aws_region,
      ]
    }
  }
}

provider "helm" {
  alias = "azure"
  kubernetes {
    host = try(module.azure_aks[0].kube_config.0.host, "")
    
    client_certificate = try(
      base64decode(module.azure_aks[0].kube_config.0.client_certificate),
      ""
    )
    client_key = try(
      base64decode(module.azure_aks[0].kube_config.0.client_key),
      ""
    )
    cluster_ca_certificate = try(
      base64decode(module.azure_aks[0].kube_config.0.cluster_ca_certificate),
      ""
    )
  }
}

provider "helm" {
  alias = "gcp"
  kubernetes {
    host = try("https://${module.gcp_gke[0].endpoint}", "")
    
    cluster_ca_certificate = try(
      base64decode(module.gcp_gke[0].ca_certificate),
      ""
    )
    
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "gke-gcloud-auth-plugin"
    }
  }
}

# Megaport Provider for cross-cloud connectivity
provider "megaport" {
  alias                 = "cross_cloud"
  access_key           = var.megaport_access_key
  secret_key           = var.megaport_secret_key
  accept_purchase_terms = true
  delete_ports         = true
  environment          = "production"
}
EOF
}

# Generate common variables
generate "variables" {
  path      = "variables.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
# Common Variables for Multi-Cloud Infrastructure

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "multicloud-k8s"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "owner" {
  description = "Owner of the infrastructure"
  type        = string
  default     = "nguie-angoue-jean-roch-junior"
}

# AWS Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "aws_availability_zones" {
  description = "AWS availability zones"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

# Azure Variables
variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "West US 2"
}

# GCP Variables
variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-west1"
}

variable "gcp_zones" {
  description = "GCP zones"
  type        = list(string)
  default     = ["us-west1-a", "us-west1-b", "us-west1-c"]
}

# Kubernetes Configuration
variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "node_count" {
  description = "Number of nodes per cluster"
  type        = number
  default     = 3
}

# Networking
variable "vpc_cidr" {
  description = "VPC CIDR blocks for each cloud"
  type = object({
    aws   = string
    azure = string
    gcp   = string
  })
  default = {
    aws   = "10.0.0.0/16"
    azure = "10.1.0.0/16"
    gcp   = "10.2.0.0/16"
  }
}

# Megaport Configuration
variable "megaport_access_key" {
  description = "Megaport API access key"
  type        = string
  sensitive   = true
}

variable "megaport_secret_key" {
  description = "Megaport API secret key"
  type        = string
  sensitive   = true
}

# Monitoring Configuration
variable "monitoring_vpc_cidr" {
  description = "CIDR block for monitoring VPC"
  type        = string
  default     = "10.100.0.0/16"
}

# Security Configuration
variable "enable_opa_gatekeeper" {
  description = "Enable OPA Gatekeeper for policy enforcement"
  type        = bool
  default     = true
}

variable "enable_falco" {
  description = "Enable Falco for runtime security"
  type        = bool
  default     = true
}

variable "enable_trivy" {
  description = "Enable Trivy for vulnerability scanning"
  type        = bool
  default     = true
}

# Observability Configuration
variable "enable_victoria_metrics" {
  description = "Enable VictoriaMetrics for metrics storage"
  type        = bool
  default     = true
}

variable "enable_grafana_tempo" {
  description = "Enable Grafana Tempo for distributed tracing"
  type        = bool
  default     = true
}

variable "enable_vector" {
  description = "Enable Vector for log collection"
  type        = bool
  default     = true
}

# Service Mesh Configuration
variable "enable_linkerd" {
  description = "Enable Linkerd service mesh"
  type        = bool
  default     = true
}

variable "enable_cilium" {
  description = "Enable Cilium CNI"
  type        = bool
  default     = true
}
EOF
}

# Configure Terraform version constraints
terraform_version_constraint = ">= 1.5.0"

# Configure Terragrunt version constraints
terragrunt_version_constraint = ">= 0.50.0" 