# Multi-Cloud Kubernetes Infrastructure
# This file orchestrates the deployment of identical Kubernetes clusters
# across AWS EKS, Azure AKS, and Google GKE

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    megaport = {
      source  = "megaport/megaport"
      version = "~> 0.4"
    }
  }
}

# Local values for cloud-agnostic configuration
locals {
  # Define cluster configurations for each cloud provider
  clusters = {
    aws = {
      provider     = "aws"
      region       = var.aws_region
      zones        = var.aws_availability_zones
      node_count   = var.node_count
      machine_type = "m5.large"
      k8s_version  = var.kubernetes_version
      vpc_cidr     = var.vpc_cidr.aws
      enabled      = true
    }
    azure = {
      provider     = "azure"
      region       = var.azure_location
      zones        = ["1", "2", "3"]  # Azure uses zone numbers
      node_count   = var.node_count
      machine_type = "Standard_D2s_v3"
      k8s_version  = var.kubernetes_version
      vpc_cidr     = var.vpc_cidr.azure
      enabled      = true
    }
    gcp = {
      provider     = "gcp"
      region       = var.gcp_region
      zones        = var.gcp_zones
      node_count   = var.node_count
      machine_type = "e2-standard-2"
      k8s_version  = var.kubernetes_version
      vpc_cidr     = var.vpc_cidr.gcp
      enabled      = true
    }
  }
  
  # Common tags for all resources
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = var.owner
  }
}

# AWS EKS Cluster with Karpenter
module "aws_eks" {
  source = "./modules/aws-eks"
  count  = local.clusters.aws.enabled ? 1 : 0
  
  cluster_name    = "${var.project_name}-${var.environment}-aws"
  cluster_version = local.clusters.aws.k8s_version
  
  vpc_cidr             = local.clusters.aws.vpc_cidr
  availability_zones   = local.clusters.aws.zones
  
  node_groups = {
    main = {
      instance_types = [local.clusters.aws.machine_type]
      min_size      = 1
      max_size      = 10
      desired_size  = local.clusters.aws.node_count
    }
  }
  
  # Enable Karpenter for autoscaling
  enable_karpenter = true
  
  # Enable Cilium CNI
  enable_cilium = var.enable_cilium
  
  # Security and compliance
  enable_opa_gatekeeper = var.enable_opa_gatekeeper
  enable_falco         = var.enable_falco
  enable_trivy         = var.enable_trivy
  
  # Observability
  enable_victoria_metrics = var.enable_victoria_metrics
  enable_grafana_tempo    = var.enable_grafana_tempo
  enable_vector          = var.enable_vector
  
  # Service mesh
  enable_linkerd = var.enable_linkerd
  
  tags = local.common_tags
}

# Azure AKS Cluster with Azure CNI
module "azure_aks" {
  source = "./modules/azure-aks"
  count  = local.clusters.azure.enabled ? 1 : 0
  
  cluster_name     = "${var.project_name}-${var.environment}-azure"
  location         = local.clusters.azure.region
  kubernetes_version = local.clusters.azure.k8s_version
  
  vnet_cidr        = local.clusters.azure.vpc_cidr
  
  default_node_pool = {
    name                = "default"
    vm_size            = local.clusters.azure.machine_type
    node_count         = local.clusters.azure.node_count
    availability_zones = local.clusters.azure.zones
  }
  
  # Enable Azure CNI (no Calico license issues)
  network_plugin = "azure"
  
  # Enable Cilium as secondary CNI
  enable_cilium = var.enable_cilium
  
  # Security and compliance
  enable_opa_gatekeeper = var.enable_opa_gatekeeper
  enable_falco         = var.enable_falco
  enable_trivy         = var.enable_trivy
  
  # Observability
  enable_victoria_metrics = var.enable_victoria_metrics
  enable_grafana_tempo    = var.enable_grafana_tempo
  enable_vector          = var.enable_vector
  
  # Service mesh
  enable_linkerd = var.enable_linkerd
  
  tags = local.common_tags
}

# Google GKE Cluster with Cosign
module "gcp_gke" {
  source = "./modules/gcp-gke"
  count  = local.clusters.gcp.enabled ? 1 : 0
  
  cluster_name = "${var.project_name}-${var.environment}-gcp"
  location     = local.clusters.gcp.region
  region       = var.gcp_region
  
  kubernetes_version = local.clusters.gcp.k8s_version
  
  vpc_cidr    = local.clusters.gcp.vpc_cidr
  zones       = local.clusters.gcp.zones
  
  node_pools = {
    default = {
      machine_type   = local.clusters.gcp.machine_type
      min_node_count = 1
      max_node_count = 10
      node_count     = local.clusters.gcp.node_count
    }
  }
  
  # Enable Cosign for image signing
  enable_cosign = true
  
  # Enable Cilium CNI
  enable_cilium = var.enable_cilium
  
  # Security and compliance
  enable_opa_gatekeeper = var.enable_opa_gatekeeper
  enable_falco         = var.enable_falco
  enable_trivy         = var.enable_trivy
  
  # Observability
  enable_victoria_metrics = var.enable_victoria_metrics
  enable_grafana_tempo    = var.enable_grafana_tempo
  enable_vector          = var.enable_vector
  
  # Service mesh
  enable_linkerd = var.enable_linkerd
  
  labels = local.common_tags
}

# Cross-Cloud Networking with Megaport
module "cross_cloud_networking" {
  source = "./modules/networking"
  
  project_name = var.project_name
  environment  = var.environment
  
  # VPC information from each cloud
  aws_vpc_id    = try(module.aws_eks[0].vpc_id, "")
  azure_vnet_id = try(module.azure_aks[0].vnet_id, "")
  gcp_vpc_id    = try(module.gcp_gke[0].vpc_id, "")
  
  # Megaport configuration
  megaport_access_key = var.megaport_access_key
  megaport_secret_key = var.megaport_secret_key
  
  depends_on = [
    module.aws_eks,
    module.azure_aks,
    module.gcp_gke
  ]
}

# Shared Monitoring VPC
module "monitoring_vpc" {
  source = "./modules/monitoring"
  
  project_name = var.project_name
  environment  = var.environment
  
  vpc_cidr = var.monitoring_vpc_cidr
  
  # VictoriaMetrics cluster configuration
  enable_victoria_metrics = var.enable_victoria_metrics
  
  # Grafana and Tempo configuration
  enable_grafana_tempo = var.enable_grafana_tempo
  
  # Vector configuration
  enable_vector = var.enable_vector
  
  # Connect to all Kubernetes clusters
  cluster_endpoints = {
    aws   = try(module.aws_eks[0].cluster_endpoint, "")
    azure = try(module.azure_aks[0].cluster_endpoint, "")
    gcp   = try(module.gcp_gke[0].cluster_endpoint, "")
  }
  
  depends_on = [
    module.aws_eks,
    module.azure_aks,
    module.gcp_gke
  ]
}

# Compliance and Security Auditing
module "compliance" {
  source = "./modules/compliance"
  
  project_name = var.project_name
  environment  = var.environment
  
  # CloudQuery configuration for SOC2 auditing
  enable_cloudquery = true
  
  # OPA policies for CIS benchmarks
  opa_policies_path = "./policies/opa"
  
  # Cluster information for auditing
  clusters = {
    for name, config in local.clusters : name => {
      provider = config.provider
      endpoint = try(
        name == "aws" ? module.aws_eks[0].cluster_endpoint :
        name == "azure" ? module.azure_aks[0].cluster_endpoint :
        name == "gcp" ? module.gcp_gke[0].cluster_endpoint : "",
        ""
      )
    } if config.enabled
  }
  
  depends_on = [
    module.aws_eks,
    module.azure_aks,
    module.gcp_gke
  ]
} 