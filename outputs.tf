# Multi-Cloud Infrastructure Outputs
# This file exposes important information from all deployed clusters

# AWS EKS Outputs
output "aws_cluster_info" {
  description = "AWS EKS cluster information"
  value = local.clusters.aws.enabled && length(module.aws_eks) > 0 ? {
    cluster_name     = module.aws_eks[0].cluster_name
    cluster_endpoint = module.aws_eks[0].cluster_endpoint
    cluster_version  = module.aws_eks[0].cluster_version
    vpc_id          = module.aws_eks[0].vpc_id
    vpc_cidr        = module.aws_eks[0].vpc_cidr_block
    node_groups     = keys(module.aws_eks[0].node_groups)
    oidc_issuer_url = module.aws_eks[0].cluster_oidc_issuer_url
  } : null
}

# Azure AKS Outputs
output "azure_cluster_info" {
  description = "Azure AKS cluster information"
  value = local.clusters.azure.enabled && length(module.azure_aks) > 0 ? {
    cluster_name     = module.azure_aks[0].cluster_name
    cluster_endpoint = module.azure_aks[0].cluster_endpoint
    cluster_version  = module.azure_aks[0].cluster_version
    resource_group   = module.azure_aks[0].resource_group_name
    vnet_id         = module.azure_aks[0].vnet_id
    vnet_cidr       = module.azure_aks[0].vnet_cidr
  } : null
}

# GCP GKE Outputs
output "gcp_cluster_info" {
  description = "GCP GKE cluster information"
  value = local.clusters.gcp.enabled && length(module.gcp_gke) > 0 ? {
    cluster_name     = module.gcp_gke[0].cluster_name
    cluster_endpoint = module.gcp_gke[0].cluster_endpoint
    cluster_version  = module.gcp_gke[0].cluster_version
    vpc_id          = module.gcp_gke[0].vpc_id
    vpc_cidr        = module.gcp_gke[0].vpc_cidr
    location        = module.gcp_gke[0].location
  } : null
}

# Cluster Summary
output "cluster_summary" {
  description = "Summary of all deployed clusters"
  value = {
    total_clusters = length([
      for cluster in [
        var.enable_aws_cluster ? "aws" : null,
        var.enable_azure_cluster ? "azure" : null,
        var.enable_gcp_cluster ? "gcp" : null
      ] : cluster if cluster != null
    ])
    
    clusters = {
      for provider, config in local.clusters : provider => {
        enabled = config.enabled
        name = config.enabled ? (
          provider == "aws" ? try(module.aws_eks[0].cluster_name, "") :
          provider == "azure" ? try(module.azure_aks[0].cluster_name, "") :
          provider == "gcp" ? try(module.gcp_gke[0].cluster_name, "") : ""
        ) : ""
        endpoint = config.enabled ? (
          provider == "aws" ? try(module.aws_eks[0].cluster_endpoint, "") :
          provider == "azure" ? try(module.azure_aks[0].cluster_endpoint, "") :
          provider == "gcp" ? try(module.gcp_gke[0].cluster_endpoint, "") : ""
        ) : ""
      } if config.enabled
    }
  }
}

# Networking Information
output "networking_info" {
  description = "Cross-cloud networking information"
  value = {
    vpc_cidrs = {
      aws   = var.vpc_cidr.aws
      azure = var.vpc_cidr.azure
      gcp   = var.vpc_cidr.gcp
    }
    monitoring_vpc_cidr = var.monitoring_vpc_cidr
    cross_cloud_connectivity = "Megaport"
  }
}

# Security and Compliance
output "security_features" {
  description = "Enabled security and compliance features"
  value = {
    opa_gatekeeper    = var.enable_opa_gatekeeper
    falco            = var.enable_falco
    trivy            = var.enable_trivy
    cilium_cni       = var.enable_cilium
    linkerd_mesh     = var.enable_linkerd
    policy_enforcement = var.enable_opa_gatekeeper
  }
}

# Observability Stack
output "observability_stack" {
  description = "Deployed observability components"
  value = {
    victoria_metrics = var.enable_victoria_metrics
    grafana_tempo   = var.enable_grafana_tempo
    vector_logging  = var.enable_vector
    monitoring_endpoints = {
      victoria_metrics = var.enable_victoria_metrics ? "http://victoria-metrics.monitoring.svc.cluster.local:8428" : null
      grafana         = var.enable_victoria_metrics ? "http://grafana.monitoring.svc.cluster.local:3000" : null
      tempo           = var.enable_grafana_tempo ? "http://tempo.tracing.svc.cluster.local:3100" : null
    }
  }
}

# Kubectl Connection Commands
output "kubectl_commands" {
  description = "Commands to connect to each cluster"
  value = {
    aws = local.clusters.aws.enabled && length(module.aws_eks) > 0 ? 
      "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.aws_eks[0].cluster_name}" : null
    
    azure = local.clusters.azure.enabled && length(module.azure_aks) > 0 ? 
      "az aks get-credentials --resource-group ${module.azure_aks[0].resource_group_name} --name ${module.azure_aks[0].cluster_name}" : null
    
    gcp = local.clusters.gcp.enabled && length(module.gcp_gke) > 0 ? 
      "gcloud container clusters get-credentials ${module.gcp_gke[0].cluster_name} --region ${var.gcp_region} --project ${var.gcp_project_id}" : null
  }
}

# Service Mesh Information
output "service_mesh_info" {
  description = "Service mesh configuration and endpoints"
  value = var.enable_linkerd ? {
    mesh_type = "Linkerd"
    version   = "2.14.1"
    dashboards = {
      linkerd_viz = "http://linkerd.multicloud-k8s.local"
      grafana     = "http://grafana.linkerd-viz.svc.cluster.local:3000"
      jaeger      = "http://jaeger.linkerd-jaeger.svc.cluster.local:16686"
    }
    multicluster_enabled = true
  } : null
}

# Compliance and Auditing
output "compliance_info" {
  description = "Compliance and auditing configuration"
  value = {
    cis_benchmarks = var.enable_opa_gatekeeper
    soc2_auditing  = true  # CloudQuery enabled
    policy_as_code = var.enable_opa_gatekeeper
    runtime_security = var.enable_falco
    vulnerability_scanning = var.enable_trivy
    
    audit_endpoints = {
      gatekeeper_violations = var.enable_opa_gatekeeper ? "kubectl get violations --all-namespaces" : null
      falco_alerts = var.enable_falco ? "kubectl logs -n falco -l app=falco" : null
      trivy_reports = var.enable_trivy ? "kubectl get vulnerabilityreports --all-namespaces" : null
    }
  }
}

# Cost Optimization Features
output "cost_optimization" {
  description = "Cost optimization features enabled"
  value = {
    aws_karpenter = local.clusters.aws.enabled ? true : false
    azure_autoscaler = local.clusters.azure.enabled ? true : false
    gcp_autoscaler = local.clusters.gcp.enabled ? true : false
    spot_instances = true
    resource_quotas = var.enable_opa_gatekeeper
  }
}

# Deployment Status
output "deployment_status" {
  description = "Overall deployment status and next steps"
  value = {
    infrastructure_deployed = true
    clusters_ready = {
      aws   = local.clusters.aws.enabled && length(module.aws_eks) > 0
      azure = local.clusters.azure.enabled && length(module.azure_aks) > 0
      gcp   = local.clusters.gcp.enabled && length(module.gcp_gke) > 0
    }
    
    next_steps = [
      "Run cluster validation: python scripts/validate_cluster_parity.py",
      "Configure kubectl contexts for all clusters",
      "Deploy sample applications to test service mesh",
      "Set up monitoring dashboards",
      "Configure alerting rules",
      "Test cross-cloud connectivity",
      "Run compliance scans"
    ]
    
    validation_command = "python scripts/validate_cluster_parity.py --config cluster_config.yaml --output validation_report.txt"
  }
}

# Environment Information
output "environment_info" {
  description = "Environment and project information"
  value = {
    project_name = var.project_name
    environment  = var.environment
    owner       = var.owner
    terraform_version = ">= 1.5.0"
    deployment_time = timestamp()
    
    documentation = {
      readme = "README.md"
      architecture_diagrams = "docs/architecture/"
      runbooks = "docs/runbooks/"
      troubleshooting = "docs/troubleshooting.md"
    }
  }
} 