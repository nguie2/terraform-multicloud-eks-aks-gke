# Azure AKS Module with Azure CNI and Cilium
# This module creates an AKS cluster with all required components

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

# Data sources
data "azurerm_client_config" "current" {}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "${var.cluster_name}-rg"
  location = var.location
  
  tags = var.tags
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "${var.cluster_name}-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  
  tags = var.tags
}

# Subnet for AKS nodes
resource "azurerm_subnet" "aks_nodes" {
  name                 = "${var.cluster_name}-nodes-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 1)]
}

# Subnet for pods (Azure CNI)
resource "azurerm_subnet" "aks_pods" {
  name                 = "${var.cluster_name}-pods-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 4, 1)]
  
  delegation {
    name = "aks-delegation"
    
    service_delegation {
      name    = "Microsoft.ContainerService/managedClusters"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Network Security Group
resource "azurerm_network_security_group" "aks" {
  name                = "${var.cluster_name}-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  
  tags = var.tags
}

# Associate NSG with subnet
resource "azurerm_subnet_network_security_group_association" "aks_nodes" {
  subnet_id                 = azurerm_subnet.aks_nodes.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# Log Analytics Workspace for AKS monitoring
resource "azurerm_log_analytics_workspace" "aks" {
  name                = "${var.cluster_name}-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  
  tags = var.tags
}

# User Assigned Identity for AKS
resource "azurerm_user_assigned_identity" "aks" {
  name                = "${var.cluster_name}-identity"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  
  tags = var.tags
}

# Role assignment for AKS identity
resource "azurerm_role_assignment" "aks_network_contributor" {
  scope                = azurerm_virtual_network.main.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_user_assigned_identity.aks.principal_id
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version
  
  # Use system-assigned identity
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }
  
  # Default node pool
  default_node_pool {
    name                = var.default_node_pool.name
    node_count          = var.default_node_pool.node_count
    vm_size             = var.default_node_pool.vm_size
    availability_zones  = var.default_node_pool.availability_zones
    vnet_subnet_id      = azurerm_subnet.aks_nodes.id
    pod_subnet_id       = azurerm_subnet.aks_pods.id
    
    # Enable auto-scaling
    enable_auto_scaling = true
    min_count          = 1
    max_count          = 10
    
    # Node configuration
    os_disk_size_gb = 50
    os_disk_type    = "Managed"
    
    tags = var.tags
  }
  
  # Network profile with Azure CNI
  network_profile {
    network_plugin     = var.network_plugin
    network_policy     = "azure"
    dns_service_ip     = cidrhost(cidrsubnet(var.vnet_cidr, 8, 0), 10)
    service_cidr       = cidrsubnet(var.vnet_cidr, 8, 0)
    pod_cidr           = null  # Not used with Azure CNI
  }
  
  # Enable Azure Monitor
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.aks.id
  }
  
  # Enable Azure Policy
  azure_policy_enabled = true
  
  # Enable HTTP application routing (for development)
  http_application_routing_enabled = false
  
  # Enable role-based access control
  role_based_access_control_enabled = true
  
  # Azure AD integration
  azure_active_directory_role_based_access_control {
    managed            = true
    azure_rbac_enabled = true
  }
  
  tags = var.tags
  
  depends_on = [
    azurerm_role_assignment.aks_network_contributor
  ]
}

# Install Cilium CNI (as secondary CNI for eBPF features)
resource "helm_release" "cilium" {
  count = var.enable_cilium ? 1 : 0
  
  name       = "cilium"
  repository = "https://helm.cilium.io/"
  chart      = "cilium"
  version    = "1.14.4"
  namespace  = "kube-system"
  
  set {
    name  = "azure.enabled"
    value = "true"
  }
  
  set {
    name  = "azure.resourceGroup"
    value = azurerm_resource_group.main.name
  }
  
  set {
    name  = "tunnel"
    value = "disabled"
  }
  
  set {
    name  = "ipam.mode"
    value = "azure"
  }
  
  set {
    name  = "enableIPv4Masquerade"
    value = "false"
  }
  
  set {
    name  = "enableIdentityMark"
    value = "false"
  }
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install OPA Gatekeeper
resource "helm_release" "gatekeeper" {
  count = var.enable_opa_gatekeeper ? 1 : 0
  
  name       = "gatekeeper"
  repository = "https://open-policy-agent.github.io/gatekeeper/charts"
  chart      = "gatekeeper"
  version    = "3.14.0"
  namespace  = "gatekeeper-system"
  
  create_namespace = true
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install Falco
resource "helm_release" "falco" {
  count = var.enable_falco ? 1 : 0
  
  name       = "falco"
  repository = "https://falcosecurity.github.io/charts"
  chart      = "falco"
  version    = "3.8.4"
  namespace  = "falco"
  
  create_namespace = true
  
  set {
    name  = "driver.kind"
    value = "ebpf"
  }
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install Trivy Operator
resource "helm_release" "trivy" {
  count = var.enable_trivy ? 1 : 0
  
  name       = "trivy-operator"
  repository = "https://aquasecurity.github.io/helm-charts/"
  chart      = "trivy-operator"
  version    = "0.18.4"
  namespace  = "trivy-system"
  
  create_namespace = true
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install VictoriaMetrics
resource "helm_release" "victoria_metrics" {
  count = var.enable_victoria_metrics ? 1 : 0
  
  name       = "victoria-metrics"
  repository = "https://victoriametrics.github.io/helm-charts/"
  chart      = "victoria-metrics-k8s-stack"
  version    = "0.18.15"
  namespace  = "monitoring"
  
  create_namespace = true
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install Grafana Tempo
resource "helm_release" "tempo" {
  count = var.enable_grafana_tempo ? 1 : 0
  
  name       = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  version    = "1.7.1"
  namespace  = "tracing"
  
  create_namespace = true
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install Vector
resource "helm_release" "vector" {
  count = var.enable_vector ? 1 : 0
  
  name       = "vector"
  repository = "https://helm.vector.dev"
  chart      = "vector"
  version    = "0.25.0"
  namespace  = "logging"
  
  create_namespace = true
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

# Install Linkerd
resource "helm_release" "linkerd_crds" {
  count = var.enable_linkerd ? 1 : 0
  
  name       = "linkerd-crds"
  repository = "https://helm.linkerd.io/stable"
  chart      = "linkerd-crds"
  version    = "1.6.1"
  namespace  = "linkerd"
  
  create_namespace = true
  
  depends_on = [azurerm_kubernetes_cluster.main]
}

resource "helm_release" "linkerd_control_plane" {
  count = var.enable_linkerd ? 1 : 0
  
  name       = "linkerd-control-plane"
  repository = "https://helm.linkerd.io/stable"
  chart      = "linkerd-control-plane"
  version    = "1.12.4"
  namespace  = "linkerd"
  
  depends_on = [helm_release.linkerd_crds]
} 