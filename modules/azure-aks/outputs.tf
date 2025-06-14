# Azure AKS Module Outputs

output "cluster_id" {
  description = "AKS cluster ID"
  value       = azurerm_kubernetes_cluster.main.id
}

output "cluster_name" {
  description = "AKS cluster name"
  value       = azurerm_kubernetes_cluster.main.name
}

output "cluster_endpoint" {
  description = "Endpoint for AKS control plane"
  value       = azurerm_kubernetes_cluster.main.kube_config.0.host
}

output "cluster_version" {
  description = "The Kubernetes version for the AKS cluster"
  value       = azurerm_kubernetes_cluster.main.kubernetes_version
}

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "ID of the resource group"
  value       = azurerm_resource_group.main.id
}

output "vnet_id" {
  description = "ID of the VNet where the cluster is deployed"
  value       = azurerm_virtual_network.main.id
}

output "vnet_cidr" {
  description = "CIDR block of the VNet"
  value       = azurerm_virtual_network.main.address_space[0]
}

output "node_subnet_id" {
  description = "ID of the node subnet"
  value       = azurerm_subnet.aks_nodes.id
}

output "pod_subnet_id" {
  description = "ID of the pod subnet"
  value       = azurerm_subnet.aks_pods.id
}

output "kube_config" {
  description = "Kubernetes configuration"
  value       = azurerm_kubernetes_cluster.main.kube_config
  sensitive   = true
}

output "kube_config_raw" {
  description = "Raw Kubernetes configuration"
  value       = azurerm_kubernetes_cluster.main.kube_config_raw
  sensitive   = true
}

output "identity" {
  description = "AKS cluster identity"
  value       = azurerm_kubernetes_cluster.main.identity
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.aks.id
} 