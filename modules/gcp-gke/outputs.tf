# GCP GKE Module Outputs

output "cluster_id" {
  description = "GKE cluster ID"
  value       = google_container_cluster.main.id
}

output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.main.name
}

output "cluster_endpoint" {
  description = "Endpoint for GKE control plane"
  value       = google_container_cluster.main.endpoint
}

output "cluster_version" {
  description = "The Kubernetes version for the GKE cluster"
  value       = google_container_cluster.main.master_version
}

output "location" {
  description = "Location of the cluster"
  value       = google_container_cluster.main.location
}

output "vpc_id" {
  description = "ID of the VPC where the cluster is deployed"
  value       = google_compute_network.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = var.vpc_cidr
}

output "subnet_id" {
  description = "ID of the subnet where nodes are deployed"
  value       = google_compute_subnetwork.nodes.id
}

output "ca_certificate" {
  description = "Cluster CA certificate (base64 encoded)"
  value       = google_container_cluster.main.master_auth[0].cluster_ca_certificate
}

output "service_account_email" {
  description = "Email of the service account used by nodes"
  value       = google_service_account.gke_nodes.email
}

output "node_pools" {
  description = "Node pool information"
  value = {
    for k, v in google_container_node_pool.main : k => {
      name         = v.name
      machine_type = v.node_config[0].machine_type
      node_count   = v.initial_node_count
      min_count    = v.autoscaling[0].min_node_count
      max_count    = v.autoscaling[0].max_node_count
    }
  }
}

output "workload_identity_pool" {
  description = "Workload Identity pool"
  value       = google_container_cluster.main.workload_identity_config[0].workload_pool
}

output "binary_authorization_enabled" {
  description = "Whether Binary Authorization is enabled"
  value       = var.enable_cosign
}

output "cosign_attestor_name" {
  description = "Name of the Cosign attestor"
  value       = var.enable_cosign ? google_binary_authorization_attestor.cosign[0].name : null
} 