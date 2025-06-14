# AWS EKS Module Outputs

output "cluster_id" {
  description = "EKS cluster ID"
  value       = aws_eks_cluster.main.id
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_version" {
  description = "The Kubernetes version for the EKS cluster"
  value       = aws_eks_cluster.main.version
}

output "cluster_arn" {
  description = "The Amazon Resource Name (ARN) of the cluster"
  value       = aws_eks_cluster.main.arn
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = aws_eks_cluster.main.certificate_authority[0].data
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster OIDC Issuer"
  value       = try(aws_eks_cluster.main.identity[0].oidc[0].issuer, null)
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}

output "vpc_id" {
  description = "ID of the VPC where the cluster is deployed"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "node_groups" {
  description = "EKS node groups"
  value = {
    for k, v in aws_eks_node_group.main : k => {
      arn           = v.arn
      status        = v.status
      capacity_type = v.capacity_type
      instance_types = v.instance_types
      ami_type      = v.ami_type
      node_role_arn = v.node_role_arn
      subnet_ids    = v.subnet_ids
      
      scaling_config = v.scaling_config
      update_config  = v.update_config
    }
  }
}

output "node_security_group_id" {
  description = "ID of the EKS node shared security group"
  value       = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}

output "cluster_primary_security_group_id" {
  description = "The cluster primary security group ID created by EKS"
  value       = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}

output "cloudwatch_log_group_name" {
  description = "Name of cloudwatch log group created"
  value       = aws_cloudwatch_log_group.eks.name
}

output "cloudwatch_log_group_arn" {
  description = "Arn of cloudwatch log group created"
  value       = aws_cloudwatch_log_group.eks.arn
}

# Karpenter outputs
output "karpenter_irsa_arn" {
  description = "Karpenter IRSA ARN"
  value       = var.enable_karpenter ? aws_iam_role.karpenter[0].arn : null
}

output "karpenter_instance_profile_name" {
  description = "Karpenter instance profile name"
  value       = var.enable_karpenter ? aws_iam_instance_profile.karpenter[0].name : null
}

output "karpenter_node_instance_profile_name" {
  description = "Karpenter node instance profile name"
  value       = var.enable_karpenter ? aws_iam_instance_profile.karpenter[0].name : null
}

# Security and observability outputs
output "security_features_enabled" {
  description = "Security features enabled on the cluster"
  value = {
    opa_gatekeeper    = var.enable_opa_gatekeeper
    falco            = var.enable_falco
    trivy            = var.enable_trivy
    cilium_cni       = var.enable_cilium
    linkerd_mesh     = var.enable_linkerd
  }
}

output "observability_features_enabled" {
  description = "Observability features enabled on the cluster"
  value = {
    victoria_metrics = var.enable_victoria_metrics
    grafana_tempo   = var.enable_grafana_tempo
    vector_logging  = var.enable_vector
  }
} 