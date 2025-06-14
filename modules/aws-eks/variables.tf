# AWS EKS Module Variables

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.28"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "node_groups" {
  description = "Map of EKS node group configurations"
  type = map(object({
    instance_types = list(string)
    min_size      = number
    max_size      = number
    desired_size  = number
  }))
  default = {
    main = {
      instance_types = ["m5.large"]
      min_size      = 1
      max_size      = 10
      desired_size  = 3
    }
  }
}

variable "enable_karpenter" {
  description = "Enable Karpenter for node autoscaling"
  type        = bool
  default     = true
}

variable "enable_cilium" {
  description = "Enable Cilium CNI"
  type        = bool
  default     = true
}

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

variable "enable_linkerd" {
  description = "Enable Linkerd service mesh"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
} 