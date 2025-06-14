# GCP GKE Module Variables

variable "cluster_name" {
  description = "Name of the GKE cluster"
  type        = string
}

variable "location" {
  description = "Location for the GKE cluster (region or zone)"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "zones" {
  description = "List of zones for the cluster"
  type        = list(string)
  default     = []
}

variable "kubernetes_version" {
  description = "Kubernetes version for the GKE cluster"
  type        = string
  default     = "1.28"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.2.0.0/16"
}

variable "node_pools" {
  description = "Map of GKE node pool configurations"
  type = map(object({
    machine_type     = string
    min_node_count   = number
    max_node_count   = number
    node_count       = number
    taints          = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
  }))
  default = {
    default = {
      machine_type   = "e2-standard-2"
      min_node_count = 1
      max_node_count = 10
      node_count     = 3
      taints         = []
    }
  }
}

variable "enable_cosign" {
  description = "Enable Cosign for image signing and verification"
  type        = bool
  default     = true
}

variable "cosign_public_key" {
  description = "Cosign public key for image verification"
  type        = string
  default     = ""
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

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default     = {}
} 