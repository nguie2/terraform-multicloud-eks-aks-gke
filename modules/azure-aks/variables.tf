# Azure AKS Module Variables

variable "cluster_name" {
  description = "Name of the AKS cluster"
  type        = string
}

variable "location" {
  description = "Azure location for the cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version for the AKS cluster"
  type        = string
  default     = "1.28"
}

variable "vnet_cidr" {
  description = "CIDR block for the VNet"
  type        = string
  default     = "10.1.0.0/16"
}

variable "default_node_pool" {
  description = "Default node pool configuration"
  type = object({
    name                = string
    vm_size            = string
    node_count         = number
    availability_zones = list(string)
  })
  default = {
    name                = "default"
    vm_size            = "Standard_D2s_v3"
    node_count         = 3
    availability_zones = ["1", "2", "3"]
  }
}

variable "network_plugin" {
  description = "Network plugin to use (azure or kubenet)"
  type        = string
  default     = "azure"
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