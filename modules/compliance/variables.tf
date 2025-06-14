# Compliance Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "enable_cloudquery" {
  description = "Enable CloudQuery for SOC2 auditing"
  type        = bool
  default     = true
}

variable "opa_policies_path" {
  description = "Path to OPA policies directory"
  type        = string
  default     = "./policies/opa"
}

variable "clusters" {
  description = "Map of cluster configurations for compliance auditing"
  type = map(object({
    provider = string
    endpoint = string
  }))
  default = {}
} 