# Monitoring Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the monitoring VPC"
  type        = string
  default     = "10.100.0.0/16"
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

variable "cluster_endpoints" {
  description = "Map of cluster endpoints to connect to"
  type        = map(string)
  default     = {}
} 