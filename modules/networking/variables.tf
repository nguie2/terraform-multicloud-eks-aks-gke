# Networking Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

# VPC/VNet IDs from each cloud
variable "aws_vpc_id" {
  description = "AWS VPC ID"
  type        = string
  default     = ""
}

variable "azure_vnet_id" {
  description = "Azure VNet ID"
  type        = string
  default     = ""
}

variable "gcp_vpc_id" {
  description = "GCP VPC ID"
  type        = string
  default     = ""
}

# VPC/VNet CIDR blocks
variable "aws_vpc_cidr" {
  description = "AWS VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "azure_vnet_cidr" {
  description = "Azure VNet CIDR block"
  type        = string
  default     = "10.1.0.0/16"
}

variable "gcp_vpc_cidr" {
  description = "GCP VPC CIDR block"
  type        = string
  default     = "10.2.0.0/16"
}

# AWS specific variables
variable "aws_account_id" {
  description = "AWS Account ID"
  type        = string
  default     = ""
}

# Azure specific variables
variable "azure_resource_group_name" {
  description = "Azure Resource Group name"
  type        = string
  default     = ""
}

variable "azure_location" {
  description = "Azure location"
  type        = string
  default     = "West US 2"
}

# GCP specific variables
variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-west1"
}

# Megaport configuration
variable "megaport_access_key" {
  description = "Megaport API access key"
  type        = string
  sensitive   = true
}

variable "megaport_secret_key" {
  description = "Megaport API secret key"
  type        = string
  sensitive   = true
}

variable "megaport_location_id" {
  description = "Megaport location ID for the port"
  type        = number
  default     = 1  # Default to a common location, should be overridden
}

variable "megaport_peering_location" {
  description = "Megaport peering location for Azure ExpressRoute"
  type        = string
  default     = "Los Angeles"
} 