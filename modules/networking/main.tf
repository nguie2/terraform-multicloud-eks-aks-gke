# Cross-Cloud Networking Module with Megaport
# This module creates cross-cloud connectivity between AWS, Azure, and GCP

terraform {
  required_providers {
    megaport = {
      source  = "megaport/megaport"
      version = "~> 0.4"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Data sources for existing VPCs
data "aws_vpc" "main" {
  count = var.aws_vpc_id != "" ? 1 : 0
  id    = var.aws_vpc_id
}

data "azurerm_virtual_network" "main" {
  count               = var.azure_vnet_id != "" ? 1 : 0
  name                = split("/", var.azure_vnet_id)[8]
  resource_group_name = split("/", var.azure_vnet_id)[4]
}

data "google_compute_network" "main" {
  count = var.gcp_vpc_id != "" ? 1 : 0
  name  = split("/", var.gcp_vpc_id)[4]
}

# Megaport Port for cross-cloud connectivity
resource "megaport_port" "main" {
  port_name   = "${var.project_name}-${var.environment}-port"
  port_speed  = 1000
  location_id = var.megaport_location_id
  
  marketplace_visibility = false
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "cross-cloud-connectivity"
  }
}

# AWS Direct Connect Gateway
resource "aws_dx_gateway" "main" {
  count = var.aws_vpc_id != "" ? 1 : 0
  name  = "${var.project_name}-${var.environment}-dx-gw"
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-dx-gw"
    Project     = var.project_name
    Environment = var.environment
  }
}

# AWS Virtual Interface
resource "megaport_aws_connection" "main" {
  count = var.aws_vpc_id != "" ? 1 : 0
  
  connection_name = "${var.project_name}-${var.environment}-aws"
  port_id        = megaport_port.main.id
  vlan           = 100
  
  # AWS connection details
  aws_account_id     = var.aws_account_id
  aws_connection_id  = aws_dx_gateway.main[0].id
  customer_asn       = 65000
  amazon_asn         = 64512
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
    Cloud       = "aws"
  }
}

# Azure ExpressRoute Circuit
resource "azurerm_express_route_circuit" "main" {
  count = var.azure_vnet_id != "" ? 1 : 0
  
  name                = "${var.project_name}-${var.environment}-er"
  resource_group_name = var.azure_resource_group_name
  location           = var.azure_location
  
  service_provider_name = "Megaport"
  peering_location     = var.megaport_peering_location
  bandwidth_in_mbps    = 1000
  
  sku {
    tier   = "Standard"
    family = "MeteredData"
  }
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
    Cloud       = "azure"
  }
}

# Azure connection via Megaport
resource "megaport_azure_connection" "main" {
  count = var.azure_vnet_id != "" ? 1 : 0
  
  connection_name = "${var.project_name}-${var.environment}-azure"
  port_id        = megaport_port.main.id
  vlan           = 200
  
  # Azure connection details
  service_key = azurerm_express_route_circuit.main[0].service_key
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
    Cloud       = "azure"
  }
}

# Google Cloud Interconnect
resource "google_compute_interconnect_attachment" "main" {
  count = var.gcp_vpc_id != "" ? 1 : 0
  
  name         = "${var.project_name}-${var.environment}-interconnect"
  type         = "PARTNER"
  router       = google_compute_router.interconnect[0].id
  region       = var.gcp_region
  
  edge_availability_domain = "AVAILABILITY_DOMAIN_1"
  
  labels = {
    project     = var.project_name
    environment = var.environment
    cloud       = "gcp"
  }
}

# Google Cloud Router for Interconnect
resource "google_compute_router" "interconnect" {
  count = var.gcp_vpc_id != "" ? 1 : 0
  
  name    = "${var.project_name}-${var.environment}-interconnect-router"
  region  = var.gcp_region
  network = var.gcp_vpc_id
  
  bgp {
    asn = 65001
  }
}

# GCP connection via Megaport
resource "megaport_gcp_connection" "main" {
  count = var.gcp_vpc_id != "" ? 1 : 0
  
  connection_name = "${var.project_name}-${var.environment}-gcp"
  port_id        = megaport_port.main.id
  vlan           = 300
  
  # GCP connection details
  pairing_key = google_compute_interconnect_attachment.main[0].pairing_key
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
    Cloud       = "gcp"
  }
}

# VPC Peering between clouds (logical representation)
# Note: Actual routing will be handled by BGP through Megaport

# AWS Route Table entries for cross-cloud traffic
resource "aws_route" "to_azure" {
  count = var.aws_vpc_id != "" && var.azure_vnet_id != "" ? 1 : 0
  
  route_table_id         = data.aws_vpc.main[0].main_route_table_id
  destination_cidr_block = var.azure_vnet_cidr
  gateway_id            = aws_dx_gateway.main[0].id
}

resource "aws_route" "to_gcp" {
  count = var.aws_vpc_id != "" && var.gcp_vpc_id != "" ? 1 : 0
  
  route_table_id         = data.aws_vpc.main[0].main_route_table_id
  destination_cidr_block = var.gcp_vpc_cidr
  gateway_id            = aws_dx_gateway.main[0].id
}

# Azure Route Table for cross-cloud traffic
resource "azurerm_route_table" "cross_cloud" {
  count = var.azure_vnet_id != "" ? 1 : 0
  
  name                = "${var.project_name}-${var.environment}-cross-cloud-rt"
  location           = var.azure_location
  resource_group_name = var.azure_resource_group_name
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "azurerm_route" "to_aws" {
  count = var.azure_vnet_id != "" && var.aws_vpc_id != "" ? 1 : 0
  
  name                = "to-aws"
  resource_group_name = var.azure_resource_group_name
  route_table_name    = azurerm_route_table.cross_cloud[0].name
  address_prefix      = var.aws_vpc_cidr
  next_hop_type       = "VirtualNetworkGateway"
}

resource "azurerm_route" "to_gcp" {
  count = var.azure_vnet_id != "" && var.gcp_vpc_id != "" ? 1 : 0
  
  name                = "to-gcp"
  resource_group_name = var.azure_resource_group_name
  route_table_name    = azurerm_route_table.cross_cloud[0].name
  address_prefix      = var.gcp_vpc_cidr
  next_hop_type       = "VirtualNetworkGateway"
}

# GCP Routes for cross-cloud traffic
resource "google_compute_route" "to_aws" {
  count = var.gcp_vpc_id != "" && var.aws_vpc_id != "" ? 1 : 0
  
  name         = "${var.project_name}-${var.environment}-to-aws"
  dest_range   = var.aws_vpc_cidr
  network      = var.gcp_vpc_id
  next_hop_gateway = "default-internet-gateway"
  priority     = 1000
  
  tags = ["cross-cloud", "aws"]
}

resource "google_compute_route" "to_azure" {
  count = var.gcp_vpc_id != "" && var.azure_vnet_id != "" ? 1 : 0
  
  name         = "${var.project_name}-${var.environment}-to-azure"
  dest_range   = var.azure_vnet_cidr
  network      = var.gcp_vpc_id
  next_hop_gateway = "default-internet-gateway"
  priority     = 1000
  
  tags = ["cross-cloud", "azure"]
}

# Network Security Groups and Firewall Rules for cross-cloud communication

# AWS Security Group for cross-cloud traffic
resource "aws_security_group" "cross_cloud" {
  count = var.aws_vpc_id != "" ? 1 : 0
  
  name_prefix = "${var.project_name}-${var.environment}-cross-cloud-"
  vpc_id      = var.aws_vpc_id
  
  # Allow traffic from Azure
  dynamic "ingress" {
    for_each = var.azure_vnet_id != "" ? [1] : []
    content {
      from_port   = 0
      to_port     = 65535
      protocol    = "tcp"
      cidr_blocks = [var.azure_vnet_cidr]
      description = "Allow traffic from Azure"
    }
  }
  
  # Allow traffic from GCP
  dynamic "ingress" {
    for_each = var.gcp_vpc_id != "" ? [1] : []
    content {
      from_port   = 0
      to_port     = 65535
      protocol    = "tcp"
      cidr_blocks = [var.gcp_vpc_cidr]
      description = "Allow traffic from GCP"
    }
  }
  
  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-cross-cloud-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Azure Network Security Group for cross-cloud traffic
resource "azurerm_network_security_group" "cross_cloud" {
  count = var.azure_vnet_id != "" ? 1 : 0
  
  name                = "${var.project_name}-${var.environment}-cross-cloud-nsg"
  location           = var.azure_location
  resource_group_name = var.azure_resource_group_name
  
  # Allow traffic from AWS
  dynamic "security_rule" {
    for_each = var.aws_vpc_id != "" ? [1] : []
    content {
      name                       = "AllowFromAWS"
      priority                   = 100
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = var.aws_vpc_cidr
      destination_address_prefix = "*"
    }
  }
  
  # Allow traffic from GCP
  dynamic "security_rule" {
    for_each = var.gcp_vpc_id != "" ? [1] : []
    content {
      name                       = "AllowFromGCP"
      priority                   = 110
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = var.gcp_vpc_cidr
      destination_address_prefix = "*"
    }
  }
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# GCP Firewall Rules for cross-cloud traffic
resource "google_compute_firewall" "allow_cross_cloud" {
  count = var.gcp_vpc_id != "" ? 1 : 0
  
  name    = "${var.project_name}-${var.environment}-allow-cross-cloud"
  network = var.gcp_vpc_id
  
  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
  
  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }
  
  allow {
    protocol = "icmp"
  }
  
  source_ranges = compact([
    var.aws_vpc_id != "" ? var.aws_vpc_cidr : "",
    var.azure_vnet_id != "" ? var.azure_vnet_cidr : ""
  ])
  
  target_tags = ["cross-cloud"]
} 