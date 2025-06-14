# Development Environment Configuration
include "root" {
  path = find_in_parent_folders()
}

# Environment-specific inputs
inputs = {
  environment = "dev"
  
  # Reduced resources for development
  node_count = 2
  
  # Development-specific networking
  vpc_cidr = {
    aws   = "10.10.0.0/16"
    azure = "10.11.0.0/16"
    gcp   = "10.12.0.0/16"
  }
  
  monitoring_vpc_cidr = "10.110.0.0/16"
  
  # Enable all features for testing
  enable_opa_gatekeeper    = true
  enable_falco            = true
  enable_trivy            = true
  enable_victoria_metrics = true
  enable_grafana_tempo    = true
  enable_vector           = true
  enable_linkerd          = true
  enable_cilium           = true
} 