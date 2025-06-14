# Production Environment Configuration
include "root" {
  path = find_in_parent_folders()
}

# Environment-specific inputs
inputs = {
  environment = "prod"
  
  # Production-grade resources
  node_count = 5
  
  # Production networking with larger address spaces
  vpc_cidr = {
    aws   = "10.0.0.0/16"
    azure = "10.1.0.0/16"
    gcp   = "10.2.0.0/16"
  }
  
  monitoring_vpc_cidr = "10.100.0.0/16"
  
  # All security and observability features enabled
  enable_opa_gatekeeper    = true
  enable_falco            = true
  enable_trivy            = true
  enable_victoria_metrics = true
  enable_grafana_tempo    = true
  enable_vector           = true
  enable_linkerd          = true
  enable_cilium           = true
} 