# GCP GKE Module with Cosign and Cilium
# This module creates a GKE cluster with all required components

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
}

# Data sources
data "google_client_config" "default" {}
data "google_project" "project" {}

# VPC Network
resource "google_compute_network" "main" {
  name                    = "${var.cluster_name}-vpc"
  auto_create_subnetworks = false
  
  description = "VPC for ${var.cluster_name} GKE cluster"
}

# Subnet for GKE nodes
resource "google_compute_subnetwork" "nodes" {
  name          = "${var.cluster_name}-nodes-subnet"
  ip_cidr_range = cidrsubnet(var.vpc_cidr, 8, 1)
  region        = var.region
  network       = google_compute_network.main.id
  
  # Secondary IP ranges for pods and services
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = cidrsubnet(var.vpc_cidr, 4, 1)
  }
  
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = cidrsubnet(var.vpc_cidr, 8, 2)
  }
  
  # Enable private Google access
  private_ip_google_access = true
}

# Cloud Router for NAT
resource "google_compute_router" "main" {
  name    = "${var.cluster_name}-router"
  region  = var.region
  network = google_compute_network.main.id
}

# Cloud NAT for outbound internet access
resource "google_compute_router_nat" "main" {
  name                               = "${var.cluster_name}-nat"
  router                            = google_compute_router.main.name
  region                            = var.region
  nat_ip_allocate_option            = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall rules
resource "google_compute_firewall" "allow_internal" {
  name    = "${var.cluster_name}-allow-internal"
  network = google_compute_network.main.name
  
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
  
  source_ranges = [var.vpc_cidr]
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.cluster_name}-allow-ssh"
  network = google_compute_network.main.name
  
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  
  source_ranges = ["35.235.240.0/20"] # Google Cloud IAP range
  target_tags   = ["gke-node"]
}

# Service Account for GKE nodes
resource "google_service_account" "gke_nodes" {
  account_id   = "${var.cluster_name}-nodes"
  display_name = "GKE Nodes Service Account for ${var.cluster_name}"
}

# IAM bindings for the service account
resource "google_project_iam_member" "gke_nodes_logging" {
  project = data.google_project.project.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_monitoring" {
  project = data.google_project.project.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_monitoring_viewer" {
  project = data.google_project.project.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_nodes_registry" {
  project = data.google_project.project.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# GKE Cluster
resource "google_container_cluster" "main" {
  name     = var.cluster_name
  location = var.location
  
  # Use regional cluster for high availability
  node_locations = var.zones
  
  # Kubernetes version
  min_master_version = var.kubernetes_version
  
  # Network configuration
  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.nodes.id
  
  # IP allocation policy for VPC-native cluster
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }
  
  # Private cluster configuration
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = cidrsubnet(var.vpc_cidr, 8, 0)
    
    master_global_access_config {
      enabled = true
    }
  }
  
  # Network policy
  network_policy {
    enabled  = true
    provider = "CALICO"
  }
  
  # Addons configuration
  addons_config {
    http_load_balancing {
      disabled = false
    }
    
    horizontal_pod_autoscaling {
      disabled = false
    }
    
    network_policy_config {
      disabled = false
    }
    
    dns_cache_config {
      enabled = true
    }
    
    gcp_filestore_csi_driver_config {
      enabled = true
    }
    
    gcs_fuse_csi_driver_config {
      enabled = true
    }
  }
  
  # Workload Identity
  workload_identity_config {
    workload_pool = "${data.google_project.project.project_id}.svc.id.goog"
  }
  
  # Binary Authorization (for Cosign)
  binary_authorization {
    evaluation_mode = var.enable_cosign ? "PROJECT_SINGLETON_POLICY_ENFORCE" : "DISABLED"
  }
  
  # Security configuration
  security_posture_config {
    mode               = "BASIC"
    vulnerability_mode = "VULNERABILITY_BASIC"
  }
  
  # Logging and monitoring
  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "API_SERVER"
    ]
  }
  
  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "API_SERVER",
      "CONTROLLER_MANAGER",
      "SCHEDULER"
    ]
    
    managed_prometheus {
      enabled = true
    }
    
    advanced_datapath_observability_config {
      enable_metrics = true
      enable_relay   = true
    }
  }
  
  # Maintenance policy
  maintenance_policy {
    recurring_window {
      start_time = "2023-01-01T02:00:00Z"
      end_time   = "2023-01-01T06:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SA"
    }
  }
  
  # Remove default node pool
  remove_default_node_pool = true
  initial_node_count       = 1
  
  # Resource labels
  resource_labels = var.labels
}

# Node pools
resource "google_container_node_pool" "main" {
  for_each = var.node_pools
  
  name       = each.key
  location   = var.location
  cluster    = google_container_cluster.main.name
  
  # Node count configuration
  initial_node_count = each.value.node_count
  
  # Autoscaling
  autoscaling {
    min_node_count = each.value.min_node_count
    max_node_count = each.value.max_node_count
  }
  
  # Node configuration
  node_config {
    preemptible  = false
    machine_type = each.value.machine_type
    disk_size_gb = 50
    disk_type    = "pd-ssd"
    image_type   = "COS_CONTAINERD"
    
    # Service account
    service_account = google_service_account.gke_nodes.email
    
    # OAuth scopes
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    
    # Security configuration
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    
    # Workload metadata configuration
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
    
    # Node taints for specific workloads
    dynamic "taint" {
      for_each = lookup(each.value, "taints", [])
      content {
        key    = taint.value.key
        value  = taint.value.value
        effect = taint.value.effect
      }
    }
    
    # Node labels
    labels = merge(var.labels, {
      "node-pool" = each.key
    })
    
    tags = ["gke-node", "${var.cluster_name}-node"]
  }
  
  # Upgrade settings
  upgrade_settings {
    strategy        = "SURGE"
    max_surge       = 1
    max_unavailable = 0
  }
  
  # Management
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# Binary Authorization Policy (for Cosign)
resource "google_binary_authorization_policy" "main" {
  count = var.enable_cosign ? 1 : 0
  
  admission_whitelist_patterns {
    name_pattern = "gcr.io/my-project/*"
  }
  
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    
    require_attestations_by = [
      google_binary_authorization_attestor.cosign[0].name
    ]
  }
  
  cluster_admission_rules {
    cluster                = google_container_cluster.main.id
    evaluation_mode        = "REQUIRE_ATTESTATION"
    enforcement_mode       = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    
    require_attestations_by = [
      google_binary_authorization_attestor.cosign[0].name
    ]
  }
}

# Cosign Attestor
resource "google_binary_authorization_attestor" "cosign" {
  count = var.enable_cosign ? 1 : 0
  
  name = "${var.cluster_name}-cosign-attestor"
  
  attestation_authority_note {
    note_reference = google_container_analysis_note.cosign[0].name
    
    public_keys {
      id = "cosign-key"
      
      pkix_public_key {
        public_key_pem      = var.cosign_public_key
        signature_algorithm = "ECDSA_P256_SHA256"
      }
    }
  }
}

# Container Analysis Note for Cosign
resource "google_container_analysis_note" "cosign" {
  count = var.enable_cosign ? 1 : 0
  
  name = "${var.cluster_name}-cosign-note"
  
  attestation_authority {
    hint {
      human_readable_name = "Cosign Attestor for ${var.cluster_name}"
    }
  }
}

# Install Cilium CNI
resource "helm_release" "cilium" {
  count = var.enable_cilium ? 1 : 0
  
  name       = "cilium"
  repository = "https://helm.cilium.io/"
  chart      = "cilium"
  version    = "1.14.4"
  namespace  = "kube-system"
  
  set {
    name  = "gke.enabled"
    value = "true"
  }
  
  set {
    name  = "ipam.mode"
    value = "kubernetes"
  }
  
  set {
    name  = "tunnel"
    value = "disabled"
  }
  
  set {
    name  = "enableIPv4Masquerade"
    value = "false"
  }
  
  set {
    name  = "enableIdentityMark"
    value = "false"
  }
  
  depends_on = [google_container_node_pool.main]
}

# Install OPA Gatekeeper
resource "helm_release" "gatekeeper" {
  count = var.enable_opa_gatekeeper ? 1 : 0
  
  name       = "gatekeeper"
  repository = "https://open-policy-agent.github.io/gatekeeper/charts"
  chart      = "gatekeeper"
  version    = "3.14.0"
  namespace  = "gatekeeper-system"
  
  create_namespace = true
  
  depends_on = [google_container_node_pool.main]
}

# Install Falco
resource "helm_release" "falco" {
  count = var.enable_falco ? 1 : 0
  
  name       = "falco"
  repository = "https://falcosecurity.github.io/charts"
  chart      = "falco"
  version    = "3.8.4"
  namespace  = "falco"
  
  create_namespace = true
  
  set {
    name  = "driver.kind"
    value = "ebpf"
  }
  
  depends_on = [google_container_node_pool.main]
}

# Install Trivy Operator
resource "helm_release" "trivy" {
  count = var.enable_trivy ? 1 : 0
  
  name       = "trivy-operator"
  repository = "https://aquasecurity.github.io/helm-charts/"
  chart      = "trivy-operator"
  version    = "0.18.4"
  namespace  = "trivy-system"
  
  create_namespace = true
  
  depends_on = [google_container_node_pool.main]
}

# Install VictoriaMetrics
resource "helm_release" "victoria_metrics" {
  count = var.enable_victoria_metrics ? 1 : 0
  
  name       = "victoria-metrics"
  repository = "https://victoriametrics.github.io/helm-charts/"
  chart      = "victoria-metrics-k8s-stack"
  version    = "0.18.15"
  namespace  = "monitoring"
  
  create_namespace = true
  
  depends_on = [google_container_node_pool.main]
}

# Install Grafana Tempo
resource "helm_release" "tempo" {
  count = var.enable_grafana_tempo ? 1 : 0
  
  name       = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  version    = "1.7.1"
  namespace  = "tracing"
  
  create_namespace = true
  
  depends_on = [google_container_node_pool.main]
}

# Install Vector
resource "helm_release" "vector" {
  count = var.enable_vector ? 1 : 0
  
  name       = "vector"
  repository = "https://helm.vector.dev"
  chart      = "vector"
  version    = "0.25.0"
  namespace  = "logging"
  
  create_namespace = true
  
  depends_on = [google_container_node_pool.main]
}

# Install Linkerd
resource "helm_release" "linkerd_crds" {
  count = var.enable_linkerd ? 1 : 0
  
  name       = "linkerd-crds"
  repository = "https://helm.linkerd.io/stable"
  chart      = "linkerd-crds"
  version    = "1.6.1"
  namespace  = "linkerd"
  
  create_namespace = true
  
  depends_on = [google_container_node_pool.main]
}

resource "helm_release" "linkerd_control_plane" {
  count = var.enable_linkerd ? 1 : 0
  
  name       = "linkerd-control-plane"
  repository = "https://helm.linkerd.io/stable"
  chart      = "linkerd-control-plane"
  version    = "1.12.4"
  namespace  = "linkerd"
  
  depends_on = [helm_release.linkerd_crds]
} 