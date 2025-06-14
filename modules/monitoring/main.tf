# Shared Monitoring VPC Module
# This module creates a dedicated monitoring infrastructure with VictoriaMetrics

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
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
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Monitoring VPC
resource "aws_vpc" "monitoring" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-vpc"
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "monitoring"
  }
}

# Internet Gateway for monitoring VPC
resource "aws_internet_gateway" "monitoring" {
  vpc_id = aws_vpc.monitoring.id
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-igw"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Public subnets for monitoring infrastructure
resource "aws_subnet" "monitoring_public" {
  count = 3
  
  vpc_id                  = aws_vpc.monitoring.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-public-${count.index + 1}"
    Project     = var.project_name
    Environment = var.environment
    Type        = "public"
  }
}

# Private subnets for monitoring workloads
resource "aws_subnet" "monitoring_private" {
  count = 3
  
  vpc_id            = aws_vpc.monitoring.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-private-${count.index + 1}"
    Project     = var.project_name
    Environment = var.environment
    Type        = "private"
  }
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# NAT Gateways for private subnets
resource "aws_eip" "monitoring_nat" {
  count = 3
  
  domain = "vpc"
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-nat-eip-${count.index + 1}"
    Project     = var.project_name
    Environment = var.environment
  }
  
  depends_on = [aws_internet_gateway.monitoring]
}

resource "aws_nat_gateway" "monitoring" {
  count = 3
  
  allocation_id = aws_eip.monitoring_nat[count.index].id
  subnet_id     = aws_subnet.monitoring_public[count.index].id
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-nat-${count.index + 1}"
    Project     = var.project_name
    Environment = var.environment
  }
  
  depends_on = [aws_internet_gateway.monitoring]
}

# Route tables
resource "aws_route_table" "monitoring_public" {
  vpc_id = aws_vpc.monitoring.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.monitoring.id
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-public-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route_table" "monitoring_private" {
  count = 3
  
  vpc_id = aws_vpc.monitoring.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.monitoring[count.index].id
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-private-rt-${count.index + 1}"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Route table associations
resource "aws_route_table_association" "monitoring_public" {
  count = 3
  
  subnet_id      = aws_subnet.monitoring_public[count.index].id
  route_table_id = aws_route_table.monitoring_public.id
}

resource "aws_route_table_association" "monitoring_private" {
  count = 3
  
  subnet_id      = aws_subnet.monitoring_private[count.index].id
  route_table_id = aws_route_table.monitoring_private[count.index].id
}

# Security group for monitoring infrastructure
resource "aws_security_group" "monitoring" {
  name_prefix = "${var.project_name}-${var.environment}-monitoring-"
  vpc_id      = aws_vpc.monitoring.id
  
  # Allow HTTP traffic for dashboards
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }
  
  # Allow HTTPS traffic for dashboards
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }
  
  # Allow Grafana
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Grafana"
  }
  
  # Allow VictoriaMetrics
  ingress {
    from_port   = 8428
    to_port     = 8428
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "VictoriaMetrics"
  }
  
  # Allow Tempo
  ingress {
    from_port   = 3100
    to_port     = 3100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Tempo"
  }
  
  # Allow Vector
  ingress {
    from_port   = 8686
    to_port     = 8686
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Vector"
  }
  
  # Allow SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "SSH"
  }
  
  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

# EKS cluster for monitoring workloads
resource "aws_eks_cluster" "monitoring" {
  name     = "${var.project_name}-${var.environment}-monitoring"
  role_arn = aws_iam_role.monitoring_cluster.arn
  version  = "1.28"
  
  vpc_config {
    subnet_ids              = concat(aws_subnet.monitoring_public[*].id, aws_subnet.monitoring_private[*].id)
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
    security_group_ids      = [aws_security_group.monitoring.id]
  }
  
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring"
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "monitoring"
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.monitoring_cluster_policy,
    aws_iam_role_policy_attachment.monitoring_vpc_resource_controller,
  ]
}

# IAM role for EKS cluster
resource "aws_iam_role" "monitoring_cluster" {
  name = "${var.project_name}-${var.environment}-monitoring-cluster-role"
  
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "monitoring_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.monitoring_cluster.name
}

resource "aws_iam_role_policy_attachment" "monitoring_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.monitoring_cluster.name
}

# EKS Node Group
resource "aws_eks_node_group" "monitoring" {
  cluster_name    = aws_eks_cluster.monitoring.name
  node_group_name = "monitoring-nodes"
  node_role_arn   = aws_iam_role.monitoring_nodes.arn
  subnet_ids      = aws_subnet.monitoring_private[*].id
  
  capacity_type  = "ON_DEMAND"
  instance_types = ["m5.large"]
  
  scaling_config {
    desired_size = 3
    max_size     = 6
    min_size     = 1
  }
  
  update_config {
    max_unavailable = 1
  }
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-monitoring-nodes"
    Project     = var.project_name
    Environment = var.environment
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.monitoring_worker_node_policy,
    aws_iam_role_policy_attachment.monitoring_cni_policy,
    aws_iam_role_policy_attachment.monitoring_registry_policy,
  ]
}

# IAM role for EKS node group
resource "aws_iam_role" "monitoring_nodes" {
  name = "${var.project_name}-${var.environment}-monitoring-nodes-role"
  
  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "monitoring_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.monitoring_nodes.name
}

resource "aws_iam_role_policy_attachment" "monitoring_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.monitoring_nodes.name
}

resource "aws_iam_role_policy_attachment" "monitoring_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.monitoring_nodes.name
}

# Kubernetes provider configuration
data "aws_eks_cluster_auth" "monitoring" {
  name = aws_eks_cluster.monitoring.name
}

provider "kubernetes" {
  alias = "monitoring"
  
  host                   = aws_eks_cluster.monitoring.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.monitoring.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.monitoring.token
}

provider "helm" {
  alias = "monitoring"
  
  kubernetes {
    host                   = aws_eks_cluster.monitoring.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.monitoring.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.monitoring.token
  }
}

# Install VictoriaMetrics cluster
resource "helm_release" "victoria_metrics" {
  count = var.enable_victoria_metrics ? 1 : 0
  
  provider = helm.monitoring
  
  name       = "victoria-metrics"
  repository = "https://victoriametrics.github.io/helm-charts/"
  chart      = "victoria-metrics-k8s-stack"
  version    = "0.18.15"
  namespace  = "monitoring"
  
  create_namespace = true
  
  values = [
    yamlencode({
      victoria-metrics-operator = {
        enabled = true
      }
      
      vmsingle = {
        enabled = true
        spec = {
          retentionPeriod = "12"
          storage = {
            accessModes = ["ReadWriteOnce"]
            resources = {
              requests = {
                storage = "50Gi"
              }
            }
          }
        }
      }
      
      vmcluster = {
        enabled = false
      }
      
      alertmanager = {
        enabled = true
        spec = {
          storage = {
            volumeClaimTemplate = {
              spec = {
                accessModes = ["ReadWriteOnce"]
                resources = {
                  requests = {
                    storage = "10Gi"
                  }
                }
              }
            }
          }
        }
      }
      
      grafana = {
        enabled = true
        sidecar = {
          datasources = {
            enabled = true
          }
          dashboards = {
            enabled = true
          }
        }
        persistence = {
          enabled = true
          size = "10Gi"
        }
        adminPassword = "admin123"  # Change in production
      }
    })
  ]
  
  depends_on = [aws_eks_node_group.monitoring]
}

# Install Grafana Tempo for distributed tracing
resource "helm_release" "tempo" {
  count = var.enable_grafana_tempo ? 1 : 0
  
  provider = helm.monitoring
  
  name       = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  version    = "1.7.1"
  namespace  = "tracing"
  
  create_namespace = true
  
  values = [
    yamlencode({
      tempo = {
        storage = {
          trace = {
            backend = "s3"
            s3 = {
              bucket = aws_s3_bucket.tempo_traces[0].bucket
              region = data.aws_region.current.name
            }
          }
        }
      }
      
      persistence = {
        enabled = true
        size = "10Gi"
      }
    })
  ]
  
  depends_on = [aws_eks_node_group.monitoring]
}

# S3 bucket for Tempo traces
resource "aws_s3_bucket" "tempo_traces" {
  count = var.enable_grafana_tempo ? 1 : 0
  
  bucket = "${var.project_name}-${var.environment}-tempo-traces-${random_id.bucket_suffix[0].hex}"
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-tempo-traces"
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "tracing"
  }
}

resource "random_id" "bucket_suffix" {
  count = var.enable_grafana_tempo ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "tempo_traces" {
  count = var.enable_grafana_tempo ? 1 : 0
  
  bucket = aws_s3_bucket.tempo_traces[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tempo_traces" {
  count = var.enable_grafana_tempo ? 1 : 0
  
  bucket = aws_s3_bucket.tempo_traces[0].id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Install Vector for log collection
resource "helm_release" "vector" {
  count = var.enable_vector ? 1 : 0
  
  provider = helm.monitoring
  
  name       = "vector"
  repository = "https://helm.vector.dev"
  chart      = "vector"
  version    = "0.25.0"
  namespace  = "logging"
  
  create_namespace = true
  
  values = [
    yamlencode({
      role = "Agent"
      
      customConfig = {
        sources = {
          kubernetes_logs = {
            type = "kubernetes_logs"
          }
        }
        
        transforms = {
          parse_logs = {
            type = "remap"
            inputs = ["kubernetes_logs"]
            source = '''
              .timestamp = parse_timestamp(.timestamp, "%Y-%m-%dT%H:%M:%S%.fZ") ?? now()
              .level = .level ?? "info"
            '''
          }
        }
        
        sinks = {
          victoria_metrics = {
            type = "prometheus_exporter"
            inputs = ["parse_logs"]
            address = "0.0.0.0:9090"
          }
          
          console = {
            type = "console"
            inputs = ["parse_logs"]
            encoding = {
              codec = "json"
            }
          }
        }
      }
    })
  ]
  
  depends_on = [aws_eks_node_group.monitoring]
} 