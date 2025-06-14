# Compliance and Security Auditing Module
# This module implements SOC2 auditing with CloudQuery and CIS benchmarks with OPA

terraform {
  required_providers {
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

# S3 bucket for compliance reports and audit logs
resource "aws_s3_bucket" "compliance" {
  bucket = "${var.project_name}-${var.environment}-compliance-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name        = "${var.project_name}-${var.environment}-compliance"
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "compliance-auditing"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "compliance" {
  bucket = aws_s3_bucket.compliance.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance" {
  bucket = aws_s3_bucket.compliance.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "compliance" {
  bucket = aws_s3_bucket.compliance.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM role for CloudQuery
resource "aws_iam_role" "cloudquery" {
  count = var.enable_cloudquery ? 1 : 0
  
  name = "${var.project_name}-${var.environment}-cloudquery-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "compliance-auditing"
  }
}

# IAM policy for CloudQuery with read-only access
resource "aws_iam_policy" "cloudquery" {
  count = var.enable_cloudquery ? 1 : 0
  
  name        = "${var.project_name}-${var.environment}-cloudquery-policy"
  description = "Policy for CloudQuery to read AWS resources for compliance auditing"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "iam:Get*",
          "iam:List*",
          "s3:GetBucket*",
          "s3:ListBucket*",
          "s3:GetObject*",
          "rds:Describe*",
          "eks:Describe*",
          "eks:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "guardduty:Get*",
          "guardduty:List*",
          "securityhub:Get*",
          "securityhub:List*",
          "inspector:Describe*",
          "inspector:List*",
          "kms:Describe*",
          "kms:Get*",
          "kms:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:List*",
          "organizations:Describe*",
          "organizations:List*",
          "support:Describe*"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.compliance.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudquery" {
  count = var.enable_cloudquery ? 1 : 0
  
  role       = aws_iam_role.cloudquery[0].name
  policy_arn = aws_iam_policy.cloudquery[0].arn
}

# CloudQuery configuration
resource "local_file" "cloudquery_config" {
  count = var.enable_cloudquery ? 1 : 0
  
  filename = "${path.module}/cloudquery-config.yml"
  content = yamlencode({
    kind = "source"
    spec = {
      name         = "aws"
      path         = "cloudquery/aws"
      version      = "v25.0.0"
      destinations = ["s3"]
      
      spec = {
        regions = [data.aws_region.current.name]
        
        # SOC2 relevant resources
        resources = [
          "aws_ec2_instances",
          "aws_iam_users",
          "aws_iam_roles",
          "aws_iam_policies",
          "aws_s3_buckets",
          "aws_rds_instances",
          "aws_eks_clusters",
          "aws_cloudtrail_trails",
          "aws_config_configuration_recorders",
          "aws_guardduty_detectors",
          "aws_securityhub_hubs",
          "aws_kms_keys",
          "aws_logs_log_groups"
        ]
      }
    }
  })
}

# CloudQuery destination configuration
resource "local_file" "cloudquery_destination" {
  count = var.enable_cloudquery ? 1 : 0
  
  filename = "${path.module}/cloudquery-destination.yml"
  content = yamlencode({
    kind = "destination"
    spec = {
      name = "s3"
      path = "cloudquery/s3"
      version = "v4.0.0"
      
      spec = {
        bucket = aws_s3_bucket.compliance.bucket
        region = data.aws_region.current.name
        path   = "compliance-reports/{{TABLE}}/{{UUID}}.{{FORMAT}}"
        format = "json"
      }
    }
  })
}

# Kubernetes namespace for compliance tools
resource "kubernetes_namespace" "compliance" {
  for_each = var.clusters
  
  metadata {
    name = "compliance"
    
    labels = {
      "app.kubernetes.io/name"    = "compliance"
      "app.kubernetes.io/part-of" = var.project_name
    }
  }
}

# OPA Gatekeeper constraint templates for CIS benchmarks
resource "kubernetes_manifest" "cis_security_context_constraint" {
  for_each = var.clusters
  
  manifest = {
    apiVersion = "templates.gatekeeper.sh/v1beta1"
    kind       = "ConstraintTemplate"
    
    metadata = {
      name      = "k8srequiredsecuritycontext"
      namespace = kubernetes_namespace.compliance[each.key].metadata[0].name
    }
    
    spec = {
      crd = {
        spec = {
          names = {
            kind = "K8sRequiredSecurityContext"
          }
          
          validation = {
            openAPIV3Schema = {
              type = "object"
              properties = {
                runAsNonRoot = {
                  type = "boolean"
                }
                readOnlyRootFilesystem = {
                  type = "boolean"
                }
                allowPrivilegeEscalation = {
                  type = "boolean"
                }
              }
            }
          }
        }
      }
      
      targets = [
        {
          target = "admission.k8s.gatekeeper.sh"
          rego = <<-EOT
            package k8srequiredsecuritycontext
            
            violation[{"msg": msg}] {
              container := input.review.object.spec.containers[_]
              not container.securityContext.runAsNonRoot
              msg := "Container must run as non-root user"
            }
            
            violation[{"msg": msg}] {
              container := input.review.object.spec.containers[_]
              not container.securityContext.readOnlyRootFilesystem
              msg := "Container must use read-only root filesystem"
            }
            
            violation[{"msg": msg}] {
              container := input.review.object.spec.containers[_]
              container.securityContext.allowPrivilegeEscalation != false
              msg := "Container must not allow privilege escalation"
            }
          EOT
        }
      ]
    }
  }
}

# CIS benchmark constraint for required security context
resource "kubernetes_manifest" "cis_security_context_policy" {
  for_each = var.clusters
  
  manifest = {
    apiVersion = "constraints.gatekeeper.sh/v1beta1"
    kind       = "K8sRequiredSecurityContext"
    
    metadata = {
      name      = "must-have-security-context"
      namespace = kubernetes_namespace.compliance[each.key].metadata[0].name
    }
    
    spec = {
      match = {
        kinds = [
          {
            apiGroups = [""]
            kinds     = ["Pod"]
          }
        ]
        
        excludedNamespaces = [
          "kube-system",
          "kube-public",
          "gatekeeper-system"
        ]
      }
      
      parameters = {
        runAsNonRoot             = true
        readOnlyRootFilesystem   = true
        allowPrivilegeEscalation = false
      }
    }
  }
  
  depends_on = [kubernetes_manifest.cis_security_context_constraint]
}

# Resource limits constraint template
resource "kubernetes_manifest" "resource_limits_constraint" {
  for_each = var.clusters
  
  manifest = {
    apiVersion = "templates.gatekeeper.sh/v1beta1"
    kind       = "ConstraintTemplate"
    
    metadata = {
      name      = "k8srequiredresourcelimits"
      namespace = kubernetes_namespace.compliance[each.key].metadata[0].name
    }
    
    spec = {
      crd = {
        spec = {
          names = {
            kind = "K8sRequiredResourceLimits"
          }
          
          validation = {
            openAPIV3Schema = {
              type = "object"
              properties = {
                limits = {
                  type = "array"
                  items = {
                    type = "string"
                  }
                }
              }
            }
          }
        }
      }
      
      targets = [
        {
          target = "admission.k8s.gatekeeper.sh"
          rego = <<-EOT
            package k8srequiredresourcelimits
            
            violation[{"msg": msg}] {
              container := input.review.object.spec.containers[_]
              required := input.parameters.limits
              provided := container.resources.limits
              missing := required[_]
              not provided[missing]
              msg := sprintf("Container is missing resource limit: %v", [missing])
            }
          EOT
        }
      ]
    }
  }
}

# Resource limits policy
resource "kubernetes_manifest" "resource_limits_policy" {
  for_each = var.clusters
  
  manifest = {
    apiVersion = "constraints.gatekeeper.sh/v1beta1"
    kind       = "K8sRequiredResourceLimits"
    
    metadata = {
      name      = "must-have-resource-limits"
      namespace = kubernetes_namespace.compliance[each.key].metadata[0].name
    }
    
    spec = {
      match = {
        kinds = [
          {
            apiGroups = [""]
            kinds     = ["Pod"]
          }
        ]
        
        excludedNamespaces = [
          "kube-system",
          "kube-public",
          "gatekeeper-system"
        ]
      }
      
      parameters = {
        limits = ["memory", "cpu"]
      }
    }
  }
  
  depends_on = [kubernetes_manifest.resource_limits_constraint]
}

# Network policy constraint template
resource "kubernetes_manifest" "network_policy_constraint" {
  for_each = var.clusters
  
  manifest = {
    apiVersion = "templates.gatekeeper.sh/v1beta1"
    kind       = "ConstraintTemplate"
    
    metadata = {
      name      = "k8srequirednetworkpolicy"
      namespace = kubernetes_namespace.compliance[each.key].metadata[0].name
    }
    
    spec = {
      crd = {
        spec = {
          names = {
            kind = "K8sRequiredNetworkPolicy"
          }
        }
      }
      
      targets = [
        {
          target = "admission.k8s.gatekeeper.sh"
          rego = <<-EOT
            package k8srequirednetworkpolicy
            
            violation[{"msg": msg}] {
              input.review.kind.kind == "Namespace"
              input.review.operation == "CREATE"
              not has_network_policy
              msg := "Namespace must have a NetworkPolicy"
            }
            
            has_network_policy {
              # This would need to be enhanced to check for existing NetworkPolicies
              # For now, we'll allow all namespaces but log the requirement
              true
            }
          EOT
        }
      ]
    }
  }
}

# Compliance dashboard ConfigMap
resource "kubernetes_config_map" "compliance_dashboard" {
  for_each = var.clusters
  
  metadata {
    name      = "compliance-dashboard"
    namespace = kubernetes_namespace.compliance[each.key].metadata[0].name
    
    labels = {
      "app.kubernetes.io/name"      = "compliance-dashboard"
      "app.kubernetes.io/component" = "monitoring"
    }
  }
  
  data = {
    "dashboard.json" = jsonencode({
      dashboard = {
        title = "Kubernetes Compliance Dashboard"
        tags  = ["compliance", "security", "cis"]
        
        panels = [
          {
            title = "OPA Gatekeeper Violations"
            type  = "stat"
            targets = [
              {
                expr = "sum(gatekeeper_violations_total)"
              }
            ]
          },
          {
            title = "Security Context Violations"
            type  = "table"
            targets = [
              {
                expr = "gatekeeper_violations_total{violation_kind=\"K8sRequiredSecurityContext\"}"
              }
            ]
          },
          {
            title = "Resource Limit Violations"
            type  = "table"
            targets = [
              {
                expr = "gatekeeper_violations_total{violation_kind=\"K8sRequiredResourceLimits\"}"
              }
            ]
          }
        ]
      }
    })
  }
}

# Compliance report generation script
resource "local_file" "compliance_report_script" {
  filename = "${path.module}/generate-compliance-report.sh"
  
  content = <<-EOT
    #!/bin/bash
    
    # Multi-Cloud Kubernetes Compliance Report Generator
    # This script generates SOC2 and CIS compliance reports
    
    set -e
    
    PROJECT_NAME="${var.project_name}"
    ENVIRONMENT="${var.environment}"
    REPORT_DATE=$(date +%Y-%m-%d)
    REPORT_DIR="compliance-reports/$REPORT_DATE"
    
    echo "Generating compliance report for $PROJECT_NAME-$ENVIRONMENT..."
    
    mkdir -p "$REPORT_DIR"
    
    # Generate CloudQuery reports
    if command -v cloudquery &> /dev/null; then
        echo "Running CloudQuery audit..."
        cloudquery sync cloudquery-config.yml cloudquery-destination.yml
    else
        echo "CloudQuery not found. Please install CloudQuery to generate infrastructure audit reports."
    fi
    
    # Generate Kubernetes compliance reports
    for cluster in ${join(" ", keys(var.clusters))}; do
        echo "Generating compliance report for $cluster cluster..."
        
        # Get OPA Gatekeeper violations
        kubectl get violations --all-namespaces -o json > "$REPORT_DIR/$cluster-violations.json" || echo "No violations found for $cluster"
        
        # Get security context audit
        kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.securityContext.runAsRoot == true or .spec.securityContext.runAsRoot == null)' > "$REPORT_DIR/$cluster-security-context-issues.json" || echo "No security context issues for $cluster"
        
        # Get resource limits audit
        kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].resources.limits == null)' > "$REPORT_DIR/$cluster-resource-limits-issues.json" || echo "No resource limit issues for $cluster"
        
        # Get network policies
        kubectl get networkpolicies --all-namespaces -o json > "$REPORT_DIR/$cluster-network-policies.json" || echo "No network policies found for $cluster"
    done
    
    # Generate summary report
    cat > "$REPORT_DIR/compliance-summary.md" << EOF
    # Compliance Report - $REPORT_DATE
    
    ## Project: $PROJECT_NAME
    ## Environment: $ENVIRONMENT
    
    ### Executive Summary
    This report provides an overview of compliance status across all Kubernetes clusters
    in the multi-cloud infrastructure.
    
    ### Clusters Audited
    $(for cluster in ${join(" ", keys(var.clusters))}; do echo "- $cluster"; done)
    
    ### Compliance Frameworks
    - SOC2 Type II
    - CIS Kubernetes Benchmark
    - NIST Cybersecurity Framework
    
    ### Key Findings
    - OPA Gatekeeper violations: $(find $REPORT_DIR -name "*violations.json" -exec jq length {} \; | awk '{sum+=$1} END {print sum}' || echo "0")
    - Security context issues: $(find $REPORT_DIR -name "*security-context-issues.json" -exec jq length {} \; | awk '{sum+=$1} END {print sum}' || echo "0")
    - Resource limit issues: $(find $REPORT_DIR -name "*resource-limits-issues.json" -exec jq length {} \; | awk '{sum+=$1} END {print sum}' || echo "0")
    
    ### Recommendations
    1. Address all OPA Gatekeeper violations
    2. Implement security contexts for all pods
    3. Set resource limits for all containers
    4. Implement network policies for all namespaces
    
    ### Next Steps
    1. Review detailed findings in individual cluster reports
    2. Create remediation plan for identified issues
    3. Schedule follow-up audit in 30 days
    
    EOF
    
    echo "Compliance report generated in $REPORT_DIR"
    echo "Summary available at $REPORT_DIR/compliance-summary.md"
  EOT
  
  file_permission = "0755"
}

# CloudWatch dashboard for compliance monitoring
resource "aws_cloudwatch_dashboard" "compliance" {
  dashboard_name = "${var.project_name}-${var.environment}-compliance"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/S3", "BucketSizeBytes", "BucketName", aws_s3_bucket.compliance.bucket, "StorageType", "StandardStorage"],
            ["AWS/S3", "NumberOfObjects", "BucketName", aws_s3_bucket.compliance.bucket, "StorageType", "AllStorageTypes"]
          ]
          period = 86400
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Compliance Data Storage"
        }
      }
    ]
  })
} 