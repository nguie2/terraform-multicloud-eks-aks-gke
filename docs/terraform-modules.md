# Terraform Module Documentation

## Overview

This document provides comprehensive documentation for all Terraform modules used in the multi-cloud Kubernetes infrastructure project. Each module is designed to be reusable, configurable, and follows Terraform best practices.

## Module Architecture

```
modules/
├── aws-eks/           # AWS EKS cluster with Karpenter
├── azure-aks/         # Azure AKS cluster with Azure CNI
├── gcp-gke/           # Google GKE cluster with Cosign
├── networking/        # Cross-cloud networking with Megaport
├── monitoring/        # Shared monitoring infrastructure
└── compliance/        # Security and compliance tools
```

## AWS EKS Module

### Purpose
Deploys a production-ready Amazon EKS cluster with advanced features including Karpenter for node provisioning, Cilium for networking, and comprehensive security tooling.

### Inputs

| Variable | Type | Description | Default | Required |
|----------|------|-------------|---------|----------|
| `cluster_name` | string | Name of the EKS cluster | - | yes |
| `cluster_version` | string | Kubernetes version | "1.28" | no |
| `region` | string | AWS region | - | yes |
| `vpc_cidr` | string | VPC CIDR block | "10.0.0.0/16" | no |
| `node_groups` | map(object) | Node group configurations | {} | no |
| `enable_karpenter` | bool | Enable Karpenter autoscaler | true | no |
| `enable_cilium` | bool | Enable Cilium CNI | true | no |
| `enable_linkerd` | bool | Enable Linkerd service mesh | true | no |
| `enable_security_tools` | bool | Enable security tools (Falco, Trivy, OPA) | true | no |

### Outputs

| Output | Description |
|--------|-------------|
| `cluster_id` | EKS cluster ID |
| `cluster_arn` | EKS cluster ARN |
| `cluster_endpoint` | EKS cluster API endpoint |
| `cluster_security_group_id` | Cluster security group ID |
| `node_groups` | Node group information |
| `karpenter_node_instance_profile` | Karpenter node instance profile |

### Usage Example

```hcl
module "aws_eks" {
  source = "./modules/aws-eks"
  
  cluster_name    = "production-eks"
  cluster_version = "1.28"
  region         = "us-west-2"
  vpc_cidr       = "10.0.0.0/16"
  
  node_groups = {
    general = {
      desired_size = 3
      max_size     = 10
      min_size     = 1
      instance_types = ["m5.large"]
    }
  }
  
  enable_karpenter = true
  enable_cilium    = true
  enable_linkerd   = true
}
```

### Security Features

- **Pod Security Standards**: Enforced at cluster level
- **Network Policies**: Cilium-based micro-segmentation
- **RBAC**: Fine-grained access control
- **Encryption**: EBS volumes and secrets encrypted at rest
- **Audit Logging**: CloudWatch integration for security monitoring

## Azure AKS Module

### Purpose
Deploys a production-ready Azure Kubernetes Service cluster with Azure CNI, advanced networking, and integrated security features.

### Inputs

| Variable | Type | Description | Default | Required |
|----------|------|-------------|---------|----------|
| `cluster_name` | string | Name of the AKS cluster | - | yes |
| `resource_group_name` | string | Azure resource group name | - | yes |
| `location` | string | Azure region | - | yes |
| `kubernetes_version` | string | Kubernetes version | "1.28" | no |
| `node_count` | number | Initial node count | 3 | no |
| `node_vm_size` | string | VM size for nodes | "Standard_D2s_v3" | no |
| `enable_azure_cni` | bool | Enable Azure CNI | true | no |
| `enable_cilium` | bool | Enable Cilium CNI overlay | true | no |
| `enable_linkerd` | bool | Enable Linkerd service mesh | true | no |

### Outputs

| Output | Description |
|--------|-------------|
| `cluster_id` | AKS cluster ID |
| `cluster_name` | AKS cluster name |
| `cluster_fqdn` | AKS cluster FQDN |
| `node_resource_group` | Node resource group name |
| `kubelet_identity` | Kubelet managed identity |

### Usage Example

```hcl
module "azure_aks" {
  source = "./modules/azure-aks"
  
  cluster_name        = "production-aks"
  resource_group_name = "rg-kubernetes-prod"
  location           = "East US"
  kubernetes_version = "1.28"
  
  node_count   = 3
  node_vm_size = "Standard_D4s_v3"
  
  enable_azure_cni = true
  enable_cilium    = true
  enable_linkerd   = true
}
```

## GCP GKE Module

### Purpose
Deploys a production-ready Google Kubernetes Engine cluster with advanced security features including Binary Authorization, Cosign integration, and Workload Identity.

### Inputs

| Variable | Type | Description | Default | Required |
|----------|------|-------------|---------|----------|
| `cluster_name` | string | Name of the GKE cluster | - | yes |
| `project_id` | string | GCP project ID | - | yes |
| `region` | string | GCP region | - | yes |
| `kubernetes_version` | string | Kubernetes version | "1.28" | no |
| `initial_node_count` | number | Initial node count per zone | 1 | no |
| `node_machine_type` | string | Machine type for nodes | "e2-medium" | no |
| `enable_binary_authorization` | bool | Enable Binary Authorization | true | no |
| `enable_cosign` | bool | Enable Cosign for image signing | true | no |
| `enable_workload_identity` | bool | Enable Workload Identity | true | no |

### Outputs

| Output | Description |
|--------|-------------|
| `cluster_id` | GKE cluster ID |
| `cluster_name` | GKE cluster name |
| `cluster_location` | GKE cluster location |
| `cluster_ca_certificate` | Cluster CA certificate |
| `service_account` | Cluster service account |

### Usage Example

```hcl
module "gcp_gke" {
  source = "./modules/gcp-gke"
  
  cluster_name       = "production-gke"
  project_id        = "my-project-id"
  region            = "us-west1"
  kubernetes_version = "1.28"
  
  initial_node_count = 2
  node_machine_type  = "e2-standard-4"
  
  enable_binary_authorization = true
  enable_cosign              = true
  enable_workload_identity   = true
}
```

## Networking Module

### Purpose
Establishes cross-cloud networking connectivity using Megaport Cloud Router for private, high-performance connections between cloud providers.

### Inputs

| Variable | Type | Description | Default | Required |
|----------|------|-------------|---------|----------|
| `megaport_username` | string | Megaport portal username | - | yes |
| `megaport_password` | string | Megaport portal password | - | yes |
| `aws_vpc_id` | string | AWS VPC ID to connect | - | yes |
| `azure_vnet_id` | string | Azure VNet ID to connect | - | yes |
| `gcp_vpc_id` | string | GCP VPC ID to connect | - | yes |
| `connection_name` | string | Name for the connection | - | yes |

### Outputs

| Output | Description |
|--------|-------------|
| `mcr_id` | Megaport Cloud Router ID |
| `aws_connection_id` | AWS connection ID |
| `azure_connection_id` | Azure connection ID |
| `gcp_connection_id` | GCP connection ID |

## Monitoring Module

### Purpose
Deploys a centralized monitoring infrastructure using VictoriaMetrics, Grafana, Tempo, and Vector for comprehensive observability across all clusters.

### Inputs

| Variable | Type | Description | Default | Required |
|----------|------|-------------|---------|----------|
| `monitoring_vpc_cidr` | string | CIDR for monitoring VPC | "10.100.0.0/16" | no |
| `victoria_metrics_retention` | string | Metrics retention period | "30d" | no |
| `grafana_admin_password` | string | Grafana admin password | - | yes |
| `enable_alertmanager` | bool | Enable Alertmanager | true | no |
| `slack_webhook_url` | string | Slack webhook for alerts | "" | no |

### Outputs

| Output | Description |
|--------|-------------|
| `grafana_url` | Grafana dashboard URL |
| `victoria_metrics_url` | VictoriaMetrics URL |
| `tempo_url` | Tempo tracing URL |
| `alertmanager_url` | Alertmanager URL |

## Compliance Module

### Purpose
Implements security and compliance tooling including OPA Gatekeeper policies for CIS benchmarks and CloudQuery for SOC2 auditing.

### Inputs

| Variable | Type | Description | Default | Required |
|----------|------|-------------|---------|----------|
| `enable_opa_gatekeeper` | bool | Enable OPA Gatekeeper | true | no |
| `enable_cloudquery` | bool | Enable CloudQuery auditing | true | no |
| `compliance_frameworks` | list(string) | Compliance frameworks to enable | ["cis", "soc2"] | no |
| `audit_log_retention` | number | Audit log retention in days | 90 | no |

### Outputs

| Output | Description |
|--------|-------------|
| `opa_gatekeeper_status` | OPA Gatekeeper deployment status |
| `cloudquery_config` | CloudQuery configuration |
| `compliance_dashboard_url` | Compliance dashboard URL |

## Best Practices

### Module Development

1. **Versioning**: Use semantic versioning for module releases
2. **Documentation**: Include comprehensive README.md for each module
3. **Testing**: Implement automated testing with Terratest
4. **Validation**: Use variable validation blocks for input validation
5. **Outputs**: Provide meaningful outputs for module consumers

### Security Considerations

1. **Secrets Management**: Never hardcode secrets in modules
2. **Least Privilege**: Apply principle of least privilege for IAM roles
3. **Encryption**: Enable encryption at rest and in transit by default
4. **Network Security**: Implement network segmentation and policies
5. **Compliance**: Ensure modules meet regulatory requirements

### Performance Optimization

1. **Resource Sizing**: Right-size resources based on workload requirements
2. **Auto Scaling**: Implement horizontal and vertical auto-scaling
3. **Caching**: Use appropriate caching strategies
4. **Monitoring**: Include performance monitoring and alerting
5. **Cost Optimization**: Implement cost-effective resource allocation

## Troubleshooting

### Common Issues

#### Module Not Found
```bash
Error: Module not found: ./modules/aws-eks

Solution:
- Verify module path is correct
- Ensure module directory exists
- Check for typos in module source path
```

#### Variable Validation Errors
```bash
Error: Invalid value for variable "cluster_version"

Solution:
- Check variable constraints in variables.tf
- Verify input values match expected format
- Review module documentation for valid values
```

#### Provider Version Conflicts
```bash
Error: Provider version conflict

Solution:
- Update provider version constraints
- Run terraform init -upgrade
- Check for provider compatibility
```

### Debugging Tips

1. **Enable Debug Logging**: Set `TF_LOG=DEBUG` for detailed logs
2. **Plan Before Apply**: Always run `terraform plan` first
3. **State Inspection**: Use `terraform state list` and `terraform state show`
4. **Module Testing**: Test modules in isolation before integration
5. **Version Pinning**: Pin provider and module versions for consistency

## Contributing

### Adding New Modules

1. Create module directory under `modules/`
2. Include required files: `main.tf`, `variables.tf`, `outputs.tf`, `README.md`
3. Follow naming conventions and coding standards
4. Add comprehensive documentation
5. Include example usage
6. Add automated tests
7. Update this documentation

### Module Standards

- Use consistent variable naming conventions
- Include input validation where appropriate
- Provide meaningful outputs
- Follow Terraform style guide
- Include security best practices
- Document all resources and data sources

---

*For additional support, please refer to the main project documentation or open an issue on GitHub.* 