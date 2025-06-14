# 🚀 Multi-Cloud Kubernetes Deployment Guide

This guide provides step-by-step instructions for deploying and managing the multi-cloud Kubernetes infrastructure across AWS EKS, Azure AKS, and Google GKE.

## 📋 Prerequisites

### Required Tools

Ensure you have the following tools installed:

```bash
# Terraform
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install terraform

# Terragrunt
wget https://github.com/gruntwork-io/terragrunt/releases/download/v0.50.0/terragrunt_linux_amd64
chmod +x terragrunt_linux_amd64
sudo mv terragrunt_linux_amd64 /usr/local/bin/terragrunt

# Kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Helm
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update && sudo apt-get install helm

# Python (for validation scripts)
sudo apt-get install python3 python3-pip
pip3 install pyyaml kubernetes
```

### Cloud CLI Tools

```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Google Cloud CLI
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get update && sudo apt-get install google-cloud-cli
```

### Version Requirements

- Terraform >= 1.5.0
- Terragrunt >= 0.50.0
- Kubectl >= 1.28.0
- Helm >= 3.12.0
- Python >= 3.9.0

## 🔐 Authentication Setup

### AWS Authentication

```bash
# Configure AWS credentials
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and default region

# Verify authentication
aws sts get-caller-identity
```

### Azure Authentication

```bash
# Login to Azure
az login

# Set subscription (if you have multiple)
az account set --subscription "your-subscription-id"

# Verify authentication
az account show
```

### Google Cloud Authentication

```bash
# Login to Google Cloud
gcloud auth login

# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable iam.googleapis.com

# Verify authentication
gcloud auth list
```

## 🏗️ Infrastructure Deployment

### Step 1: Clone and Configure

```bash
# Clone the repository
git clone https://github.com/nguie2/terraform-multicloud-eks-aks-gke.git
cd terraform-multicloud-eks-aks-gke

# Copy environment configuration
cp environments/dev/terragrunt.hcl.example environments/dev/terragrunt.hcl
cp environments/prod/terragrunt.hcl.example environments/prod/terragrunt.hcl
```

### Step 2: Configure Environment Variables

Create a `.env` file with your specific configuration:

```bash
# .env file
export TF_VAR_project_name="multicloud-k8s"
export TF_VAR_gcp_project_id="your-gcp-project-id"
export TF_VAR_megaport_access_key="your-megaport-access-key"
export TF_VAR_megaport_secret_key="your-megaport-secret-key"

# Load environment variables
source .env
```

### Step 3: Initialize Terraform State

```bash
# Create S3 bucket for Terraform state (one-time setup)
aws s3 mb s3://multicloud-k8s-terraform-state-${TF_VAR_project_name} --region us-west-2

# Create DynamoDB table for state locking
aws dynamodb create-table \
  --table-name multicloud-k8s-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  --region us-west-2
```

### Step 4: Deploy Development Environment

```bash
# Navigate to development environment
cd environments/dev

# Initialize Terragrunt
terragrunt run-all init

# Plan deployment
terragrunt run-all plan

# Apply infrastructure
terragrunt run-all apply
```

### Step 5: Deploy Production Environment

```bash
# Navigate to production environment
cd ../prod

# Initialize Terragrunt
terragrunt run-all init

# Plan deployment
terragrunt run-all plan

# Apply infrastructure
terragrunt run-all apply
```

## 🔧 Post-Deployment Configuration

### Configure Kubectl Contexts

After deployment, configure kubectl to access all clusters:

```bash
# AWS EKS
aws eks update-kubeconfig --region us-west-2 --name multicloud-k8s-dev-aws
aws eks update-kubeconfig --region us-west-2 --name multicloud-k8s-prod-aws

# Azure AKS
az aks get-credentials --resource-group multicloud-k8s-dev-azure-rg --name multicloud-k8s-dev-azure
az aks get-credentials --resource-group multicloud-k8s-prod-azure-rg --name multicloud-k8s-prod-azure

# Google GKE
gcloud container clusters get-credentials multicloud-k8s-dev-gcp --region us-west1 --project ${TF_VAR_gcp_project_id}
gcloud container clusters get-credentials multicloud-k8s-prod-gcp --region us-west1 --project ${TF_VAR_gcp_project_id}

# Verify contexts
kubectl config get-contexts
```

### Install Additional Components

```bash
# Install Linkerd CLI
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh
export PATH=$PATH:$HOME/.linkerd2/bin

# Verify Linkerd installation on each cluster
for context in $(kubectl config get-contexts -o name | grep multicloud-k8s); do
  echo "Checking Linkerd on $context"
  kubectl --context=$context -n linkerd get pods
done
```

## ✅ Validation and Testing

### Run Cluster Parity Validation

```bash
# Create cluster configuration
python scripts/validate_cluster_parity.py --create-config

# Edit cluster_config.yaml with your actual cluster contexts
vim cluster_config.yaml

# Run validation
python scripts/validate_cluster_parity.py --config cluster_config.yaml --output validation_report.txt

# View results
cat validation_report.txt
```

### Test Cross-Cloud Connectivity

```bash
# Deploy test application across clusters
kubectl apply -f examples/test-app/ --context=multicloud-k8s-dev-aws
kubectl apply -f examples/test-app/ --context=multicloud-k8s-dev-azure
kubectl apply -f examples/test-app/ --context=multicloud-k8s-dev-gcp

# Test service mesh connectivity
linkerd --context=multicloud-k8s-dev-aws check
linkerd --context=multicloud-k8s-dev-azure check
linkerd --context=multicloud-k8s-dev-gcp check
```

### Verify Security Policies

```bash
# Check OPA Gatekeeper policies
for context in $(kubectl config get-contexts -o name | grep multicloud-k8s); do
  echo "Checking Gatekeeper on $context"
  kubectl --context=$context get constrainttemplates
  kubectl --context=$context get violations --all-namespaces
done

# Test policy enforcement
kubectl --context=multicloud-k8s-dev-aws apply -f examples/policy-test/privileged-pod.yaml
# Should be rejected by Gatekeeper
```

## 📊 Monitoring and Observability

### Access Monitoring Dashboards

```bash
# Port-forward to Grafana (VictoriaMetrics stack)
kubectl --context=multicloud-k8s-dev-aws port-forward -n monitoring svc/grafana 3000:3000

# Access Grafana at http://localhost:3000
# Default credentials: admin/admin

# Port-forward to Linkerd dashboard
kubectl --context=multicloud-k8s-dev-aws port-forward -n linkerd-viz svc/web 8084:8084

# Access Linkerd Viz at http://localhost:8084
```

### Configure Alerting

```bash
# Apply alerting rules
kubectl apply -f configs/monitoring/alerting-rules.yaml --context=multicloud-k8s-dev-aws
kubectl apply -f configs/monitoring/alerting-rules.yaml --context=multicloud-k8s-dev-azure
kubectl apply -f configs/monitoring/alerting-rules.yaml --context=multicloud-k8s-dev-gcp

# Configure Slack/email notifications
kubectl create secret generic alertmanager-config \
  --from-file=configs/monitoring/alertmanager.yml \
  -n monitoring \
  --context=multicloud-k8s-dev-aws
```

## 🔄 CI/CD Integration

### GitHub Actions Setup

```yaml
# .github/workflows/deploy.yml
name: Multi-Cloud Infrastructure

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: 1.5.0
          
      - name: Setup Terragrunt
        run: |
          wget https://github.com/gruntwork-io/terragrunt/releases/download/v0.50.0/terragrunt_linux_amd64
          chmod +x terragrunt_linux_amd64
          sudo mv terragrunt_linux_amd64 /usr/local/bin/terragrunt
          
      - name: Terraform Validate
        run: |
          cd environments/dev
          terragrunt run-all validate
          
      - name: Security Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          
  deploy:
    needs: validate
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Deploy Infrastructure
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          ARM_CLIENT_ID: ${{ secrets.ARM_CLIENT_ID }}
          ARM_CLIENT_SECRET: ${{ secrets.ARM_CLIENT_SECRET }}
          ARM_TENANT_ID: ${{ secrets.ARM_TENANT_ID }}
          ARM_SUBSCRIPTION_ID: ${{ secrets.ARM_SUBSCRIPTION_ID }}
          GOOGLE_CREDENTIALS: ${{ secrets.GOOGLE_CREDENTIALS }}
        run: |
          cd environments/dev
          terragrunt run-all apply --terragrunt-non-interactive
```

## 🛠️ Maintenance and Operations

### Regular Maintenance Tasks

```bash
# Update Kubernetes versions
terragrunt run-all plan -var="kubernetes_version=1.29"
terragrunt run-all apply -var="kubernetes_version=1.29"

# Update Helm charts
helm repo update
# Update chart versions in Terraform modules

# Rotate certificates (Linkerd)
linkerd upgrade --context=multicloud-k8s-prod-aws | kubectl apply -f -
```

### Backup and Disaster Recovery

```bash
# Backup cluster configurations
kubectl get all --all-namespaces -o yaml > cluster-backup-$(date +%Y%m%d).yaml

# Backup persistent volumes
velero backup create cluster-backup-$(date +%Y%m%d) --include-cluster-resources

# Test disaster recovery
# Deploy to secondary regions and test failover
```

### Cost Optimization

```bash
# Review resource usage
kubectl top nodes --context=multicloud-k8s-prod-aws
kubectl top pods --all-namespaces --context=multicloud-k8s-prod-aws

# Scale down development environments
terragrunt run-all apply -var="node_count=1" -target=environments/dev

# Use spot instances for non-critical workloads
# Configure in Karpenter NodePools
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Terraform State Lock

```bash
# If state is locked
terragrunt force-unlock LOCK_ID

# Or delete the lock from DynamoDB
aws dynamodb delete-item \
  --table-name multicloud-k8s-terraform-locks \
  --key '{"LockID":{"S":"LOCK_ID"}}'
```

#### 2. Cluster Connection Issues

```bash
# Refresh kubeconfig
aws eks update-kubeconfig --region us-west-2 --name CLUSTER_NAME

# Check cluster status
kubectl cluster-info --context=CONTEXT_NAME

# Verify node status
kubectl get nodes --context=CONTEXT_NAME
```

#### 3. Service Mesh Issues

```bash
# Check Linkerd control plane
linkerd check --context=CONTEXT_NAME

# Restart Linkerd components
kubectl rollout restart deployment -n linkerd

# Check proxy injection
kubectl get pods -o jsonpath='{.items[*].spec.containers[*].name}' | grep linkerd-proxy
```

#### 4. Policy Violations

```bash
# Check Gatekeeper violations
kubectl get violations --all-namespaces

# Disable policy temporarily
kubectl patch constrainttemplate TEMPLATE_NAME -p '{"spec":{"enforcementAction":"warn"}}'

# Debug policy issues
kubectl describe constrainttemplate TEMPLATE_NAME
```

### Log Collection

```bash
# Collect logs from all clusters
for context in $(kubectl config get-contexts -o name | grep multicloud-k8s); do
  echo "Collecting logs from $context"
  kubectl --context=$context logs -n kube-system -l component=kube-apiserver > logs-$context-apiserver.log
  kubectl --context=$context logs -n linkerd -l linkerd.io/control-plane-component=controller > logs-$context-linkerd.log
done
```

## 📈 Scaling and Performance

### Horizontal Scaling

```bash
# Scale node groups
terragrunt run-all apply -var="node_count=5"

# Configure Karpenter for automatic scaling
kubectl apply -f configs/karpenter/nodepool.yaml

# Scale applications
kubectl scale deployment webapp --replicas=10 --context=multicloud-k8s-prod-aws
```

### Performance Tuning

```bash
# Optimize Cilium settings
kubectl patch configmap cilium-config -n kube-system --patch '{"data":{"enable-bandwidth-manager":"true"}}'

# Tune Linkerd proxy resources
kubectl patch deployment linkerd-proxy -n linkerd --patch '{"spec":{"template":{"spec":{"containers":[{"name":"linkerd-proxy","resources":{"requests":{"cpu":"200m","memory":"64Mi"}}}]}}}}'

# Configure resource quotas
kubectl apply -f configs/resource-quotas/ --context=multicloud-k8s-prod-aws
```

## 🔒 Security Hardening

### Additional Security Measures

```bash
# Enable Pod Security Standards
kubectl label namespace default pod-security.kubernetes.io/enforce=restricted

# Configure network policies
kubectl apply -f configs/network-policies/ --recursive

# Enable audit logging
# Configure in cluster creation parameters

# Rotate service account tokens
kubectl create token default --duration=1h
```

### Compliance Scanning

```bash
# Run CIS benchmark scan
kube-bench run --targets master,node,etcd,policies

# Scan for vulnerabilities
trivy k8s cluster --context=multicloud-k8s-prod-aws

# Generate compliance report
python scripts/compliance_report.py --output compliance-$(date +%Y%m%d).html
```

## 📞 Support and Contact

For issues, questions, or contributions:

- **GitHub Issues**: [Create an issue](https://github.com/nguie2/terraform-multicloud-eks-aks-gke/issues)
- **Email**: nguierochjunior@gmail.com
- **LinkedIn**: [Nguie Angoue J](https://www.linkedin.com/in/nguie-angoue-j-2b2880254/)
- **Twitter**: [@jean32529](https://x.com/jean32529)

## 📚 Additional Resources

- [Terraform Documentation](https://www.terraform.io/docs)
- [Terragrunt Documentation](https://terragrunt.gruntwork.io/docs/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Linkerd Documentation](https://linkerd.io/docs/)
- [Cilium Documentation](https://docs.cilium.io/)
- [OPA Gatekeeper Documentation](https://open-policy-agent.github.io/gatekeeper/)

---

*This deployment guide is part of the Multi-Cloud Kubernetes Infrastructure project by Nguie Angoue Jean Roch Junior.* 