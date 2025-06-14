#!/bin/bash

# Multi-Cloud Kubernetes Infrastructure Deployment Script
# Author: Nguie Angoue Jean Roch Junior
# Email: nguierochjunior@gmail.com

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="multicloud-k8s"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Help function
show_help() {
    cat << EOF
Multi-Cloud Kubernetes Infrastructure Deployment Script

Usage: $0 [OPTIONS] ENVIRONMENT

ENVIRONMENT:
    dev         Deploy development environment
    prod        Deploy production environment

OPTIONS:
    -h, --help              Show this help message
    -v, --validate-only     Only validate prerequisites, don't deploy
    -p, --plan-only         Run terraform plan only
    -d, --destroy           Destroy infrastructure
    --skip-validation       Skip prerequisite validation
    --aws-only              Deploy only AWS EKS
    --azure-only            Deploy only Azure AKS
    --gcp-only              Deploy only GCP GKE

Examples:
    $0 dev                  Deploy development environment
    $0 prod --plan-only     Plan production deployment
    $0 dev --aws-only       Deploy only AWS EKS in dev
    $0 prod --destroy       Destroy production infrastructure

EOF
}

# Parse command line arguments
ENVIRONMENT=""
VALIDATE_ONLY=false
PLAN_ONLY=false
DESTROY=false
SKIP_VALIDATION=false
AWS_ONLY=false
AZURE_ONLY=false
GCP_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--validate-only)
            VALIDATE_ONLY=true
            shift
            ;;
        -p|--plan-only)
            PLAN_ONLY=true
            shift
            ;;
        -d|--destroy)
            DESTROY=true
            shift
            ;;
        --skip-validation)
            SKIP_VALIDATION=true
            shift
            ;;
        --aws-only)
            AWS_ONLY=true
            shift
            ;;
        --azure-only)
            AZURE_ONLY=true
            shift
            ;;
        --gcp-only)
            GCP_ONLY=true
            shift
            ;;
        dev|prod)
            ENVIRONMENT=$1
            shift
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Validate environment
if [[ -z "$ENVIRONMENT" ]]; then
    error "Environment is required. Use 'dev' or 'prod'"
fi

if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
    error "Environment must be 'dev' or 'prod'"
fi

log "Starting deployment for environment: $ENVIRONMENT"

# Prerequisite validation
validate_prerequisites() {
    log "Validating prerequisites..."
    
    local errors=0
    
    # Check required tools
    local tools=("terraform" "terragrunt" "kubectl" "helm" "aws" "az" "gcloud" "python3" "jq")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "Required tool not found: $tool"
            ((errors++))
        else
            local version
            case $tool in
                terraform)
                    version=$(terraform version | head -n1 | cut -d' ' -f2)
                    log "✓ Terraform: $version"
                    ;;
                terragrunt)
                    version=$(terragrunt --version | head -n1 | cut -d' ' -f3)
                    log "✓ Terragrunt: $version"
                    ;;
                kubectl)
                    version=$(kubectl version --client --short 2>/dev/null | cut -d' ' -f3)
                    log "✓ kubectl: $version"
                    ;;
                helm)
                    version=$(helm version --short | cut -d' ' -f1)
                    log "✓ Helm: $version"
                    ;;
                aws)
                    version=$(aws --version | cut -d' ' -f1)
                    log "✓ AWS CLI: $version"
                    ;;
                az)
                    version=$(az version --output tsv --query '"azure-cli"')
                    log "✓ Azure CLI: $version"
                    ;;
                gcloud)
                    version=$(gcloud version --format="value(Google Cloud SDK)" 2>/dev/null | head -n1)
                    log "✓ Google Cloud SDK: $version"
                    ;;
                python3)
                    version=$(python3 --version | cut -d' ' -f2)
                    log "✓ Python: $version"
                    ;;
                jq)
                    version=$(jq --version)
                    log "✓ jq: $version"
                    ;;
            esac
        fi
    done
    
    # Check cloud authentication
    log "Checking cloud authentication..."
    
    if [[ "$AWS_ONLY" == "true" || ("$AZURE_ONLY" == "false" && "$GCP_ONLY" == "false") ]]; then
        if ! aws sts get-caller-identity &> /dev/null; then
            error "AWS authentication failed. Run 'aws configure'"
            ((errors++))
        else
            local aws_account=$(aws sts get-caller-identity --query Account --output text)
            local aws_user=$(aws sts get-caller-identity --query Arn --output text)
            success "AWS authenticated: $aws_user (Account: $aws_account)"
        fi
    fi
    
    if [[ "$AZURE_ONLY" == "true" || ("$AWS_ONLY" == "false" && "$GCP_ONLY" == "false") ]]; then
        if ! az account show &> /dev/null; then
            error "Azure authentication failed. Run 'az login'"
            ((errors++))
        else
            local azure_account=$(az account show --query name --output tsv)
            local azure_user=$(az account show --query user.name --output tsv)
            success "Azure authenticated: $azure_user (Subscription: $azure_account)"
        fi
    fi
    
    if [[ "$GCP_ONLY" == "true" || ("$AWS_ONLY" == "false" && "$AZURE_ONLY" == "false") ]]; then
        if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 &> /dev/null; then
            error "GCP authentication failed. Run 'gcloud auth login'"
            ((errors++))
        else
            local gcp_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1)
            local gcp_project=$(gcloud config get-value project 2>/dev/null || echo "Not set")
            success "GCP authenticated: $gcp_account (Project: $gcp_project)"
        fi
    fi
    
    # Check environment variables
    log "Checking required environment variables..."
    
    local required_vars=()
    
    if [[ "$GCP_ONLY" == "true" || ("$AWS_ONLY" == "false" && "$AZURE_ONLY" == "false") ]]; then
        required_vars+=("TF_VAR_gcp_project_id")
    fi
    
    # Optional but recommended
    local optional_vars=("TF_VAR_megaport_access_key" "TF_VAR_megaport_secret_key")
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            error "Required environment variable not set: $var"
            ((errors++))
        fi
    done
    
    for var in "${optional_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            warning "Optional environment variable not set: $var (cross-cloud networking will be disabled)"
        fi
    done
    
    # Check file permissions
    if [[ ! -r "$ROOT_DIR/environments/$ENVIRONMENT/terragrunt.hcl" ]]; then
        error "Cannot read environment configuration: $ROOT_DIR/environments/$ENVIRONMENT/terragrunt.hcl"
        ((errors++))
    fi
    
    if [[ $errors -gt 0 ]]; then
        error "Prerequisites validation failed with $errors errors"
    fi
    
    success "All prerequisites validated successfully"
}

# Initialize Terraform state
initialize_terraform() {
    log "Initializing Terraform state..."
    
    cd "$ROOT_DIR/environments/$ENVIRONMENT"
    
    # Initialize terragrunt
    terragrunt run-all init --terragrunt-non-interactive
    
    success "Terraform state initialized"
}

# Plan deployment
plan_deployment() {
    log "Planning deployment..."
    
    cd "$ROOT_DIR/environments/$ENVIRONMENT"
    
    local plan_args=""
    
    if [[ "$AWS_ONLY" == "true" ]]; then
        plan_args="-target=module.aws_eks"
    elif [[ "$AZURE_ONLY" == "true" ]]; then
        plan_args="-target=module.azure_aks"
    elif [[ "$GCP_ONLY" == "true" ]]; then
        plan_args="-target=module.gcp_gke"
    fi
    
    terragrunt run-all plan --terragrunt-non-interactive $plan_args
    
    success "Deployment plan completed"
}

# Deploy infrastructure
deploy_infrastructure() {
    log "Deploying infrastructure..."
    
    cd "$ROOT_DIR/environments/$ENVIRONMENT"
    
    local apply_args=""
    
    if [[ "$AWS_ONLY" == "true" ]]; then
        apply_args="-target=module.aws_eks"
    elif [[ "$AZURE_ONLY" == "true" ]]; then
        apply_args="-target=module.azure_aks"
    elif [[ "$GCP_ONLY" == "true" ]]; then
        apply_args="-target=module.gcp_gke"
    fi
    
    terragrunt run-all apply --terragrunt-non-interactive $apply_args
    
    success "Infrastructure deployed successfully"
}

# Destroy infrastructure
destroy_infrastructure() {
    log "Destroying infrastructure..."
    
    warning "This will destroy all infrastructure in the $ENVIRONMENT environment!"
    read -p "Are you sure you want to continue? (yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        log "Destruction cancelled"
        exit 0
    fi
    
    cd "$ROOT_DIR/environments/$ENVIRONMENT"
    
    terragrunt run-all destroy --terragrunt-non-interactive
    
    success "Infrastructure destroyed"
}

# Validate deployment
validate_deployment() {
    log "Validating deployment..."
    
    # Run cluster validation script
    if [[ -f "$ROOT_DIR/scripts/validate_cluster_parity.py" ]]; then
        python3 "$ROOT_DIR/scripts/validate_cluster_parity.py"
    else
        warning "Cluster validation script not found"
    fi
    
    # Check cluster connectivity
    log "Checking cluster connectivity..."
    
    cd "$ROOT_DIR/environments/$ENVIRONMENT"
    
    # Get kubectl commands from terraform output
    local kubectl_commands
    kubectl_commands=$(terragrunt output -json kubectl_commands 2>/dev/null || echo "{}")
    
    if [[ "$kubectl_commands" != "{}" ]]; then
        echo "$kubectl_commands" | jq -r 'to_entries[] | select(.value != null) | "\(.key): \(.value)"' | while read -r line; do
            log "Kubectl command: $line"
        done
    fi
    
    success "Deployment validation completed"
}

# Generate deployment report
generate_report() {
    log "Generating deployment report..."
    
    local report_file="$ROOT_DIR/deployment-report-$ENVIRONMENT-$(date +%Y%m%d-%H%M%S).md"
    
    cd "$ROOT_DIR/environments/$ENVIRONMENT"
    
    cat > "$report_file" << EOF
# Multi-Cloud Kubernetes Deployment Report

**Environment:** $ENVIRONMENT  
**Date:** $(date)  
**Deployed by:** $(whoami)  

## Infrastructure Summary

$(terragrunt output -json cluster_summary 2>/dev/null | jq -r '.' || echo "No cluster summary available")

## Security Features

$(terragrunt output -json security_features 2>/dev/null | jq -r '.' || echo "No security features information available")

## Observability Stack

$(terragrunt output -json observability_stack 2>/dev/null | jq -r '.' || echo "No observability stack information available")

## Kubectl Commands

$(terragrunt output -json kubectl_commands 2>/dev/null | jq -r 'to_entries[] | select(.value != null) | "- **\(.key):** \`\(.value)\`"' || echo "No kubectl commands available")

## Next Steps

1. Configure kubectl contexts for all clusters
2. Deploy sample applications to test service mesh
3. Set up monitoring dashboards
4. Configure alerting rules
5. Test cross-cloud connectivity
6. Run compliance scans

## Support

For issues or questions, contact:
- **Author:** Nguie Angoue Jean Roch Junior
- **Email:** nguierochjunior@gmail.com
- **GitHub:** @nguie2

EOF
    
    success "Deployment report generated: $report_file"
}

# Main execution
main() {
    log "Multi-Cloud Kubernetes Infrastructure Deployment"
    log "Author: Nguie Angoue Jean Roch Junior"
    log "Environment: $ENVIRONMENT"
    
    # Validate prerequisites unless skipped
    if [[ "$SKIP_VALIDATION" == "false" ]]; then
        validate_prerequisites
    fi
    
    # Exit if validation only
    if [[ "$VALIDATE_ONLY" == "true" ]]; then
        success "Validation completed successfully"
        exit 0
    fi
    
    # Handle destroy
    if [[ "$DESTROY" == "true" ]]; then
        destroy_infrastructure
        exit 0
    fi
    
    # Initialize Terraform
    initialize_terraform
    
    # Plan deployment
    plan_deployment
    
    # Exit if plan only
    if [[ "$PLAN_ONLY" == "true" ]]; then
        success "Planning completed successfully"
        exit 0
    fi
    
    # Deploy infrastructure
    deploy_infrastructure
    
    # Validate deployment
    validate_deployment
    
    # Generate report
    generate_report
    
    success "Deployment completed successfully!"
    log "Check the deployment report for next steps and kubectl commands"
}

# Run main function
main "$@" 