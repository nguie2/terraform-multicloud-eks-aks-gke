# Security Configuration Guide

## Overview

This guide provides comprehensive security configuration and best practices for the multi-cloud Kubernetes infrastructure. It covers security at every layer from infrastructure to application level.

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ APPLICATION │  │   RUNTIME   │  │  NETWORK    │            │
│  │  SECURITY   │  │  SECURITY   │  │  SECURITY   │            │
│  │             │  │             │  │             │            │
│  │ • Pod Sec   │  │ • Falco     │  │ • Cilium    │            │
│  │ • OPA       │  │ • AppArmor  │  │ • NetworkPol│            │
│  │ • RBAC      │  │ • SELinux   │  │ • mTLS      │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   IMAGE     │  │ INFRASTRUCTURE│  │ COMPLIANCE  │            │
│  │  SECURITY   │  │   SECURITY    │  │   & AUDIT   │            │
│  │             │  │               │  │             │            │
│  │ • Trivy     │  │ • Encryption  │  │ • CloudQuery│            │
│  │ • Cosign    │  │ • IAM/RBAC    │  │ • CIS Bench │            │
│  │ • Admission │  │ • Secrets Mgmt│  │ • SOC2      │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## Infrastructure Security

### Cloud Provider Security

#### AWS Security Configuration

```hcl
# EKS Cluster Security
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false  # Private cluster
    public_access_cidrs     = []
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]
}

# KMS Key for EKS encryption
resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}
```

#### Azure Security Configuration

```hcl
# AKS Cluster Security
resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  # Private cluster configuration
  private_cluster_enabled = true
  private_dns_zone_id     = azurerm_private_dns_zone.aks.id

  # Network security
  network_profile {
    network_plugin      = "azure"
    network_policy      = "cilium"
    service_cidr        = "10.2.0.0/24"
    dns_service_ip      = "10.2.0.10"
    docker_bridge_cidr  = "172.17.0.1/16"
  }

  # Azure AD integration
  azure_active_directory {
    managed                = true
    admin_group_object_ids = [var.admin_group_object_id]
    azure_rbac_enabled     = true
  }

  # Security features
  role_based_access_control {
    enabled = true
  }

  addon_profile {
    azure_policy {
      enabled = true
    }
    oms_agent {
      enabled                    = true
      log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
    }
  }
}
```

#### GCP Security Configuration

```hcl
# GKE Cluster Security
resource "google_container_cluster" "main" {
  name     = var.cluster_name
  location = var.region
  project  = var.project_id

  # Private cluster configuration
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # Workload Identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Binary Authorization
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # Security features
  security_group = "gke-security-groups@${var.domain}"
  
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  # Network policy
  network_policy {
    enabled  = true
    provider = "CILIUM"
  }

  # Pod security policy
  pod_security_policy_config {
    enabled = true
  }
}
```

### Network Security

#### Cilium Network Policies

```yaml
# Deny all ingress traffic by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress

---
# Allow specific application communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080

---
# Cilium L7 Network Policy
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: l7-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: api-server
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/api/v1/.*"
        - method: "POST"
          path: "/api/v1/users"
```

#### Service Mesh Security (Linkerd)

```yaml
# Linkerd Service Profile for security
apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata:
  name: api-service
  namespace: production
spec:
  routes:
  - name: get_user
    condition:
      method: GET
      pathRegex: /api/v1/users/[0-9]+
    responseClasses:
    - condition:
        status:
          min: 200
          max: 299
      isFailure: false
  - name: create_user
    condition:
      method: POST
      pathRegex: /api/v1/users
    responseClasses:
    - condition:
        status:
          min: 200
          max: 299
      isFailure: false

---
# Traffic Split for security testing
apiVersion: split.smi-spec.io/v1alpha1
kind: TrafficSplit
metadata:
  name: api-service-split
  namespace: production
spec:
  service: api-service
  backends:
  - service: api-service-stable
    weight: 90
  - service: api-service-canary
    weight: 10
```

## Container Security

### Image Security with Trivy

```yaml
# Trivy Operator Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: trivy-operator
  namespace: trivy-system
data:
  trivy.repository: "ghcr.io/aquasecurity/trivy"
  trivy.tag: "0.45.0"
  trivy.severity: "CRITICAL,HIGH,MEDIUM"
  trivy.ignoreUnfixed: "false"
  trivy.timeout: "5m0s"
  trivy.resources.requests.cpu: "100m"
  trivy.resources.requests.memory: "100M"
  trivy.resources.limits.cpu: "500m"
  trivy.resources.limits.memory: "500M"

---
# Vulnerability Scan Policy
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  name: nginx-vulnerability-report
  namespace: default
spec:
  artifact:
    repository: nginx
    tag: "1.21"
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: "0.45.0"
```

### Image Signing with Cosign

```bash
# Generate key pair for signing
cosign generate-key-pair

# Sign container image
cosign sign --key cosign.key gcr.io/my-project/my-app:v1.0.0

# Verify image signature
cosign verify --key cosign.pub gcr.io/my-project/my-app:v1.0.0

# Policy for signed images only
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: enforce
  background: false
  rules:
  - name: check-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "*"
      attestors:
      - entries:
        - keys:
            publicKeys: |-
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
              -----END PUBLIC KEY-----
```

## Runtime Security

### Falco Configuration

```yaml
# Falco Rules for Runtime Security
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules
  namespace: falco
data:
  custom_rules.yaml: |
    - rule: Detect Shell in Container
      desc: Detect shell execution in container
      condition: >
        spawned_process and container and
        (proc.name in (shell_binaries) or
         proc.name in (shell_mgmt_binaries))
      output: >
        Shell spawned in container (user=%user.name container_id=%container.id
        container_name=%container.name shell=%proc.name parent=%proc.pname
        cmdline=%proc.cmdline)
      priority: WARNING
      tags: [container, shell, mitre_execution]

    - rule: Detect Privilege Escalation
      desc: Detect privilege escalation attempts
      condition: >
        spawned_process and container and
        proc.name in (privilege_escalation_binaries)
      output: >
        Privilege escalation attempt (user=%user.name container_id=%container.id
        container_name=%container.name command=%proc.cmdline)
      priority: CRITICAL
      tags: [container, privilege_escalation]

    - rule: Detect Network Activity
      desc: Detect suspicious network activity
      condition: >
        (inbound_outbound) and container and
        (fd.sockfamily=ip and fd.sport!=53 and fd.dport!=53)
      output: >
        Network activity detected (user=%user.name container_id=%container.id
        container_name=%container.name connection=%fd.name)
      priority: INFO
      tags: [network, container]

---
# Falco Deployment
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccountName: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco:0.35.1
        securityContext:
          privileged: true
        volumeMounts:
        - name: dev
          mountPath: /host/dev
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
        - name: lib-modules
          mountPath: /host/lib/modules
          readOnly: true
        - name: usr
          mountPath: /host/usr
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
        - name: falco-config
          mountPath: /etc/falco
      volumes:
      - name: dev
        hostPath:
          path: /dev
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr
        hostPath:
          path: /usr
      - name: etc
        hostPath:
          path: /etc
      - name: falco-config
        configMap:
          name: falco-rules
```

## Policy as Code

### OPA Gatekeeper Policies

```yaml
# Constraint Template for Security Context
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsecuritycontext
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSecurityContext
      validation:
        openAPIV3Schema:
          type: object
          properties:
            runAsNonRoot:
              type: boolean
            readOnlyRootFilesystem:
              type: boolean
            allowPrivilegeEscalation:
              type: boolean
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
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
          container.securityContext.allowPrivilegeEscalation
          msg := "Container must not allow privilege escalation"
        }

---
# Apply Security Context Constraint
apiVersion: config.gatekeeper.sh/v1beta1
kind: K8sRequiredSecurityContext
metadata:
  name: must-have-security-context
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    runAsNonRoot: true
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false

---
# Resource Limits Constraint
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredresources
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredResources
      validation:
        openAPIV3Schema:
          type: object
          properties:
            limits:
              type: array
              items:
                type: string
            requests:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredresources

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          required := input.parameters.limits
          missing := required[_]
          not container.resources.limits[missing]
          msg := sprintf("Container is missing required resource limit: %v", [missing])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          required := input.parameters.requests
          missing := required[_]
          not container.resources.requests[missing]
          msg := sprintf("Container is missing required resource request: %v", [missing])
        }
```

## Secrets Management

### External Secrets Operator

```yaml
# External Secrets Store
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: production
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-west-2
      auth:
        secretRef:
          accessKeyID:
            name: aws-credentials
            key: access-key-id
          secretAccessKey:
            name: aws-credentials
            key: secret-access-key

---
# External Secret
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: database-secret
    creationPolicy: Owner
  data:
  - secretKey: username
    remoteRef:
      key: prod/database
      property: username
  - secretKey: password
    remoteRef:
      key: prod/database
      property: password
```

### Sealed Secrets

```bash
# Install Sealed Secrets Controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.18.0/controller.yaml

# Create sealed secret
echo -n mypassword | kubectl create secret generic mysecret --dry-run=client --from-file=password=/dev/stdin -o yaml | kubeseal -o yaml > mysealedsecret.yaml

# Apply sealed secret
kubectl apply -f mysealedsecret.yaml
```

## Compliance and Auditing

### CloudQuery Configuration

```yaml
# CloudQuery Configuration for SOC2 Compliance
kind: source
spec:
  name: "aws"
  path: "cloudquery/aws"
  version: "v23.0.0"
  tables: ["*"]
  destinations: ["postgresql"]
  spec:
    regions: ["us-west-2", "us-east-1"]
    accounts:
      - id: "123456789012"
        local_profile: "production"

---
kind: source
spec:
  name: "azure"
  path: "cloudquery/azure"
  version: "v5.0.0"
  tables: ["*"]
  destinations: ["postgresql"]
  spec:
    subscriptions: ["subscription-id-1"]

---
kind: source
spec:
  name: "gcp"
  path: "cloudquery/gcp"
  version: "v9.0.0"
  tables: ["*"]
  destinations: ["postgresql"]
  spec:
    project_ids: ["my-project-id"]

---
kind: destination
spec:
  name: "postgresql"
  path: "cloudquery/postgresql"
  version: "v4.0.0"
  spec:
    connection_string: "${CQ_DSN}"
```

### CIS Benchmark Policies

```yaml
# CIS 5.1.1 - Ensure that the cluster-admin role is only used where required
apiVersion: config.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: cis-5-1-1-cluster-admin-usage
spec:
  match:
    kinds:
      - apiGroups: ["rbac.authorization.k8s.io"]
        kinds: ["ClusterRoleBinding"]
  parameters:
    labels: ["cis-exception"]
    message: "ClusterRoleBinding with cluster-admin must have cis-exception label"

---
# CIS 5.2.2 - Minimize the admission of containers with allowPrivilegeEscalation
apiVersion: config.gatekeeper.sh/v1beta1
kind: K8sRequiredSecurityContext
metadata:
  name: cis-5-2-2-no-privilege-escalation
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowPrivilegeEscalation: false

---
# CIS 5.2.3 - Minimize the admission of root containers
apiVersion: config.gatekeeper.sh/v1beta1
kind: K8sRequiredSecurityContext
metadata:
  name: cis-5-2-3-run-as-non-root
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    runAsNonRoot: true
```

## Security Monitoring and Alerting

### Prometheus Security Metrics

```yaml
# Security-focused ServiceMonitor
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: security-metrics
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: security-exporter
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics

---
# Security Alerts
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-alerts
  namespace: monitoring
spec:
  groups:
  - name: security.rules
    rules:
    - alert: HighVulnerabilityCount
      expr: trivy_image_vulnerabilities{severity="Critical"} > 0
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: "Critical vulnerabilities detected"
        description: "{{ $labels.image }} has {{ $value }} critical vulnerabilities"

    - alert: UnauthorizedAPIAccess
      expr: increase(apiserver_audit_total{verb="create",objectRef_resource="pods",user_username!~"system:.*"}[5m]) > 10
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "Unusual API access pattern detected"
        description: "User {{ $labels.user_username }} created {{ $value }} pods in 5 minutes"

    - alert: PrivilegedContainerDetected
      expr: kube_pod_container_status_running{container=~".*"} and on(pod, namespace) kube_pod_spec_containers_security_context_privileged == 1
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: "Privileged container detected"
        description: "Privileged container {{ $labels.container }} in pod {{ $labels.pod }}"
```

## Security Best Practices

### Development Security

1. **Secure Coding Practices**
   - Input validation and sanitization
   - Proper error handling
   - Secure authentication and authorization
   - Regular security code reviews

2. **Container Security**
   - Use minimal base images (distroless, alpine)
   - Run containers as non-root users
   - Implement read-only root filesystems
   - Regular vulnerability scanning

3. **Secrets Management**
   - Never hardcode secrets in code or images
   - Use external secret management systems
   - Rotate secrets regularly
   - Implement least privilege access

### Operational Security

1. **Access Control**
   - Implement RBAC with least privilege
   - Use service accounts for applications
   - Regular access reviews and cleanup
   - Multi-factor authentication for admin access

2. **Network Security**
   - Implement network segmentation
   - Use service mesh for mTLS
   - Regular network policy audits
   - Monitor network traffic patterns

3. **Monitoring and Incident Response**
   - Comprehensive security monitoring
   - Automated threat detection
   - Incident response procedures
   - Regular security drills

### Compliance Maintenance

1. **Regular Audits**
   - Automated compliance scanning
   - Manual security assessments
   - Third-party security audits
   - Vulnerability assessments

2. **Documentation**
   - Security policies and procedures
   - Incident response playbooks
   - Compliance evidence collection
   - Regular documentation updates

3. **Training and Awareness**
   - Security training for development teams
   - Regular security awareness sessions
   - Incident response training
   - Security best practices documentation

## Troubleshooting Security Issues

### Common Security Problems

#### Pod Security Policy Violations
```bash
# Check PSP violations
kubectl get events --field-selector reason=FailedCreate

# Debug pod security context
kubectl describe pod <pod-name>

# Check security context constraints
kubectl get psp
kubectl describe psp <policy-name>
```

#### Network Policy Issues
```bash
# Test network connectivity
kubectl exec -it <pod-name> -- nc -zv <target-ip> <port>

# Check network policies
kubectl get networkpolicies -A
kubectl describe networkpolicy <policy-name>

# Debug Cilium policies
kubectl exec -n kube-system <cilium-pod> -- cilium policy get
```

#### RBAC Permission Issues
```bash
# Check user permissions
kubectl auth can-i <verb> <resource> --as=<user>

# Debug RBAC
kubectl get rolebindings,clusterrolebindings -A
kubectl describe rolebinding <binding-name>

# Check service account permissions
kubectl auth can-i <verb> <resource> --as=system:serviceaccount:<namespace>:<sa-name>
```

---

*This security guide should be regularly updated to reflect the latest security best practices and threat landscape changes.* 