# Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting procedures for common issues encountered in the multi-cloud Kubernetes infrastructure. It covers problems across all layers from infrastructure to applications.

## Quick Diagnosis Commands

### Cluster Health Check
```bash
# Check cluster status
kubectl cluster-info
kubectl get nodes -o wide
kubectl get pods --all-namespaces | grep -v Running

# Check system pods
kubectl get pods -n kube-system
kubectl get pods -n linkerd
kubectl get pods -n monitoring

# Check resource usage
kubectl top nodes
kubectl top pods --all-namespaces --sort-by=cpu
kubectl top pods --all-namespaces --sort-by=memory
```

### Network Connectivity Test
```bash
# Test DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup kubernetes.default

# Test service connectivity
kubectl run -it --rm debug --image=busybox --restart=Never -- wget -qO- http://service-name.namespace.svc.cluster.local

# Check network policies
kubectl get networkpolicies -A
kubectl describe networkpolicy <policy-name> -n <namespace>
```

## Infrastructure Issues

### Terraform/Terragrunt Problems

#### State Lock Issues
```bash
# Problem: Terraform state is locked
Error: Error acquiring the state lock

# Solution 1: Wait for lock to expire (usually 10-15 minutes)
# Solution 2: Force unlock (use with caution)
terragrunt force-unlock <LOCK_ID>

# Solution 3: Check who has the lock
aws dynamodb get-item \
  --table-name terraform-state-lock \
  --key '{"LockID":{"S":"<LOCK_ID>"}}'

# Prevention: Always use proper cleanup
terragrunt run-all destroy --terragrunt-non-interactive
```

#### Module Not Found Errors
```bash
# Problem: Module not found
Error: Module not found: ./modules/aws-eks

# Solution: Check module path and structure
ls -la modules/
tree modules/

# Verify module source in main.tf
grep -r "source.*modules" .

# Re-initialize if needed
terragrunt init --upgrade
```

#### Provider Version Conflicts
```bash
# Problem: Provider version conflicts
Error: Provider version conflict

# Solution: Update provider constraints
# Edit terragrunt.hcl or main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Upgrade providers
terragrunt init -upgrade
```

### Cloud Provider Authentication

#### AWS Authentication Issues
```bash
# Problem: AWS credentials not found
Error: NoCredentialsError

# Solution 1: Check AWS credentials
aws sts get-caller-identity
aws configure list

# Solution 2: Set environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-west-2"

# Solution 3: Use AWS CLI profiles
aws configure --profile production
export AWS_PROFILE=production

# Solution 4: Check IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name <username>
```

#### Azure Authentication Issues
```bash
# Problem: Azure authentication failed
Error: Azure CLI authentication failed

# Solution 1: Login to Azure
az login
az account show

# Solution 2: Set subscription
az account list
az account set --subscription "subscription-id"

# Solution 3: Service principal authentication
az login --service-principal \
  --username <app-id> \
  --password <password> \
  --tenant <tenant-id>

# Solution 4: Check permissions
az role assignment list --assignee <user-or-sp>
```

#### GCP Authentication Issues
```bash
# Problem: GCP authentication failed
Error: Google Cloud authentication failed

# Solution 1: Login to GCP
gcloud auth login
gcloud auth list

# Solution 2: Set project
gcloud projects list
gcloud config set project <project-id>

# Solution 3: Application default credentials
gcloud auth application-default login

# Solution 4: Service account key
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
```

## Kubernetes Cluster Issues

### Node Problems

#### Node Not Ready
```bash
# Problem: Node shows NotReady status
kubectl get nodes
NAME     STATUS     ROLES    AGE   VERSION
node-1   NotReady   <none>   1d    v1.28.0

# Diagnosis
kubectl describe node node-1
kubectl get events --field-selector involvedObject.name=node-1

# Common causes and solutions:
# 1. Kubelet not running
ssh node-1
sudo systemctl status kubelet
sudo systemctl restart kubelet

# 2. Network plugin issues
kubectl logs -n kube-system -l k8s-app=cilium
kubectl exec -n kube-system <cilium-pod> -- cilium status

# 3. Disk pressure
df -h
sudo docker system prune -f

# 4. Memory pressure
free -h
sudo systemctl restart kubelet
```

#### Node Resource Exhaustion
```bash
# Problem: Pods stuck in Pending due to insufficient resources
kubectl get pods -A | grep Pending
kubectl describe pod <pending-pod>

# Check resource requests vs available
kubectl describe nodes | grep -A 5 "Allocated resources"

# Solutions:
# 1. Scale cluster (if using autoscaler)
kubectl get nodes
kubectl get hpa

# 2. Optimize resource requests
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].resources.requests}{"\n"}{end}'

# 3. Add more nodes manually
# For EKS with Karpenter
kubectl apply -f - <<EOF
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: additional-capacity
spec:
  limits:
    resources:
      cpu: 1000
      memory: 1000Gi
  requirements:
    - key: karpenter.sh/capacity-type
      operator: In
      values: ["on-demand"]
EOF
```

### Pod Issues

#### Pod Stuck in Pending
```bash
# Problem: Pod remains in Pending state
kubectl get pods
kubectl describe pod <pod-name>

# Common causes:
# 1. Insufficient resources
Events:
  Warning  FailedScheduling  pod didn't trigger scale-up: 2 max node group size reached

# Solution: Scale cluster or optimize resources
kubectl scale deployment <deployment-name> --replicas=2

# 2. Node selector/affinity issues
kubectl get nodes --show-labels
kubectl describe pod <pod-name> | grep -A 10 "Node-Selectors\|Affinity"

# 3. Taints and tolerations
kubectl describe nodes | grep Taints
kubectl describe pod <pod-name> | grep -A 5 Tolerations
```

#### Pod CrashLoopBackOff
```bash
# Problem: Pod keeps restarting
kubectl get pods
NAME                    READY   STATUS             RESTARTS   AGE
app-pod                 0/1     CrashLoopBackOff   5          5m

# Diagnosis
kubectl logs <pod-name>
kubectl logs <pod-name> --previous
kubectl describe pod <pod-name>

# Common solutions:
# 1. Fix application configuration
kubectl edit configmap <config-name>
kubectl rollout restart deployment <deployment-name>

# 2. Adjust resource limits
kubectl patch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<container-name>","resources":{"limits":{"memory":"512Mi"}}}]}}}}'

# 3. Fix liveness/readiness probes
kubectl patch deployment <deployment-name> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<container-name>","livenessProbe":{"initialDelaySeconds":60}}]}}}}'
```

#### ImagePullBackOff
```bash
# Problem: Cannot pull container image
kubectl get pods
NAME      READY   STATUS             RESTARTS   AGE
app-pod   0/1     ImagePullBackOff   0          2m

# Diagnosis
kubectl describe pod <pod-name>
kubectl get events --field-selector involvedObject.name=<pod-name>

# Solutions:
# 1. Check image name and tag
kubectl get deployment <deployment-name> -o yaml | grep image:

# 2. Check image registry credentials
kubectl get secrets
kubectl describe secret <registry-secret>

# 3. Create registry secret if missing
kubectl create secret docker-registry regcred \
  --docker-server=<registry-url> \
  --docker-username=<username> \
  --docker-password=<password> \
  --docker-email=<email>

# 4. Add secret to service account
kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "regcred"}]}'
```

## Networking Issues

### Service Discovery Problems

#### Service Not Accessible
```bash
# Problem: Cannot access service
kubectl get services
kubectl describe service <service-name>

# Test service connectivity
kubectl run -it --rm debug --image=busybox --restart=Never -- wget -qO- http://<service-name>.<namespace>.svc.cluster.local

# Check endpoints
kubectl get endpoints <service-name>
kubectl describe endpoints <service-name>

# Verify pod labels match service selector
kubectl get pods --show-labels
kubectl describe service <service-name> | grep Selector
```

#### DNS Resolution Issues
```bash
# Problem: DNS not working
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup kubernetes.default

# Check CoreDNS
kubectl get pods -n kube-system -l k8s-app=kube-dns
kubectl logs -n kube-system -l k8s-app=kube-dns

# Check DNS configuration
kubectl get configmap coredns -n kube-system -o yaml

# Test specific DNS queries
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup <service-name>.<namespace>.svc.cluster.local
```

### Network Policy Issues

#### Traffic Blocked by Network Policies
```bash
# Problem: Network policies blocking legitimate traffic
kubectl get networkpolicies -A
kubectl describe networkpolicy <policy-name> -n <namespace>

# Test connectivity
kubectl run -it --rm debug --image=busybox --restart=Never -- nc -zv <target-ip> <port>

# Temporarily disable network policies for testing
kubectl delete networkpolicy <policy-name> -n <namespace>

# Debug Cilium network policies
kubectl exec -n kube-system <cilium-pod> -- cilium policy get
kubectl exec -n kube-system <cilium-pod> -- cilium endpoint list
```

### Load Balancer Issues

#### LoadBalancer Service Stuck in Pending
```bash
# Problem: LoadBalancer service not getting external IP
kubectl get services
NAME           TYPE           CLUSTER-IP     EXTERNAL-IP   PORT(S)        AGE
my-service     LoadBalancer   10.100.1.100   <pending>     80:30000/TCP   5m

# Check cloud provider load balancer controller
kubectl get pods -n kube-system | grep -i "load\|cloud"
kubectl logs -n kube-system <cloud-controller-pod>

# For AWS ALB Controller
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
kubectl logs -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller

# Check service annotations
kubectl describe service <service-name>
```

## Storage Issues

### Persistent Volume Problems

#### PVC Stuck in Pending
```bash
# Problem: PersistentVolumeClaim stuck in Pending
kubectl get pvc
NAME        STATUS    VOLUME   CAPACITY   ACCESS MODES   STORAGECLASS   AGE
my-pvc      Pending                                      gp2            5m

# Check storage class
kubectl get storageclass
kubectl describe storageclass <storage-class-name>

# Check PVC events
kubectl describe pvc <pvc-name>

# Check if CSI driver is running
kubectl get pods -n kube-system | grep csi
kubectl logs -n kube-system <csi-driver-pod>
```

#### Volume Mount Issues
```bash
# Problem: Pod cannot mount volume
kubectl describe pod <pod-name>
kubectl get events --field-selector involvedObject.name=<pod-name>

# Check volume permissions
kubectl exec -it <pod-name> -- ls -la /mounted/path

# For NFS issues
kubectl exec -it <pod-name> -- mount | grep nfs
showmount -e <nfs-server>
```

## Security Issues

### RBAC Permission Denied

#### Insufficient Permissions
```bash
# Problem: User/ServiceAccount lacks permissions
Error: User "system:serviceaccount:default:my-sa" cannot create pods

# Check current permissions
kubectl auth can-i create pods --as=system:serviceaccount:default:my-sa
kubectl auth can-i '*' '*' --as=system:serviceaccount:default:my-sa

# List role bindings
kubectl get rolebindings,clusterrolebindings -A | grep my-sa
kubectl describe rolebinding <binding-name>

# Create necessary RBAC
kubectl create clusterrolebinding my-sa-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=default:my-sa
```

### Pod Security Policy Violations

#### Pod Security Standards
```bash
# Problem: Pod violates security policies
Error: Pod "my-pod" is forbidden: violates PodSecurity "restricted:latest"

# Check pod security context
kubectl describe pod <pod-name> | grep -A 10 "Security Context"

# Fix security context
kubectl patch deployment <deployment-name> -p '{
  "spec": {
    "template": {
      "spec": {
        "securityContext": {
          "runAsNonRoot": true,
          "runAsUser": 1000,
          "fsGroup": 2000
        },
        "containers": [{
          "name": "<container-name>",
          "securityContext": {
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "capabilities": {
              "drop": ["ALL"]
            }
          }
        }]
      }
    }
  }
}'
```

## Monitoring and Observability Issues

### Metrics Not Available

#### Prometheus Scraping Issues
```bash
# Problem: Metrics not being scraped
kubectl get servicemonitors -A
kubectl describe servicemonitor <monitor-name>

# Check Prometheus targets
kubectl port-forward -n monitoring svc/prometheus 9090:9090
# Visit http://localhost:9090/targets

# Check service labels match ServiceMonitor selector
kubectl get service <service-name> --show-labels
kubectl describe servicemonitor <monitor-name> | grep -A 5 selector
```

#### Grafana Dashboard Issues
```bash
# Problem: Grafana dashboards not loading data
# Check Grafana data sources
kubectl port-forward -n monitoring svc/grafana 3000:3000
# Visit http://localhost:3000

# Check Grafana logs
kubectl logs -n monitoring deployment/grafana

# Verify data source configuration
kubectl get configmap grafana-datasources -n monitoring -o yaml
```

### Log Collection Problems

#### Vector/Fluent Bit Not Collecting Logs
```bash
# Problem: Logs not appearing in centralized logging
kubectl get pods -n logging
kubectl logs -n logging <vector-pod>

# Check log collection configuration
kubectl get configmap vector-config -n logging -o yaml

# Test log generation
kubectl run log-test --image=busybox --restart=Never -- sh -c 'while true; do echo "Test log $(date)"; sleep 1; done'
kubectl logs log-test
```

## Application-Specific Issues

### Database Connectivity

#### Database Connection Failures
```bash
# Problem: Application cannot connect to database
kubectl logs <app-pod> | grep -i database

# Check database service
kubectl get service <database-service>
kubectl describe service <database-service>

# Test database connectivity
kubectl run -it --rm debug --image=postgres:13 --restart=Never -- psql -h <db-host> -U <username> -d <database>

# Check database credentials
kubectl get secret <db-secret> -o yaml
echo "<base64-encoded-password>" | base64 -d
```

### Configuration Issues

#### ConfigMap/Secret Not Mounted
```bash
# Problem: Configuration not available in pod
kubectl describe pod <pod-name> | grep -A 10 Mounts
kubectl exec -it <pod-name> -- ls -la /etc/config

# Check ConfigMap/Secret exists
kubectl get configmap <config-name>
kubectl get secret <secret-name>

# Verify volume mount configuration
kubectl describe deployment <deployment-name> | grep -A 20 "Volume Mounts"
```

## Performance Issues

### High Resource Usage

#### CPU/Memory Exhaustion
```bash
# Problem: High resource usage causing performance issues
kubectl top nodes
kubectl top pods --all-namespaces --sort-by=cpu
kubectl top pods --all-namespaces --sort-by=memory

# Check resource limits and requests
kubectl describe pod <pod-name> | grep -A 10 "Limits\|Requests"

# Analyze resource usage over time
kubectl port-forward -n monitoring svc/grafana 3000:3000
# Check Kubernetes resource dashboards

# Optimize resource allocation
kubectl patch deployment <deployment-name> -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "<container-name>",
          "resources": {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "500m", "memory": "512Mi"}
          }
        }]
      }
    }
  }
}'
```

### Slow Application Response

#### Performance Bottlenecks
```bash
# Problem: Application responding slowly
# Check application metrics
kubectl port-forward <app-pod> 8080:8080
curl http://localhost:8080/metrics

# Analyze distributed traces
kubectl port-forward -n monitoring svc/jaeger-query 16686:16686
# Visit http://localhost:16686

# Check database performance
kubectl exec -it <database-pod> -- top
kubectl exec -it <database-pod> -- iostat -x 1

# Network latency testing
kubectl run -it --rm debug --image=busybox --restart=Never -- ping <target-host>
kubectl run -it --rm debug --image=busybox --restart=Never -- time wget -qO- http://<service-url>
```

## Emergency Procedures

### Cluster Recovery

#### Complete Cluster Failure
```bash
# Problem: Entire cluster is unresponsive
# 1. Check cloud provider status
aws eks describe-cluster --name <cluster-name>
az aks show --name <cluster-name> --resource-group <rg-name>
gcloud container clusters describe <cluster-name> --region <region>

# 2. Restore from backup if available
# For etcd backup restoration (if available)
kubectl get pods -n kube-system | grep etcd

# 3. Recreate cluster from Terraform
cd environments/prod
terragrunt destroy --target=module.aws_eks
terragrunt apply --target=module.aws_eks

# 4. Restore applications from GitOps
kubectl apply -f manifests/
```

#### Data Recovery
```bash
# Problem: Critical data lost
# 1. Check persistent volume snapshots
kubectl get volumesnapshots
kubectl describe volumesnapshot <snapshot-name>

# 2. Restore from cloud provider snapshots
# AWS EBS snapshots
aws ec2 describe-snapshots --owner-ids self

# Azure disk snapshots
az snapshot list

# GCP disk snapshots
gcloud compute snapshots list

# 3. Restore database from backup
kubectl exec -it <database-pod> -- pg_restore -d <database> /backup/dump.sql
```

## Preventive Measures

### Monitoring Setup
```bash
# Set up comprehensive monitoring
kubectl apply -f monitoring/prometheus/
kubectl apply -f monitoring/grafana/
kubectl apply -f monitoring/alertmanager/

# Configure alerts for critical issues
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: critical-alerts
spec:
  groups:
  - name: cluster.rules
    rules:
    - alert: NodeDown
      expr: up{job="node-exporter"} == 0
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Node {{ \$labels.instance }} is down"
EOF
```

### Backup Strategy
```bash
# Automated backup setup
# 1. etcd backup (for self-managed clusters)
kubectl create cronjob etcd-backup \
  --image=k8s.gcr.io/etcd:3.5.0 \
  --schedule="0 2 * * *" \
  -- /bin/sh -c "etcdctl snapshot save /backup/etcd-$(date +%Y%m%d).db"

# 2. Persistent volume snapshots
kubectl apply -f - <<EOF
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: daily-snapshots
driver: ebs.csi.aws.com
deletionPolicy: Retain
parameters:
  tagSpecification_1: "Name=daily-snapshot"
EOF

# 3. Application data backup
kubectl create cronjob database-backup \
  --image=postgres:13 \
  --schedule="0 1 * * *" \
  -- pg_dump -h database-service -U postgres -d mydb > /backup/db-$(date +%Y%m%d).sql
```

---

*This troubleshooting guide should be regularly updated based on new issues encountered and solutions discovered.* 