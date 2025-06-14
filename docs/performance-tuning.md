# Performance Tuning Guide

## Overview

This guide provides comprehensive performance optimization strategies for the multi-cloud Kubernetes infrastructure. It covers optimization at every layer from infrastructure to applications.

## Performance Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PERFORMANCE LAYERS                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │APPLICATION  │  │   RUNTIME   │  │  NETWORK    │            │
│  │OPTIMIZATION │  │OPTIMIZATION │  │OPTIMIZATION │            │
│  │             │  │             │  │             │            │
│  │• Resource   │  │• JVM Tuning │  │• Cilium eBPF│            │
│  │  Requests   │  │• GC Tuning  │  │• Load Bal   │            │
│  │• HPA/VPA    │  │• Memory Mgmt│  │• CDN        │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │  STORAGE    │  │INFRASTRUCTURE│  │ MONITORING  │            │
│  │OPTIMIZATION │  │ OPTIMIZATION │  │OPTIMIZATION │            │
│  │             │  │              │  │             │            │
│  │• SSD/NVMe   │  │• Node Types  │  │• Sampling   │            │
│  │• Caching    │  │• Spot Inst   │  │• Aggregation│            │
│  │• Compression│  │• Karpenter   │  │• Retention  │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## Infrastructure Optimization

### Node Optimization

#### AWS EKS Node Optimization
```hcl
# Optimized EKS node groups
resource "aws_eks_node_group" "optimized" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "optimized-nodes"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids

  # Performance-optimized instance types
  instance_types = ["m6i.xlarge", "m6i.2xlarge", "c6i.2xlarge"]
  
  # Enable nitro system for better performance
  ami_type       = "AL2_x86_64"
  capacity_type  = "ON_DEMAND"  # Use spot for non-critical workloads
  
  scaling_config {
    desired_size = 3
    max_size     = 20
    min_size     = 1
  }

  # Optimize EBS volumes
  disk_size = 100  # GB, SSD by default

  # Performance-focused launch template
  launch_template {
    id      = aws_launch_template.optimized.id
    version = "$Latest"
  }

  # Taints for dedicated workloads
  taint {
    key    = "performance"
    value  = "optimized"
    effect = "NO_SCHEDULE"
  }
}

# Optimized launch template
resource "aws_launch_template" "optimized" {
  name_prefix   = "eks-optimized-"
  image_id      = data.aws_ami.eks_worker.id
  instance_type = "m6i.xlarge"

  # Enhanced networking
  network_interfaces {
    associate_public_ip_address = false
    security_groups            = [aws_security_group.node.id]
    delete_on_termination      = true
  }

  # Optimized EBS configuration
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 100
      volume_type          = "gp3"  # Latest generation SSD
      iops                 = 3000   # Provisioned IOPS
      throughput           = 125    # MB/s
      encrypted            = true
      delete_on_termination = true
    }
  }

  # Performance-focused user data
  user_data = base64encode(templatefile("${path.module}/userdata.sh", {
    cluster_name = aws_eks_cluster.main.name
    endpoint     = aws_eks_cluster.main.endpoint
    ca_data      = aws_eks_cluster.main.certificate_authority[0].data
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "eks-optimized-node"
      Performance = "high"
    }
  }
}
```

#### Karpenter Performance Configuration
```yaml
# High-performance Karpenter provisioner
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: performance-provisioner
spec:
  # Resource limits
  limits:
    resources:
      cpu: 10000
      memory: 10000Gi
      nvidia.com/gpu: 100

  # Performance-focused requirements
  requirements:
    # Latest generation instances
    - key: karpenter.sh/capacity-type
      operator: In
      values: ["on-demand"]  # Consistent performance
    
    # High-performance instance families
    - key: node.kubernetes.io/instance-type
      operator: In
      values: ["m6i.large", "m6i.xlarge", "m6i.2xlarge", "c6i.xlarge", "c6i.2xlarge", "r6i.xlarge"]
    
    # Enhanced networking
    - key: kubernetes.io/arch
      operator: In
      values: ["amd64"]

  # Fast provisioning
  ttlSecondsAfterEmpty: 30  # Quick scale-down
  ttlSecondsUntilExpired: 2592000  # 30 days

  # Performance taints
  taints:
    - key: performance-tier
      value: high
      effect: NoSchedule

  # Optimized user data
  userData: |
    #!/bin/bash
    /etc/eks/bootstrap.sh performance-cluster
    
    # Kernel optimizations
    echo 'net.core.somaxconn = 65535' >> /etc/sysctl.conf
    echo 'net.ipv4.tcp_max_syn_backlog = 65535' >> /etc/sysctl.conf
    echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
    sysctl -p
    
    # CPU governor for performance
    echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

---
# Performance-focused node pool
apiVersion: karpenter.k8s.aws/v1alpha1
kind: AWSNodePool
metadata:
  name: performance-nodepool
spec:
  # Instance configuration
  amiFamily: AL2
  
  # Performance storage
  blockDeviceMappings:
    - deviceName: /dev/xvda
      ebs:
        volumeSize: 100Gi
        volumeType: gp3
        iops: 3000
        throughput: 125
        encrypted: true

  # Enhanced networking
  metadataOptions:
    httpEndpoint: enabled
    httpProtocolIPv6: disabled
    httpPutResponseHopLimit: 2
    httpTokens: required

  # Performance security groups
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: "performance-cluster"
        Performance: "high"
```

### Storage Performance

#### High-Performance Storage Classes
```yaml
# NVMe SSD storage class for AWS
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
  iops: "16000"      # Maximum IOPS
  throughput: "1000"  # MB/s
  encrypted: "true"
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete

---
# Ultra-fast storage for databases
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ultra-fast
provisioner: ebs.csi.aws.com
parameters:
  type: io2
  iops: "64000"      # Ultra-high IOPS
  encrypted: "true"
allowVolumeExpansion: true
volumeBindingMode: Immediate
reclaimPolicy: Retain

---
# Azure Premium SSD
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: azure-premium
provisioner: disk.csi.azure.com
parameters:
  skuName: Premium_LRS
  cachingmode: ReadOnly
  kind: Managed
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer

---
# GCP SSD Persistent Disk
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: gcp-ssd
provisioner: pd.csi.storage.gke.io
parameters:
  type: pd-ssd
  replication-type: regional-pd
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
```

#### Storage Optimization Techniques
```yaml
# Database with optimized storage
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: high-performance-db
spec:
  serviceName: db-service
  replicas: 3
  selector:
    matchLabels:
      app: high-performance-db
  template:
    metadata:
      labels:
        app: high-performance-db
    spec:
      # Performance-focused scheduling
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - high-performance-db
            topologyKey: kubernetes.io/hostname
      
      containers:
      - name: database
        image: postgres:15-alpine
        resources:
          requests:
            cpu: "2"
            memory: "4Gi"
          limits:
            cpu: "4"
            memory: "8Gi"
        
        # Database performance tuning
        env:
        - name: POSTGRES_DB
          value: "performance_db"
        - name: POSTGRES_USER
          value: "postgres"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
        
        # PostgreSQL performance configuration
        - name: POSTGRES_INITDB_ARGS
          value: "--data-checksums"
        
        # Mount optimizations
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
          subPath: postgres
        - name: config
          mountPath: /etc/postgresql/postgresql.conf
          subPath: postgresql.conf
        - name: tmpfs
          mountPath: /tmp
        
        # Performance-focused probes
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
        
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3

      volumes:
      - name: config
        configMap:
          name: postgres-config
      - name: tmpfs
        emptyDir:
          medium: Memory
          sizeLimit: 1Gi

  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: ultra-fast
      resources:
        requests:
          storage: 100Gi

---
# PostgreSQL performance configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-config
data:
  postgresql.conf: |
    # Memory settings
    shared_buffers = 2GB
    effective_cache_size = 6GB
    work_mem = 64MB
    maintenance_work_mem = 512MB
    
    # Checkpoint settings
    checkpoint_completion_target = 0.9
    wal_buffers = 64MB
    
    # Connection settings
    max_connections = 200
    
    # Query planner
    random_page_cost = 1.1  # SSD optimization
    effective_io_concurrency = 200
    
    # WAL settings
    wal_level = replica
    max_wal_size = 4GB
    min_wal_size = 1GB
    
    # Logging
    log_min_duration_statement = 1000
    log_checkpoints = on
    log_connections = on
    log_disconnections = on
    log_lock_waits = on
```

## Network Performance

### Cilium eBPF Optimization
```yaml
# High-performance Cilium configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  # Enable eBPF-based datapath
  datapath-mode: "veth"
  enable-bpf-masquerade: "true"
  enable-ip-masq-agent: "false"
  
  # Performance optimizations
  enable-bandwidth-manager: "true"
  enable-local-redirect-policy: "true"
  enable-host-legacy-routing: "false"
  
  # Kernel bypass optimizations
  enable-host-port: "true"
  enable-external-ips: "true"
  enable-node-port: "true"
  
  # CPU and memory optimizations
  operator-prometheus-serve-addr: ":9963"
  prometheus-serve-addr: ":9962"
  
  # Network policy optimization
  enable-policy: "default"
  policy-enforcement-mode: "default"
  
  # Load balancing
  enable-session-affinity: "true"
  enable-l7-proxy: "true"
  
  # Monitoring optimization
  monitor-aggregation: "medium"
  monitor-aggregation-interval: "5s"

---
# Cilium performance tuning
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cilium
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - name: cilium-agent
        image: quay.io/cilium/cilium:v1.14.0
        resources:
          requests:
            cpu: 100m
            memory: 512Mi
          limits:
            cpu: 4000m
            memory: 4Gi
        
        # Performance environment variables
        env:
        - name: CILIUM_PROMETHEUS_SERVE_ADDR
          value: ":9962"
        - name: CILIUM_OPERATOR_PROMETHEUS_SERVE_ADDR
          value: ":9963"
        
        # Kernel optimization arguments
        args:
        - --config-dir=/tmp/cilium/config-map
        - --enable-bpf-clock-probe
        - --sockops-enable
        - --enable-bandwidth-manager
        - --enable-local-redirect-policy
```

### Load Balancer Optimization
```yaml
# High-performance ingress controller
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-ingress-controller
  namespace: ingress-nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx-ingress-controller
  template:
    metadata:
      labels:
        app: nginx-ingress-controller
    spec:
      # Performance scheduling
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - nginx-ingress-controller
              topologyKey: kubernetes.io/hostname
      
      containers:
      - name: nginx-ingress-controller
        image: k8s.gcr.io/ingress-nginx/controller:v1.8.0
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 2Gi
        
        # Performance arguments
        args:
        - /nginx-ingress-controller
        - --configmap=$(POD_NAMESPACE)/nginx-configuration
        - --tcp-services-configmap=$(POD_NAMESPACE)/tcp-services
        - --udp-services-configmap=$(POD_NAMESPACE)/udp-services
        - --publish-service=$(POD_NAMESPACE)/ingress-nginx
        - --annotations-prefix=nginx.ingress.kubernetes.io
        - --enable-ssl-passthrough
        - --default-ssl-certificate=$(POD_NAMESPACE)/default-ssl-certificate
        - --max-worker-connections=65536
        - --max-worker-open-files=65536
        
        # Performance environment variables
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace

---
# NGINX performance configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-configuration
  namespace: ingress-nginx
data:
  # Worker process optimization
  worker-processes: "auto"
  worker-connections: "65536"
  worker-rlimit-nofile: "65536"
  
  # Performance settings
  use-gzip: "true"
  gzip-level: "6"
  gzip-types: "text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript"
  
  # Connection optimization
  keep-alive: "75"
  keep-alive-requests: "1000"
  upstream-keepalive-connections: "320"
  upstream-keepalive-requests: "10000"
  upstream-keepalive-timeout: "60"
  
  # Buffer optimization
  client-body-buffer-size: "128k"
  client-header-buffer-size: "4k"
  large-client-header-buffers: "4 16k"
  proxy-buffer-size: "128k"
  proxy-buffers: "4 256k"
  proxy-busy-buffers-size: "256k"
  
  # Timeout optimization
  client-body-timeout: "60"
  client-header-timeout: "60"
  proxy-connect-timeout: "5"
  proxy-send-timeout: "60"
  proxy-read-timeout: "60"
  
  # SSL optimization
  ssl-protocols: "TLSv1.2 TLSv1.3"
  ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
  ssl-session-cache: "shared:SSL:10m"
  ssl-session-timeout: "10m"
```

## Application Performance

### Resource Optimization

#### Horizontal Pod Autoscaler (HPA)
```yaml
# Performance-focused HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  minReplicas: 3
  maxReplicas: 100
  
  # Multiple metrics for better scaling decisions
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  
  # Custom metrics for application-specific scaling
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
  
  # External metrics (e.g., queue length)
  - type: External
    external:
      metric:
        name: queue_length
        selector:
          matchLabels:
            queue: web-app-queue
      target:
        type: Value
        value: "100"
  
  # Scaling behavior optimization
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300  # 5 minutes
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
      - type: Pods
        value: 5
        periodSeconds: 60
      selectPolicy: Min
    
    scaleUp:
      stabilizationWindowSeconds: 60   # 1 minute
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
      - type: Pods
        value: 10
        periodSeconds: 30
      selectPolicy: Max
```

#### Vertical Pod Autoscaler (VPA)
```yaml
# VPA for automatic resource optimization
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: web-app-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  
  updatePolicy:
    updateMode: "Auto"  # Automatically apply recommendations
  
  resourcePolicy:
    containerPolicies:
    - containerName: web-app
      # Minimum resources to ensure performance
      minAllowed:
        cpu: 100m
        memory: 128Mi
      
      # Maximum resources to prevent over-allocation
      maxAllowed:
        cpu: 4000m
        memory: 8Gi
      
      # Resource scaling policies
      controlledResources: ["cpu", "memory"]
      controlledValues: RequestsAndLimits
```

### JVM Performance Tuning

#### Java Application Optimization
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: java-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: java-app
  template:
    metadata:
      labels:
        app: java-app
    spec:
      containers:
      - name: java-app
        image: openjdk:17-jre-slim
        resources:
          requests:
            cpu: 1000m
            memory: 2Gi
          limits:
            cpu: 2000m
            memory: 4Gi
        
        # JVM performance tuning
        env:
        - name: JAVA_OPTS
          value: >-
            -server
            -Xms2g
            -Xmx3g
            -XX:+UseG1GC
            -XX:MaxGCPauseMillis=200
            -XX:+UseStringDeduplication
            -XX:+OptimizeStringConcat
            -XX:+UseCompressedOops
            -XX:+UseCompressedClassPointers
            -XX:+UnlockExperimentalVMOptions
            -XX:+UseCGroupMemoryLimitForHeap
            -XX:+PrintGCDetails
            -XX:+PrintGCTimeStamps
            -XX:+PrintGCApplicationStoppedTime
            -Xloggc:/var/log/gc.log
            -XX:+UseGCLogFileRotation
            -XX:NumberOfGCLogFiles=5
            -XX:GCLogFileSize=10M
            -Djava.security.egd=file:/dev/./urandom
            -Dspring.profiles.active=production
        
        # Application-specific optimizations
        - name: SPRING_OPTS
          value: >-
            --server.tomcat.max-threads=200
            --server.tomcat.min-spare-threads=20
            --server.tomcat.max-connections=8192
            --server.tomcat.accept-count=1000
            --server.tomcat.connection-timeout=20000
            --spring.datasource.hikari.maximum-pool-size=20
            --spring.datasource.hikari.minimum-idle=5
            --spring.datasource.hikari.connection-timeout=30000
            --spring.datasource.hikari.idle-timeout=600000
            --spring.datasource.hikari.max-lifetime=1800000
        
        # Performance monitoring
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8081
          name: management
        
        # Optimized health checks
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: management
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: management
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        
        # Volume mounts for performance
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: logs
          mountPath: /var/log
      
      volumes:
      - name: tmp
        emptyDir:
          medium: Memory
          sizeLimit: 1Gi
      - name: logs
        emptyDir:
          sizeLimit: 5Gi
```

### Database Performance

#### Redis Performance Optimization
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
spec:
  serviceName: redis-cluster
  replicas: 6
  selector:
    matchLabels:
      app: redis-cluster
  template:
    metadata:
      labels:
        app: redis-cluster
    spec:
      # Performance-focused scheduling
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - redis-cluster
            topologyKey: kubernetes.io/hostname
      
      containers:
      - name: redis
        image: redis:7-alpine
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 1000m
            memory: 2Gi
        
        # Redis performance configuration
        command:
        - redis-server
        - /etc/redis/redis.conf
        
        ports:
        - containerPort: 6379
          name: redis
        - containerPort: 16379
          name: cluster
        
        # Performance-optimized volume mounts
        volumeMounts:
        - name: data
          mountPath: /data
        - name: config
          mountPath: /etc/redis
        
        # Fast health checks
        livenessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
        
        readinessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3

      volumes:
      - name: config
        configMap:
          name: redis-config

  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 50Gi

---
# Redis performance configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
data:
  redis.conf: |
    # Network optimization
    tcp-backlog 511
    timeout 0
    tcp-keepalive 300
    
    # Memory optimization
    maxmemory 1.5gb
    maxmemory-policy allkeys-lru
    
    # Persistence optimization
    save 900 1
    save 300 10
    save 60 10000
    stop-writes-on-bgsave-error yes
    rdbcompression yes
    rdbchecksum yes
    
    # AOF optimization
    appendonly yes
    appendfilename "appendonly.aof"
    appendfsync everysec
    no-appendfsync-on-rewrite no
    auto-aof-rewrite-percentage 100
    auto-aof-rewrite-min-size 64mb
    
    # Cluster configuration
    cluster-enabled yes
    cluster-config-file nodes.conf
    cluster-node-timeout 15000
    cluster-announce-ip $(POD_IP)
    cluster-announce-port 6379
    cluster-announce-bus-port 16379
    
    # Performance tuning
    hash-max-ziplist-entries 512
    hash-max-ziplist-value 64
    list-max-ziplist-size -2
    list-compress-depth 0
    set-max-intset-entries 512
    zset-max-ziplist-entries 128
    zset-max-ziplist-value 64
    
    # Logging
    loglevel notice
    logfile ""
```

## Monitoring Performance

### High-Performance Metrics Collection
```yaml
# Optimized Prometheus configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
      external_labels:
        cluster: 'multi-cloud-k8s'
    
    # Performance-optimized scrape configs
    scrape_configs:
    - job_name: 'kubernetes-apiservers'
      kubernetes_sd_configs:
      - role: endpoints
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      relabel_configs:
      - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
        action: keep
        regex: default;kubernetes;https
      # Reduce cardinality
      metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'apiserver_request_duration_seconds_bucket'
        target_label: __tmp_bucket
        replacement: '${1}'
      - source_labels: [__tmp_bucket]
        regex: '0.005|0.01|0.025|0.05|0.1|0.25|0.5|1|2.5|5|10'
        action: keep
    
    - job_name: 'kubernetes-nodes'
      kubernetes_sd_configs:
      - role: node
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)
      # Sample high-cardinality metrics less frequently
      metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'node_filesystem_.*'
        target_label: __tmp_sample
        replacement: '60s'
    
    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      # Performance optimization: scrape only annotated pods
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
    
    # Recording rules for performance
    rule_files:
    - "/etc/prometheus/rules/*.yml"

---
# Performance-focused recording rules
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-rules
  namespace: monitoring
data:
  performance.yml: |
    groups:
    - name: performance.rules
      interval: 30s
      rules:
      # CPU utilization aggregations
      - record: cluster:cpu_usage:rate5m
        expr: sum(rate(container_cpu_usage_seconds_total{container!="POD",container!=""}[5m])) by (cluster)
      
      - record: namespace:cpu_usage:rate5m
        expr: sum(rate(container_cpu_usage_seconds_total{container!="POD",container!=""}[5m])) by (namespace)
      
      # Memory utilization aggregations
      - record: cluster:memory_usage:bytes
        expr: sum(container_memory_working_set_bytes{container!="POD",container!=""}) by (cluster)
      
      - record: namespace:memory_usage:bytes
        expr: sum(container_memory_working_set_bytes{container!="POD",container!=""}) by (namespace)
      
      # Network I/O aggregations
      - record: cluster:network_receive_bytes:rate5m
        expr: sum(rate(container_network_receive_bytes_total[5m])) by (cluster)
      
      - record: cluster:network_transmit_bytes:rate5m
        expr: sum(rate(container_network_transmit_bytes_total[5m])) by (cluster)
      
      # Disk I/O aggregations
      - record: cluster:disk_read_bytes:rate5m
        expr: sum(rate(container_fs_reads_bytes_total[5m])) by (cluster)
      
      - record: cluster:disk_write_bytes:rate5m
        expr: sum(rate(container_fs_writes_bytes_total[5m])) by (cluster)
```

### Performance Alerting
```yaml
# Performance-focused alerts
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: performance-alerts
  namespace: monitoring
spec:
  groups:
  - name: performance.rules
    rules:
    # High CPU utilization
    - alert: HighCPUUtilization
      expr: cluster:cpu_usage:rate5m > 0.8
      for: 5m
      labels:
        severity: warning
        category: performance
      annotations:
        summary: "High CPU utilization detected"
        description: "Cluster CPU utilization is {{ $value | humanizePercentage }} for more than 5 minutes"
        runbook_url: "https://runbooks.example.com/high-cpu"
    
    # High memory utilization
    - alert: HighMemoryUtilization
      expr: cluster:memory_usage:bytes / cluster:memory_capacity:bytes > 0.85
      for: 5m
      labels:
        severity: warning
        category: performance
      annotations:
        summary: "High memory utilization detected"
        description: "Cluster memory utilization is {{ $value | humanizePercentage }} for more than 5 minutes"
    
    # Slow API server response
    - alert: SlowAPIServerResponse
      expr: histogram_quantile(0.99, sum(rate(apiserver_request_duration_seconds_bucket{verb!="WATCH"}[5m])) by (le)) > 1
      for: 2m
      labels:
        severity: critical
        category: performance
      annotations:
        summary: "API server responding slowly"
        description: "99th percentile API server response time is {{ $value }}s"
    
    # High network latency
    - alert: HighNetworkLatency
      expr: histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) > 0.5
      for: 3m
      labels:
        severity: warning
        category: performance
      annotations:
        summary: "High network latency detected"
        description: "95th percentile request latency is {{ $value }}s"
    
    # Disk I/O saturation
    - alert: HighDiskIOUtilization
      expr: rate(node_disk_io_time_seconds_total[5m]) > 0.8
      for: 5m
      labels:
        severity: warning
        category: performance
      annotations:
        summary: "High disk I/O utilization"
        description: "Disk I/O utilization on {{ $labels.device }} is {{ $value | humanizePercentage }}"
```

## Cost Optimization

### Spot Instance Strategy
```yaml
# Mixed instance type deployment for cost optimization
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: cost-optimized
spec:
  limits:
    resources:
      cpu: 1000
      memory: 1000Gi
  
  requirements:
    # Mix of spot and on-demand
    - key: karpenter.sh/capacity-type
      operator: In
      values: ["spot", "on-demand"]
    
    # Diverse instance types for better spot availability
    - key: node.kubernetes.io/instance-type
      operator: In
      values: ["m5.large", "m5.xlarge", "m5a.large", "m5a.xlarge", "m4.large", "m4.xlarge"]
  
  # Quick replacement for spot interruptions
  ttlSecondsAfterEmpty: 30
  
  # Spot instance handling
  taints:
    - key: spot-instance
      value: "true"
      effect: NoSchedule

---
# Deployment with spot tolerance
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cost-optimized-app
spec:
  replicas: 10
  selector:
    matchLabels:
      app: cost-optimized-app
  template:
    metadata:
      labels:
        app: cost-optimized-app
    spec:
      # Tolerate spot instances
      tolerations:
      - key: spot-instance
        operator: Equal
        value: "true"
        effect: NoSchedule
      
      # Prefer spot instances for cost savings
      affinity:
        nodeAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            preference:
              matchExpressions:
              - key: karpenter.sh/capacity-type
                operator: In
                values: ["spot"]
      
      containers:
      - name: app
        image: nginx:alpine
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 200m
            memory: 256Mi
```

## Performance Testing

### Load Testing Configuration
```yaml
# K6 load testing job
apiVersion: batch/v1
kind: Job
metadata:
  name: performance-test
spec:
  template:
    spec:
      containers:
      - name: k6
        image: grafana/k6:latest
        command: ["k6", "run", "--vus", "100", "--duration", "10m", "/scripts/load-test.js"]
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 1Gi
        volumeMounts:
        - name: test-scripts
          mountPath: /scripts
      volumes:
      - name: test-scripts
        configMap:
          name: k6-scripts
      restartPolicy: Never

---
# Load test script
apiVersion: v1
kind: ConfigMap
metadata:
  name: k6-scripts
data:
  load-test.js: |
    import http from 'k6/http';
    import { check, sleep } from 'k6';
    import { Rate } from 'k6/metrics';
    
    export let errorRate = new Rate('errors');
    
    export let options = {
      stages: [
        { duration: '2m', target: 10 },   // Ramp up
        { duration: '5m', target: 100 },  // Stay at 100 users
        { duration: '2m', target: 200 },  // Ramp up to 200 users
        { duration: '5m', target: 200 },  // Stay at 200 users
        { duration: '2m', target: 0 },    // Ramp down
      ],
      thresholds: {
        http_req_duration: ['p(95)<500'],  // 95% of requests under 500ms
        http_req_failed: ['rate<0.1'],     // Error rate under 10%
        errors: ['rate<0.1'],
      },
    };
    
    export default function() {
      let response = http.get('http://web-app-service.default.svc.cluster.local');
      
      check(response, {
        'status is 200': (r) => r.status === 200,
        'response time < 500ms': (r) => r.timings.duration < 500,
      }) || errorRate.add(1);
      
      sleep(1);
    }
```

---

*This performance tuning guide should be regularly updated based on performance testing results and new optimization techniques.* 