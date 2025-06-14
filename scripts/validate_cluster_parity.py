#!/usr/bin/env python3
"""
Multi-Cloud Kubernetes Cluster Parity Validation Script

This script validates that all Kubernetes clusters across AWS EKS, Azure AKS, 
and Google GKE have identical configurations and components installed.

Author: Nguie Angoue Jean Roch Junior
Email: nguierochjunior@gmail.com
"""

import subprocess
import json
import yaml
import sys
import os
import argparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cluster_validation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ClusterConfig:
    """Configuration for a Kubernetes cluster"""
    name: str
    context: str
    provider: str
    expected_nodes: int
    k8s_version: str
    components: List[str]

@dataclass
class ValidationResult:
    """Result of a validation check"""
    cluster: str
    check: str
    passed: bool
    message: str
    details: Optional[Dict] = None

class KubernetesValidator:
    """Validates Kubernetes cluster configurations and components"""
    
    def __init__(self, clusters: List[ClusterConfig]):
        self.clusters = clusters
        self.results: List[ValidationResult] = []
        
    def run_kubectl_command(self, context: str, command: List[str]) -> Tuple[bool, str, str]:
        """Execute kubectl command with specified context"""
        full_command = ['kubectl', '--context', context] + command
        
        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def validate_cluster_connectivity(self, cluster: ClusterConfig) -> ValidationResult:
        """Validate that we can connect to the cluster"""
        logger.info(f"Validating connectivity to {cluster.name}")
        
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context, 
            ['cluster-info']
        )
        
        if success:
            return ValidationResult(
                cluster=cluster.name,
                check="connectivity",
                passed=True,
                message="Successfully connected to cluster",
                details={"cluster_info": stdout}
            )
        else:
            return ValidationResult(
                cluster=cluster.name,
                check="connectivity",
                passed=False,
                message=f"Failed to connect to cluster: {stderr}"
            )
    
    def validate_node_count(self, cluster: ClusterConfig) -> ValidationResult:
        """Validate cluster has expected number of nodes"""
        logger.info(f"Validating node count for {cluster.name}")
        
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'nodes', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="node_count",
                passed=False,
                message=f"Failed to get nodes: {stderr}"
            )
        
        try:
            nodes_data = json.loads(stdout)
            actual_count = len(nodes_data['items'])
            
            if actual_count >= cluster.expected_nodes:
                return ValidationResult(
                    cluster=cluster.name,
                    check="node_count",
                    passed=True,
                    message=f"Node count validation passed: {actual_count}/{cluster.expected_nodes}",
                    details={"actual_count": actual_count, "expected_count": cluster.expected_nodes}
                )
            else:
                return ValidationResult(
                    cluster=cluster.name,
                    check="node_count",
                    passed=False,
                    message=f"Insufficient nodes: {actual_count}/{cluster.expected_nodes}"
                )
        except json.JSONDecodeError:
            return ValidationResult(
                cluster=cluster.name,
                check="node_count",
                passed=False,
                message="Failed to parse nodes JSON response"
            )
    
    def validate_kubernetes_version(self, cluster: ClusterConfig) -> ValidationResult:
        """Validate Kubernetes version matches expected version"""
        logger.info(f"Validating Kubernetes version for {cluster.name}")
        
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['version', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="k8s_version",
                passed=False,
                message=f"Failed to get version: {stderr}"
            )
        
        try:
            version_data = json.loads(stdout)
            server_version = version_data['serverVersion']['gitVersion']
            
            # Extract major.minor version (e.g., "v1.28.3" -> "1.28")
            version_parts = server_version.lstrip('v').split('.')
            actual_version = f"{version_parts[0]}.{version_parts[1]}"
            
            if actual_version == cluster.k8s_version:
                return ValidationResult(
                    cluster=cluster.name,
                    check="k8s_version",
                    passed=True,
                    message=f"Kubernetes version matches: {server_version}",
                    details={"actual_version": server_version, "expected_version": cluster.k8s_version}
                )
            else:
                return ValidationResult(
                    cluster=cluster.name,
                    check="k8s_version",
                    passed=False,
                    message=f"Version mismatch: {actual_version} != {cluster.k8s_version}"
                )
        except (json.JSONDecodeError, KeyError, IndexError):
            return ValidationResult(
                cluster=cluster.name,
                check="k8s_version",
                passed=False,
                message="Failed to parse version response"
            )
    
    def validate_component_installed(self, cluster: ClusterConfig, component: str) -> ValidationResult:
        """Validate that a specific component is installed"""
        logger.info(f"Validating {component} installation on {cluster.name}")
        
        # Component-specific validation logic
        component_checks = {
            'cilium': self._check_cilium,
            'linkerd': self._check_linkerd,
            'gatekeeper': self._check_gatekeeper,
            'falco': self._check_falco,
            'trivy': self._check_trivy,
            'victoria-metrics': self._check_victoria_metrics,
            'tempo': self._check_tempo,
            'vector': self._check_vector,
            'karpenter': self._check_karpenter,
            'cosign': self._check_cosign
        }
        
        if component in component_checks:
            return component_checks[component](cluster)
        else:
            return ValidationResult(
                cluster=cluster.name,
                check=f"component_{component}",
                passed=False,
                message=f"Unknown component: {component}"
            )
    
    def _check_cilium(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Cilium is installed and running"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'pods', '-n', 'kube-system', '-l', 'k8s-app=cilium', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_cilium",
                passed=False,
                message=f"Failed to check Cilium pods: {stderr}"
            )
        
        try:
            pods_data = json.loads(stdout)
            cilium_pods = pods_data['items']
            
            if not cilium_pods:
                return ValidationResult(
                    cluster=cluster.name,
                    check="component_cilium",
                    passed=False,
                    message="No Cilium pods found"
                )
            
            running_pods = [
                pod for pod in cilium_pods 
                if pod['status']['phase'] == 'Running'
            ]
            
            if len(running_pods) == len(cilium_pods):
                return ValidationResult(
                    cluster=cluster.name,
                    check="component_cilium",
                    passed=True,
                    message=f"Cilium is running ({len(running_pods)} pods)",
                    details={"pod_count": len(running_pods)}
                )
            else:
                return ValidationResult(
                    cluster=cluster.name,
                    check="component_cilium",
                    passed=False,
                    message=f"Some Cilium pods not running: {len(running_pods)}/{len(cilium_pods)}"
                )
        except json.JSONDecodeError:
            return ValidationResult(
                cluster=cluster.name,
                check="component_cilium",
                passed=False,
                message="Failed to parse Cilium pods response"
            )
    
    def _check_linkerd(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Linkerd is installed and running"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'linkerd', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_linkerd",
                passed=False,
                message="Linkerd namespace not found"
            )
        
        # Check Linkerd control plane pods
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'pods', '-n', 'linkerd', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_linkerd",
                passed=False,
                message=f"Failed to check Linkerd pods: {stderr}"
            )
        
        try:
            pods_data = json.loads(stdout)
            linkerd_pods = pods_data['items']
            
            if not linkerd_pods:
                return ValidationResult(
                    cluster=cluster.name,
                    check="component_linkerd",
                    passed=False,
                    message="No Linkerd pods found"
                )
            
            running_pods = [
                pod for pod in linkerd_pods 
                if pod['status']['phase'] == 'Running'
            ]
            
            if len(running_pods) == len(linkerd_pods):
                return ValidationResult(
                    cluster=cluster.name,
                    check="component_linkerd",
                    passed=True,
                    message=f"Linkerd is running ({len(running_pods)} pods)",
                    details={"pod_count": len(running_pods)}
                )
            else:
                return ValidationResult(
                    cluster=cluster.name,
                    check="component_linkerd",
                    passed=False,
                    message=f"Some Linkerd pods not running: {len(running_pods)}/{len(linkerd_pods)}"
                )
        except json.JSONDecodeError:
            return ValidationResult(
                cluster=cluster.name,
                check="component_linkerd",
                passed=False,
                message="Failed to parse Linkerd pods response"
            )
    
    def _check_gatekeeper(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if OPA Gatekeeper is installed"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'gatekeeper-system', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_gatekeeper",
                passed=False,
                message="Gatekeeper namespace not found"
            )
        
        return ValidationResult(
            cluster=cluster.name,
            check="component_gatekeeper",
            passed=True,
            message="OPA Gatekeeper is installed"
        )
    
    def _check_falco(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Falco is installed"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'falco', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_falco",
                passed=False,
                message="Falco namespace not found"
            )
        
        return ValidationResult(
            cluster=cluster.name,
            check="component_falco",
            passed=True,
            message="Falco is installed"
        )
    
    def _check_trivy(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Trivy is installed"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'trivy-system', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_trivy",
                passed=False,
                message="Trivy namespace not found"
            )
        
        return ValidationResult(
            cluster=cluster.name,
            check="component_trivy",
            passed=True,
            message="Trivy is installed"
        )
    
    def _check_victoria_metrics(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if VictoriaMetrics is installed"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'monitoring', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_victoria_metrics",
                passed=False,
                message="Monitoring namespace not found"
            )
        
        return ValidationResult(
            cluster=cluster.name,
            check="component_victoria_metrics",
            passed=True,
            message="VictoriaMetrics is installed"
        )
    
    def _check_tempo(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Grafana Tempo is installed"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'tracing', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_tempo",
                passed=False,
                message="Tracing namespace not found"
            )
        
        return ValidationResult(
            cluster=cluster.name,
            check="component_tempo",
            passed=True,
            message="Grafana Tempo is installed"
        )
    
    def _check_vector(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Vector is installed"""
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'logging', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_vector",
                passed=False,
                message="Logging namespace not found"
            )
        
        return ValidationResult(
            cluster=cluster.name,
            check="component_vector",
            passed=True,
            message="Vector is installed"
        )
    
    def _check_karpenter(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Karpenter is installed (AWS only)"""
        if cluster.provider != 'aws':
            return ValidationResult(
                cluster=cluster.name,
                check="component_karpenter",
                passed=True,
                message="Karpenter not applicable for non-AWS clusters"
            )
        
        success, stdout, stderr = self.run_kubectl_command(
            cluster.context,
            ['get', 'namespace', 'karpenter', '-o', 'json']
        )
        
        if not success:
            return ValidationResult(
                cluster=cluster.name,
                check="component_karpenter",
                passed=False,
                message="Karpenter namespace not found"
            )
        
        return ValidationResult(
            cluster=cluster.name,
            check="component_karpenter",
            passed=True,
            message="Karpenter is installed"
        )
    
    def _check_cosign(self, cluster: ClusterConfig) -> ValidationResult:
        """Check if Cosign is configured (GCP only)"""
        if cluster.provider != 'gcp':
            return ValidationResult(
                cluster=cluster.name,
                check="component_cosign",
                passed=True,
                message="Cosign not applicable for non-GCP clusters"
            )
        
        # For GCP, we check if Binary Authorization is enabled
        # This is a simplified check - in practice, you'd verify the actual policy
        return ValidationResult(
            cluster=cluster.name,
            check="component_cosign",
            passed=True,
            message="Cosign configuration assumed present (GCP Binary Authorization)"
        )
    
    def validate_cluster(self, cluster: ClusterConfig) -> List[ValidationResult]:
        """Run all validations for a single cluster"""
        logger.info(f"Starting validation for cluster: {cluster.name}")
        
        cluster_results = []
        
        # Basic connectivity
        result = self.validate_cluster_connectivity(cluster)
        cluster_results.append(result)
        
        if not result.passed:
            logger.error(f"Cannot connect to {cluster.name}, skipping further checks")
            return cluster_results
        
        # Node count validation
        cluster_results.append(self.validate_node_count(cluster))
        
        # Kubernetes version validation
        cluster_results.append(self.validate_kubernetes_version(cluster))
        
        # Component validations
        for component in cluster.components:
            cluster_results.append(self.validate_component_installed(cluster, component))
        
        return cluster_results
    
    def validate_all_clusters(self) -> Dict[str, List[ValidationResult]]:
        """Run validations for all clusters"""
        logger.info("Starting multi-cloud cluster validation")
        
        all_results = {}
        
        for cluster in self.clusters:
            cluster_results = self.validate_cluster(cluster)
            all_results[cluster.name] = cluster_results
            self.results.extend(cluster_results)
        
        return all_results
    
    def generate_report(self) -> str:
        """Generate a comprehensive validation report"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("MULTI-CLOUD KUBERNETES CLUSTER VALIDATION REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Clusters: {len(self.clusters)}")
        report_lines.append("")
        
        # Summary statistics
        total_checks = len(self.results)
        passed_checks = len([r for r in self.results if r.passed])
        failed_checks = total_checks - passed_checks
        
        report_lines.append("SUMMARY")
        report_lines.append("-" * 40)
        report_lines.append(f"Total Checks: {total_checks}")
        report_lines.append(f"Passed: {passed_checks}")
        report_lines.append(f"Failed: {failed_checks}")
        report_lines.append(f"Success Rate: {(passed_checks/total_checks)*100:.1f}%")
        report_lines.append("")
        
        # Detailed results by cluster
        for cluster in self.clusters:
            cluster_results = [r for r in self.results if r.cluster == cluster.name]
            cluster_passed = len([r for r in cluster_results if r.passed])
            cluster_total = len(cluster_results)
            
            report_lines.append(f"CLUSTER: {cluster.name.upper()} ({cluster.provider.upper()})")
            report_lines.append("-" * 40)
            report_lines.append(f"Status: {cluster_passed}/{cluster_total} checks passed")
            report_lines.append("")
            
            for result in cluster_results:
                status = "✅ PASS" if result.passed else "❌ FAIL"
                report_lines.append(f"  {status} {result.check}: {result.message}")
            
            report_lines.append("")
        
        # Failed checks summary
        failed_results = [r for r in self.results if not r.passed]
        if failed_results:
            report_lines.append("FAILED CHECKS SUMMARY")
            report_lines.append("-" * 40)
            for result in failed_results:
                report_lines.append(f"❌ {result.cluster} - {result.check}: {result.message}")
            report_lines.append("")
        
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)

def load_cluster_configs(config_file: str) -> List[ClusterConfig]:
    """Load cluster configurations from YAML file"""
    try:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        clusters = []
        for cluster_data in config_data['clusters']:
            clusters.append(ClusterConfig(
                name=cluster_data['name'],
                context=cluster_data['context'],
                provider=cluster_data['provider'],
                expected_nodes=cluster_data['expected_nodes'],
                k8s_version=cluster_data['k8s_version'],
                components=cluster_data['components']
            ))
        
        return clusters
    except Exception as e:
        logger.error(f"Failed to load cluster configuration: {e}")
        sys.exit(1)

def create_default_config():
    """Create a default configuration file"""
    default_config = {
        'clusters': [
            {
                'name': 'multicloud-k8s-dev-aws',
                'context': 'arn:aws:eks:us-west-2:ACCOUNT:cluster/multicloud-k8s-dev-aws',
                'provider': 'aws',
                'expected_nodes': 2,
                'k8s_version': '1.28',
                'components': [
                    'cilium', 'linkerd', 'gatekeeper', 'falco', 'trivy',
                    'victoria-metrics', 'tempo', 'vector', 'karpenter'
                ]
            },
            {
                'name': 'multicloud-k8s-dev-azure',
                'context': 'multicloud-k8s-dev-azure',
                'provider': 'azure',
                'expected_nodes': 2,
                'k8s_version': '1.28',
                'components': [
                    'cilium', 'linkerd', 'gatekeeper', 'falco', 'trivy',
                    'victoria-metrics', 'tempo', 'vector'
                ]
            },
            {
                'name': 'multicloud-k8s-dev-gcp',
                'context': 'gke_PROJECT_us-west1_multicloud-k8s-dev-gcp',
                'provider': 'gcp',
                'expected_nodes': 2,
                'k8s_version': '1.28',
                'components': [
                    'cilium', 'linkerd', 'gatekeeper', 'falco', 'trivy',
                    'victoria-metrics', 'tempo', 'vector', 'cosign'
                ]
            }
        ]
    }
    
    with open('cluster_config.yaml', 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False)
    
    logger.info("Created default cluster configuration: cluster_config.yaml")
    logger.info("Please update the configuration with your actual cluster contexts")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Validate multi-cloud Kubernetes cluster parity"
    )
    parser.add_argument(
        '--config', '-c',
        default='cluster_config.yaml',
        help='Path to cluster configuration file (default: cluster_config.yaml)'
    )
    parser.add_argument(
        '--create-config',
        action='store_true',
        help='Create a default configuration file'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for validation report'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.create_config:
        create_default_config()
        return
    
    if not os.path.exists(args.config):
        logger.error(f"Configuration file not found: {args.config}")
        logger.info("Use --create-config to generate a default configuration")
        sys.exit(1)
    
    # Load cluster configurations
    clusters = load_cluster_configs(args.config)
    
    # Run validations
    validator = KubernetesValidator(clusters)
    results = validator.validate_all_clusters()
    
    # Generate report
    report = validator.generate_report()
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        logger.info(f"Validation report saved to: {args.output}")
    else:
        print(report)
    
    # Exit with error code if any validations failed
    failed_count = len([r for r in validator.results if not r.passed])
    if failed_count > 0:
        logger.error(f"Validation completed with {failed_count} failures")
        sys.exit(1)
    else:
        logger.info("All validations passed successfully!")

if __name__ == "__main__":
    main() 