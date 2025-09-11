"""
Multi-cloud risk detection algorithms for identifying security vulnerabilities.
"""
from typing import Dict, Any, List, Optional, Set, Tuple
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from dataclasses import dataclass
from datetime import datetime, timedelta
import networkx as nx

from ..models import CloudResource, ResourceRelationship, SecurityFinding, CloudProvider, CloudAccount
from .graph_analysis import CloudResourceGraph, GraphNeuralAnalyzer


@dataclass
class RiskPath:
    """Represents a potential attack or risk path."""
    path_id: str
    path_type: str  # privilege_escalation, data_exfiltration, lateral_movement
    severity: str
    risk_score: float
    resources: List[str]
    description: str
    attack_vectors: List[str]
    mitigation_steps: List[str]
    compliance_impact: List[str]


@dataclass
class ComplianceViolation:
    """Represents a compliance framework violation."""
    violation_id: str
    framework: str
    control_id: str
    severity: str
    resources: List[str]
    description: str
    remediation_priority: str


class MultiCloudRiskDetector:
    """Advanced risk detection engine for multi-cloud environments."""

    def __init__(self, db: Session):
        self.db = db
        self.graph_analyzer = GraphNeuralAnalyzer(db)

        # Risk detection rules
        self.privilege_escalation_patterns = [
            'public_to_admin',
            'service_to_service_escalation',
            'cross_account_assumption',
            'container_breakout'
        ]

        self.data_exfiltration_patterns = [
            'data_store_to_public',
            'cross_region_replication',
            'unauthorized_backup',
            'api_data_leakage'
        ]

        self.lateral_movement_patterns = [
            'cross_vpc_communication',
            'service_mesh_exploitation',
            'shared_credentials',
            'network_segmentation_bypass'
        ]

    def detect_privilege_escalation_paths(self, max_path_length: int = 5) -> List[RiskPath]:
        """Detect potential privilege escalation paths across cloud resources."""

        risk_paths = []

        # Build resource graph
        graph_builder = CloudResourceGraph(self.db)
        graph_builder.build_graph_from_db()
        graph = graph_builder.graph

        # Find resources with public access (potential entry points)
        entry_points = [
            node for node, attrs in graph.nodes(data=True)
            if attrs.get('public_access', False) or
            attrs.get('resource_type') in [
                'api_gateway', 'lambda_function', 'cloud_function']
        ]

        # Find high-privilege resources (targets)
        privilege_targets = [
            node for node, attrs in graph.nodes(data=True)
            if attrs.get('resource_type') in [
                'iam_role', 'iam_user', 'service_account',
                'admin_role', 'root_account', 'subscription_owner'
            ] or 'admin' in attrs.get('resource_type', '').lower()
        ]

        # Find paths from entry points to privilege targets
        for entry in entry_points:
            for target in privilege_targets:
                if entry != target:
                    try:
                        paths = list(nx.all_simple_paths(
                            graph, entry, target, cutoff=max_path_length
                        ))

                        for path in paths[:10]:  # Limit to prevent explosion
                            risk_path = self._analyze_privilege_escalation_path(
                                graph, path, graph_builder.resource_nodes
                            )
                            if risk_path:
                                risk_paths.append(risk_path)

                    except nx.NetworkXNoPath:
                        continue

        return sorted(risk_paths, key=lambda x: x.risk_score, reverse=True)

    def detect_data_exfiltration_risks(self) -> List[RiskPath]:
        """Detect potential data exfiltration paths."""

        risk_paths = []

        # Find data stores
        data_stores = self.db.query(CloudResource).filter(
            CloudResource.resource_type.in_([
                's3_bucket', 'rds_instance', 'dynamodb_table',
                'storage_bucket', 'cloud_sql_instance', 'firestore',
                'storage_account', 'cosmos_db', 'sql_database'
            ])
        ).all()

        # Find external access points
        external_access = self.db.query(CloudResource).filter(
            or_(
                CloudResource.public_access == True,
                CloudResource.resource_type.in_([
                    'api_gateway', 'load_balancer', 'cdn_distribution',
                    'cloud_function', 'app_service'
                ])
            )
        ).all()

        # Analyze paths from data stores to external access
        for data_store in data_stores:
            for external in external_access:
                if data_store.id != external.id:
                    # Check if there's a relationship path
                    path_exists = self._check_resource_connectivity(
                        data_store.id, external.id
                    )

                    if path_exists:
                        risk_path = self._create_data_exfiltration_risk(
                            data_store, external, path_exists
                        )
                        risk_paths.append(risk_path)

        return sorted(risk_paths, key=lambda x: x.risk_score, reverse=True)

    def detect_cross_cloud_risks(self) -> List[RiskPath]:
        """Detect risks spanning multiple cloud providers."""

        risk_paths = []

        # Get resources from different providers
        providers = self.db.query(CloudProvider).all()

        if len(providers) < 2:
            return risk_paths

        # Check for cross-cloud connections
        for i, provider1 in enumerate(providers):
            for provider2 in providers[i+1:]:
                cross_cloud_risks = self._analyze_cross_cloud_connections(
                    provider1, provider2
                )
                risk_paths.extend(cross_cloud_risks)

        return risk_paths

    def detect_network_segmentation_violations(self) -> List[RiskPath]:
        """Detect network segmentation violations."""

        violations = []

        # Find resources that should be isolated but have connections
        critical_resources = self.db.query(CloudResource).filter(
            or_(
                CloudResource.resource_type.in_([
                    'rds_instance', 'database', 'key_vault', 'secrets_manager'
                ]),
                CloudResource.resource_name.ilike('%prod%'),
                CloudResource.resource_name.ilike('%production%')
            )
        ).all()

        for resource in critical_resources:
            # Check for unexpected network connections
            connections = self._get_network_connections(resource)

            for connection in connections:
                if self._is_segmentation_violation(resource, connection):
                    violation = self._create_segmentation_violation_risk(
                        resource, connection
                    )
                    violations.append(violation)

        return violations

    def detect_compliance_violations(self, frameworks: List[str] = None) -> List[ComplianceViolation]:
        """Detect compliance framework violations."""

        if frameworks is None:
            frameworks = ['PCI DSS', 'SOC 2', 'ISO 27001', 'HIPAA', 'GDPR']

        violations = []

        for framework in frameworks:
            framework_violations = self._check_framework_compliance(framework)
            violations.extend(framework_violations)

        return violations

    def detect_insider_threat_risks(self) -> List[RiskPath]:
        """Detect potential insider threat vectors."""

        risks = []

        # Find overprivileged accounts
        overprivileged = self._find_overprivileged_accounts()

        # Find shared credentials
        shared_creds = self._find_shared_credentials()

        # Find excessive access patterns
        excessive_access = self._find_excessive_access_patterns()

        # Create risk paths for each finding
        for account in overprivileged:
            risk = self._create_insider_threat_risk(
                'overprivileged_account', account
            )
            risks.append(risk)

        for cred in shared_creds:
            risk = self._create_insider_threat_risk(
                'shared_credentials', cred
            )
            risks.append(risk)

        for access in excessive_access:
            risk = self._create_insider_threat_risk(
                'excessive_access', access
            )
            risks.append(risk)

        return risks

    def _analyze_privilege_escalation_path(
        self,
        graph: nx.DiGraph,
        path: List[str],
        resource_nodes: Dict[str, CloudResource]
    ) -> Optional[RiskPath]:
        """Analyze a potential privilege escalation path."""

        if len(path) < 2:
            return None

        # Calculate risk score based on path characteristics
        risk_score = 0.0
        attack_vectors = []

        # Entry point analysis
        entry_node = resource_nodes.get(path[0])
        if entry_node and entry_node.public_access:
            risk_score += 3.0
            attack_vectors.append("Public internet access")

        # Path complexity (shorter paths are riskier)
        path_length_penalty = (len(path) - 1) * 0.5
        risk_score = max(0, risk_score - path_length_penalty)

        # Target analysis
        target_node = resource_nodes.get(path[-1])
        if target_node:
            if 'admin' in target_node.resource_type.lower():
                risk_score += 4.0
                attack_vectors.append("Administrative access")
            elif target_node.resource_type in ['iam_role', 'service_account']:
                risk_score += 2.0
                attack_vectors.append("Service account access")

        # Intermediate nodes analysis
        for node_id in path[1:-1]:
            node = resource_nodes.get(node_id)
            if node:
                if not node.encryption_enabled:
                    risk_score += 1.0
                    attack_vectors.append("Unencrypted intermediate resource")

                # Check for security findings
                findings_count = len(
                    node.security_findings) if node.security_findings else 0
                risk_score += min(findings_count * 0.5, 2.0)

        # Determine severity
        if risk_score >= 8.0:
            severity = 'critical'
        elif risk_score >= 6.0:
            severity = 'high'
        elif risk_score >= 4.0:
            severity = 'medium'
        else:
            severity = 'low'

        return RiskPath(
            path_id=f"priv_esc_{hash(''.join(path))}",
            path_type='privilege_escalation',
            severity=severity,
            risk_score=min(risk_score, 10.0),
            resources=path,
            description=f"Potential privilege escalation from {entry_node.resource_type if entry_node else 'unknown'} to {target_node.resource_type if target_node else 'unknown'}",
            attack_vectors=attack_vectors,
            mitigation_steps=[
                "Implement least privilege access controls",
                "Add multi-factor authentication",
                "Monitor privileged account usage",
                "Implement network segmentation",
                "Enable comprehensive logging"
            ],
            compliance_impact=["SOC 2", "ISO 27001"]
        )

    def _check_resource_connectivity(self, source_id: UUID, target_id: UUID) -> Optional[List[str]]:
        """Check if two resources are connected through relationships."""

        # Simple path check using direct relationships
        relationship = self.db.query(ResourceRelationship).filter(
            or_(
                and_(
                    ResourceRelationship.source_resource_id == source_id,
                    ResourceRelationship.target_resource_id == target_id
                ),
                and_(
                    ResourceRelationship.source_resource_id == target_id,
                    ResourceRelationship.target_resource_id == source_id
                )
            )
        ).first()

        if relationship:
            return [str(source_id), str(target_id)]

        # Check for indirect connections (2-hop)
        indirect = self.db.query(ResourceRelationship).filter(
            ResourceRelationship.source_resource_id == source_id
        ).all()

        for rel in indirect:
            second_hop = self.db.query(ResourceRelationship).filter(
                ResourceRelationship.source_resource_id == rel.target_resource_id,
                ResourceRelationship.target_resource_id == target_id
            ).first()

            if second_hop:
                return [str(source_id), str(rel.target_resource_id), str(target_id)]

        return None

    def _create_data_exfiltration_risk(
        self,
        data_store: CloudResource,
        external: CloudResource,
        path: List[str]
    ) -> RiskPath:
        """Create a data exfiltration risk path."""

        # Calculate risk score
        risk_score = 5.0  # Base score

        if data_store.public_access:
            risk_score += 3.0
        if not data_store.encryption_enabled:
            risk_score += 2.0
        if external.public_access:
            risk_score += 2.0

        # Determine severity
        if risk_score >= 8.0:
            severity = 'critical'
        elif risk_score >= 6.0:
            severity = 'high'
        else:
            severity = 'medium'

        return RiskPath(
            path_id=f"data_exfil_{data_store.id}_{external.id}",
            path_type='data_exfiltration',
            severity=severity,
            risk_score=min(risk_score, 10.0),
            resources=path,
            description=f"Potential data exfiltration from {data_store.resource_type} to {external.resource_type}",
            attack_vectors=[
                "Direct data access",
                "API exploitation",
                "Service-to-service communication"
            ],
            mitigation_steps=[
                "Implement data loss prevention (DLP)",
                "Enable encryption in transit",
                "Add access logging and monitoring",
                "Implement network access controls",
                "Regular access reviews"
            ],
            compliance_impact=["GDPR", "PCI DSS", "HIPAA"]
        )

    def _analyze_cross_cloud_connections(
        self,
        provider1: CloudProvider,
        provider2: CloudProvider
    ) -> List[RiskPath]:
        """Analyze risks from cross-cloud connections."""

        risks = []

        # Find resources that might have cross-cloud connectivity
        # This is a simplified analysis - in practice, you'd need to analyze
        # network configurations, VPN connections, etc.

        p1_resources = self.db.query(CloudResource).filter(
            CloudResource.provider_id == provider1.id
        ).all()

        p2_resources = self.db.query(CloudResource).filter(
            CloudResource.provider_id == provider2.id
        ).all()

        # Look for potential cross-cloud risks
        for r1 in p1_resources[:10]:  # Limit to prevent explosion
            for r2 in p2_resources[:10]:
                if self._has_potential_cross_cloud_risk(r1, r2):
                    risk = RiskPath(
                        path_id=f"cross_cloud_{r1.id}_{r2.id}",
                        path_type='cross_cloud_exposure',
                        severity='medium',
                        risk_score=5.0,
                        resources=[str(r1.id), str(r2.id)],
                        description=f"Potential cross-cloud exposure between {provider1.name} and {provider2.name}",
                        attack_vectors=[
                            "Cross-cloud data transfer", "Identity federation"],
                        mitigation_steps=[
                            "Review cross-cloud connectivity",
                            "Implement cross-cloud monitoring",
                            "Validate identity federation"
                        ],
                        compliance_impact=["Data residency requirements"]
                    )
                    risks.append(risk)

        return risks

    def _has_potential_cross_cloud_risk(self, r1: CloudResource, r2: CloudResource) -> bool:
        """Check if two resources from different clouds have potential risk."""

        # Simplified risk assessment
        risk_types = ['api_gateway', 'load_balancer',
                      'vpn_gateway', 'direct_connect']

        return (r1.resource_type in risk_types or r2.resource_type in risk_types or
                r1.public_access or r2.public_access)

    def _get_network_connections(self, resource: CloudResource) -> List[CloudResource]:
        """Get network connections for a resource."""

        connections = []

        # Find related resources through relationships
        relationships = self.db.query(ResourceRelationship).filter(
            or_(
                ResourceRelationship.source_resource_id == resource.id,
                ResourceRelationship.target_resource_id == resource.id
            )
        ).all()

        for rel in relationships:
            if rel.relationship_type in ['network_connection', 'vpc_peering', 'attached_to']:
                if rel.source_resource_id == resource.id:
                    connections.append(rel.target_resource)
                else:
                    connections.append(rel.source_resource)

        return connections

    def _is_segmentation_violation(self, resource: CloudResource, connection: CloudResource) -> bool:
        """Check if a connection violates network segmentation."""

        # Example segmentation rules
        if 'prod' in resource.resource_name.lower() and 'dev' in connection.resource_name.lower():
            return True

        if resource.resource_type == 'rds_instance' and connection.public_access:
            return True

        return False

    def _create_segmentation_violation_risk(
        self,
        resource: CloudResource,
        connection: CloudResource
    ) -> RiskPath:
        """Create a network segmentation violation risk."""

        return RiskPath(
            path_id=f"seg_violation_{resource.id}_{connection.id}",
            path_type='network_segmentation_violation',
            severity='high',
            risk_score=7.0,
            resources=[str(resource.id), str(connection.id)],
            description=f"Network segmentation violation between {resource.resource_type} and {connection.resource_type}",
            attack_vectors=["Lateral movement", "Data access"],
            mitigation_steps=[
                "Implement network segmentation",
                "Review security group rules",
                "Add network monitoring"
            ],
            compliance_impact=["PCI DSS", "SOC 2"]
        )

    def _check_framework_compliance(self, framework: str) -> List[ComplianceViolation]:
        """Check compliance for a specific framework."""

        violations = []

        if framework == 'PCI DSS':
            violations.extend(self._check_pci_dss_compliance())
        elif framework == 'SOC 2':
            violations.extend(self._check_soc2_compliance())
        elif framework == 'GDPR':
            violations.extend(self._check_gdpr_compliance())

        return violations

    def _check_pci_dss_compliance(self) -> List[ComplianceViolation]:
        """Check PCI DSS compliance violations."""

        violations = []

        # Check for unencrypted data stores
        unencrypted = self.db.query(CloudResource).filter(
            CloudResource.resource_type.in_(['rds_instance', 's3_bucket']),
            CloudResource.encryption_enabled == False
        ).all()

        for resource in unencrypted:
            violations.append(ComplianceViolation(
                violation_id=f"pci_encryption_{resource.id}",
                framework='PCI DSS',
                control_id='3.4',
                severity='high',
                resources=[str(resource.id)],
                description='Cardholder data not encrypted at rest',
                remediation_priority='high'
            ))

        return violations

    def _check_soc2_compliance(self) -> List[ComplianceViolation]:
        """Check SOC 2 compliance violations."""

        violations = []

        # Check for public access to sensitive resources
        public_sensitive = self.db.query(CloudResource).filter(
            CloudResource.public_access == True,
            CloudResource.resource_type.in_(['rds_instance', 's3_bucket'])
        ).all()

        for resource in public_sensitive:
            violations.append(ComplianceViolation(
                violation_id=f"soc2_access_{resource.id}",
                framework='SOC 2',
                control_id='CC6.1',
                severity='critical',
                resources=[str(resource.id)],
                description='Sensitive resource has public access',
                remediation_priority='critical'
            ))

        return violations

    def _check_gdpr_compliance(self) -> List[ComplianceViolation]:
        """Check GDPR compliance violations."""

        violations = []

        # Check for cross-region data storage without proper controls
        eu_resources = self.db.query(CloudResource).filter(
            CloudResource.region.like('eu-%')
        ).all()

        non_eu_resources = self.db.query(CloudResource).filter(
            ~CloudResource.region.like('eu-%')
        ).all()

        if eu_resources and non_eu_resources:
            violations.append(ComplianceViolation(
                violation_id='gdpr_data_residency',
                framework='GDPR',
                control_id='Art. 44',
                severity='high',
                resources=[str(r.id) for r in eu_resources[:5]],
                description='Potential cross-border data transfer without adequate safeguards',
                remediation_priority='high'
            ))

        return violations

    def _find_overprivileged_accounts(self) -> List[Dict[str, Any]]:
        """Find overprivileged accounts."""

        # Simplified implementation - would need more sophisticated analysis
        accounts = []

        iam_resources = self.db.query(CloudResource).filter(
            CloudResource.resource_type.in_(
                ['iam_role', 'iam_user', 'service_account'])
        ).all()

        for resource in iam_resources:
            if resource.configuration:
                config = resource.configuration
                # Check for wildcard permissions
                if '*' in str(config):
                    accounts.append({
                        'resource_id': str(resource.id),
                        'resource_type': resource.resource_type,
                        'risk_factor': 'wildcard_permissions'
                    })

        return accounts

    def _find_shared_credentials(self) -> List[Dict[str, Any]]:
        """Find shared credentials."""

        # Simplified implementation
        return []

    def _find_excessive_access_patterns(self) -> List[Dict[str, Any]]:
        """Find excessive access patterns."""

        # Simplified implementation
        return []

    def _create_insider_threat_risk(self, threat_type: str, data: Dict[str, Any]) -> RiskPath:
        """Create an insider threat risk path."""

        return RiskPath(
            path_id=f"insider_{threat_type}_{data.get('resource_id', 'unknown')}",
            path_type='insider_threat',
            severity='medium',
            risk_score=6.0,
            resources=[data.get('resource_id', 'unknown')],
            description=f"Insider threat risk: {threat_type}",
            attack_vectors=["Privileged access abuse", "Credential misuse"],
            mitigation_steps=[
                "Implement privileged access management",
                "Enable user activity monitoring",
                "Regular access reviews",
                "Implement separation of duties"
            ],
            compliance_impact=["SOC 2", "ISO 27001"]
        )
