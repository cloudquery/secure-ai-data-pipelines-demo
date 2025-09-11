"""
Service for cloud resource operations and management.
"""
from typing import List, Dict, Any, Optional
from uuid import UUID
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from ..models import CloudResource, ResourceRelationship, CloudProvider
from ..core.security import sanitize_cloud_resource_id, mask_sensitive_fields


class ResourceService:
    """Service for managing cloud resources."""

    def __init__(self, db: Session):
        self.db = db

    def get_resource_relationships(self, resource_id: UUID) -> List[Dict[str, Any]]:
        """Get all relationships for a resource."""

        # Get outgoing relationships
        outgoing = self.db.query(ResourceRelationship).filter(
            ResourceRelationship.source_resource_id == resource_id
        ).all()

        # Get incoming relationships
        incoming = self.db.query(ResourceRelationship).filter(
            ResourceRelationship.target_resource_id == resource_id
        ).all()

        relationships = []

        # Process outgoing relationships
        for rel in outgoing:
            target_resource = rel.target_resource
            relationships.append({
                "id": str(rel.id),
                "direction": "outgoing",
                "relationship_type": rel.relationship_type,
                "confidence_score": rel.confidence_score,
                "target_resource": {
                    "id": str(target_resource.id),
                    "resource_id": target_resource.resource_id,
                    "resource_name": target_resource.resource_name,
                    "resource_type": target_resource.resource_type,
                    "region": target_resource.region,
                    "provider": target_resource.provider.name
                },
                "relationship_data": rel.relationship_data,
                "discovered_at": rel.discovered_at.isoformat() if rel.discovered_at else None
            })

        # Process incoming relationships
        for rel in incoming:
            source_resource = rel.source_resource
            relationships.append({
                "id": str(rel.id),
                "direction": "incoming",
                "relationship_type": rel.relationship_type,
                "confidence_score": rel.confidence_score,
                "source_resource": {
                    "id": str(source_resource.id),
                    "resource_id": source_resource.resource_id,
                    "resource_name": source_resource.resource_name,
                    "resource_type": source_resource.resource_type,
                    "region": source_resource.region,
                    "provider": source_resource.provider.name
                },
                "relationship_data": rel.relationship_data,
                "discovered_at": rel.discovered_at.isoformat() if rel.discovered_at else None
            })

        return relationships

    def get_resource_graph_data(self, resource_ids: List[UUID]) -> Dict[str, Any]:
        """Get graph data for visualization."""

        # Get resources
        resources = self.db.query(CloudResource).filter(
            CloudResource.id.in_(resource_ids)
        ).all()

        # Get relationships between these resources
        relationships = self.db.query(ResourceRelationship).filter(
            and_(
                ResourceRelationship.source_resource_id.in_(resource_ids),
                ResourceRelationship.target_resource_id.in_(resource_ids)
            )
        ).all()

        # Format nodes
        nodes = []
        for resource in resources:
            node = {
                "id": str(resource.id),
                "label": resource.resource_name or resource.resource_id,
                "type": resource.resource_type,
                "provider": resource.provider.name,
                "region": resource.region,
                "public_access": resource.public_access,
                "encryption_enabled": resource.encryption_enabled,
                "risk_level": self._calculate_resource_risk_level(resource)
            }
            nodes.append(node)

        # Format edges
        edges = []
        for rel in relationships:
            edge = {
                "id": str(rel.id),
                "source": str(rel.source_resource_id),
                "target": str(rel.target_resource_id),
                "type": rel.relationship_type,
                "confidence": rel.confidence_score
            }
            edges.append(edge)

        return {
            "nodes": nodes,
            "edges": edges
        }

    def _calculate_resource_risk_level(self, resource: CloudResource) -> str:
        """Calculate risk level for a resource based on its properties."""

        risk_score = 0

        # Public access increases risk
        if resource.public_access:
            risk_score += 3

        # Lack of encryption increases risk
        if not resource.encryption_enabled:
            risk_score += 2

        # Certain resource types are inherently riskier
        high_risk_types = ['s3_bucket', 'rds_instance',
                           'ec2_instance', 'lambda_function']
        if resource.resource_type in high_risk_types:
            risk_score += 1

        # Check for security findings
        findings_count = len(
            resource.security_findings) if resource.security_findings else 0
        if findings_count > 0:
            risk_score += min(findings_count, 3)  # Cap at 3 additional points

        # Determine risk level
        if risk_score >= 6:
            return "critical"
        elif risk_score >= 4:
            return "high"
        elif risk_score >= 2:
            return "medium"
        else:
            return "low"

    def discover_relationships(self, resource_ids: List[UUID]) -> int:
        """Discover and create relationships between resources."""

        relationships_created = 0

        # Get resources with their configurations
        resources = self.db.query(CloudResource).filter(
            CloudResource.id.in_(resource_ids)
        ).all()

        # Build resource lookup by ID patterns
        resource_lookup = {}
        for resource in resources:
            resource_lookup[resource.resource_id] = resource
            if resource.resource_arn:
                resource_lookup[resource.resource_arn] = resource

        # Discover relationships based on configuration references
        for resource in resources:
            if not resource.configuration:
                continue

            relationships = self._extract_relationships_from_config(
                resource, resource.configuration, resource_lookup
            )

            for rel_data in relationships:
                # Check if relationship already exists
                existing = self.db.query(ResourceRelationship).filter(
                    and_(
                        ResourceRelationship.source_resource_id == resource.id,
                        ResourceRelationship.target_resource_id == rel_data["target_id"],
                        ResourceRelationship.relationship_type == rel_data["type"]
                    )
                ).first()

                if not existing:
                    relationship = ResourceRelationship(
                        source_resource_id=resource.id,
                        target_resource_id=rel_data["target_id"],
                        relationship_type=rel_data["type"],
                        relationship_data=rel_data.get("data", {}),
                        confidence_score=rel_data.get("confidence", 0.8)
                    )
                    self.db.add(relationship)
                    relationships_created += 1

        self.db.commit()
        return relationships_created

    def _extract_relationships_from_config(
        self,
        source_resource: CloudResource,
        config: Dict[str, Any],
        resource_lookup: Dict[str, CloudResource]
    ) -> List[Dict[str, Any]]:
        """Extract relationships from resource configuration."""

        relationships = []

        # Common patterns to look for in configurations
        reference_patterns = {
            'vpc_id': 'network_member',
            'subnet_id': 'network_member',
            'security_group_ids': 'protected_by',
            'security_groups': 'protected_by',
            'load_balancer_arn': 'load_balanced_by',
            'target_group_arn': 'member_of',
            'kms_key_id': 'encrypted_by',
            'iam_role': 'assumes_role',
            'instance_profile': 'uses_profile'
        }

        def search_config_recursive(obj, path=""):
            """Recursively search configuration for resource references."""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key

                    # Check if this key matches a known pattern
                    if key.lower() in reference_patterns:
                        relationship_type = reference_patterns[key.lower()]

                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, str) and item in resource_lookup:
                                    target_resource = resource_lookup[item]
                                    relationships.append({
                                        "target_id": target_resource.id,
                                        "type": relationship_type,
                                        "confidence": 0.9,
                                        "data": {"config_path": current_path}
                                    })
                        elif isinstance(value, str) and value in resource_lookup:
                            target_resource = resource_lookup[value]
                            relationships.append({
                                "target_id": target_resource.id,
                                "type": relationship_type,
                                "confidence": 0.9,
                                "data": {"config_path": current_path}
                            })

                    # Continue recursive search
                    search_config_recursive(value, current_path)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_config_recursive(item, f"{path}[{i}]")

        search_config_recursive(config)
        return relationships

    def sanitize_resource_data(self, resource: CloudResource) -> CloudResource:
        """Sanitize sensitive data in a resource."""

        # Create a copy to avoid modifying the original
        sanitized = CloudResource()

        # Copy basic attributes
        for attr in ['id', 'provider_id', 'account_id', 'resource_type', 'service_name',
                     'region', 'availability_zone', 'state', 'public_access',
                     'encryption_enabled', 'encryption_type', 'resource_created_at',
                     'last_modified', 'discovered_at', 'last_scanned']:
            setattr(sanitized, attr, getattr(resource, attr))

        # Sanitize identifiers
        sanitized.resource_id = sanitize_cloud_resource_id(
            resource.resource_id)
        if resource.resource_arn:
            sanitized.resource_arn = self._sanitize_arn(resource.resource_arn)
        if resource.resource_name:
            sanitized.resource_name = f"resource-{sanitize_cloud_resource_id(resource.resource_name)[:8]}"

        # Sanitize configuration
        if resource.configuration:
            sanitized.configuration = mask_sensitive_fields(
                resource.configuration)

        # Sanitize tags
        if resource.tags:
            sanitized.tags = mask_sensitive_fields(resource.tags)

        return sanitized

    def _sanitize_arn(self, arn: str) -> str:
        """Sanitize AWS ARN by hashing the resource identifier."""
        parts = arn.split(':')
        if len(parts) >= 6:
            # Keep the structure but hash the resource identifier
            resource_part = parts[-1]
            if '/' in resource_part:
                # For resources like role/MyRole
                resource_type, resource_id = resource_part.split('/', 1)
                sanitized_id = sanitize_cloud_resource_id(resource_id)
                parts[-1] = f"{resource_type}/{sanitized_id}"
            else:
                parts[-1] = sanitize_cloud_resource_id(resource_part)

            return ':'.join(parts)

        return sanitize_cloud_resource_id(arn)
