"""
Service for AI-powered security analysis and risk assessment.
"""
from typing import List, Dict, Any, Optional
from uuid import UUID, uuid4
from sqlalchemy.orm import Session
from datetime import datetime
import json
import asyncio

from ..models import CloudResource, SecurityFinding, CloudProvider
from ..core.config import settings
from ..core.security import mask_sensitive_fields


class SecurityService:
    """Service for security analysis and risk assessment."""

    def __init__(self, db: Session):
        self.db = db
        self.ai_client = None  # Initialize AI client based on configuration

    def start_security_analysis(self, resource_ids: List[UUID]) -> str:
        """Start AI-powered security analysis for resources."""

        analysis_id = str(uuid4())

        # In a production environment, this would be queued for background processing
        # For now, we'll simulate the analysis

        resources = self.db.query(CloudResource).filter(
            CloudResource.id.in_(resource_ids)
        ).all()

        for resource in resources:
            findings = self._analyze_resource_security(resource)

            # Save findings to database
            for finding_data in findings:
                finding = SecurityFinding(
                    resource_id=resource.id,
                    finding_type=finding_data["type"],
                    severity=finding_data["severity"],
                    risk_score=finding_data["risk_score"],
                    title=finding_data["title"],
                    description=finding_data["description"],
                    ai_analysis=finding_data.get("ai_analysis"),
                    attack_vectors=finding_data.get("attack_vectors"),
                    impact_assessment=finding_data.get("impact_assessment"),
                    compliance_frameworks=finding_data.get(
                        "compliance_frameworks"),
                    remediation_priority=finding_data.get("priority"),
                )
                self.db.add(finding)

        self.db.commit()
        return analysis_id

    def _analyze_resource_security(self, resource: CloudResource) -> List[Dict[str, Any]]:
        """Analyze security of a single resource."""

        findings = []

        # Rule-based security checks
        findings.extend(self._check_public_access(resource))
        findings.extend(self._check_encryption(resource))
        findings.extend(self._check_network_security(resource))
        findings.extend(self._check_access_controls(resource))
        findings.extend(self._check_logging_monitoring(resource))

        # AI-enhanced analysis (if AI client is available)
        if self.ai_client and resource.configuration:
            ai_findings = self._ai_analyze_configuration(resource)
            findings.extend(ai_findings)

        return findings

    def _check_public_access(self, resource: CloudResource) -> List[Dict[str, Any]]:
        """Check for public access vulnerabilities."""

        findings = []

        if resource.public_access:
            severity = "critical" if resource.resource_type in [
                "s3_bucket", "rds_instance"] else "high"
            risk_score = 9.0 if severity == "critical" else 7.0

            finding = {
                "type": "public_access",
                "severity": severity,
                "risk_score": risk_score,
                "title": f"Public access enabled on {resource.resource_type}",
                "description": f"The {resource.resource_type} '{resource.resource_name}' has public access enabled, which could expose sensitive data or services to unauthorized users.",
                "ai_analysis": {
                    "risk_factors": [
                        "Resource is accessible from the internet",
                        "Potential for data exposure",
                        "Attack surface expansion"
                    ],
                    "business_impact": "High - potential data breach or service compromise"
                },
                "attack_vectors": [
                    {
                        "vector": "Direct internet access",
                        "likelihood": "high",
                        "impact": "high"
                    }
                ],
                "compliance_frameworks": ["PCI DSS", "SOC 2", "ISO 27001"],
                "priority": "critical" if severity == "critical" else "high",
            }

            findings.append(finding)

        return findings

    def _check_encryption(self, resource: CloudResource) -> List[Dict[str, Any]]:
        """Check for encryption-related vulnerabilities."""

        findings = []

        if not resource.encryption_enabled:
            # Determine severity based on resource type
            critical_types = ["s3_bucket", "rds_instance", "ebs_volume"]
            severity = "high" if resource.resource_type in critical_types else "medium"
            risk_score = 7.0 if severity == "high" else 5.0

            finding = {
                "type": "encryption_disabled",
                "severity": severity,
                "risk_score": risk_score,
                "title": f"Encryption not enabled on {resource.resource_type}",
                "description": f"The {resource.resource_type} '{resource.resource_name}' does not have encryption enabled, which could lead to data exposure if the resource is compromised.",
                "ai_analysis": {
                    "risk_factors": [
                        "Data stored in plaintext",
                        "Compliance violations possible",
                        "Increased impact of data breaches"
                    ],
                    "business_impact": "Medium to High - potential compliance violations and data exposure"
                },
                "compliance_frameworks": ["PCI DSS", "HIPAA", "SOC 2"],
                "priority": severity,
            }

            findings.append(finding)

        return findings

    def _check_network_security(self, resource: CloudResource) -> List[Dict[str, Any]]:
        """Check network security configuration."""

        findings = []

        if not resource.configuration:
            return findings

        config = resource.configuration

        # Check for overly permissive security groups
        if "security_groups" in config or "security_group_ids" in config:
            sg_findings = self._analyze_security_groups(resource, config)
            findings.extend(sg_findings)

        # Check for missing VPC configuration
        if not resource.vpc_id and resource.resource_type in ["ec2_instance", "rds_instance", "lambda_function"]:
            finding = {
                "type": "network_isolation",
                "severity": "medium",
                "risk_score": 5.0,
                "title": f"{resource.resource_type} not in VPC",
                "description": f"The {resource.resource_type} is not deployed in a VPC, reducing network isolation and security controls.",
                "priority": "medium",
            }
            findings.append(finding)

        return findings

    def _analyze_security_groups(self, resource: CloudResource, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security group configurations."""

        findings = []

        # Look for common security group misconfigurations
        security_rules = config.get(
            "ingress_rules", []) + config.get("egress_rules", [])

        for rule in security_rules:
            if isinstance(rule, dict):
                # Check for overly permissive rules
                if rule.get("cidr_blocks") and "0.0.0.0/0" in rule.get("cidr_blocks", []):
                    if rule.get("from_port") == 22 or rule.get("to_port") == 22:
                        finding = {
                            "type": "network_misconfiguration",
                            "severity": "critical",
                            "risk_score": 9.0,
                            "title": "SSH access open to the world",
                            "description": "Security group allows SSH access (port 22) from any IP address (0.0.0.0/0).",
                            "priority": "critical",
                        }
                        findings.append(finding)

                    elif rule.get("from_port") == 3389 or rule.get("to_port") == 3389:
                        finding = {
                            "type": "network_misconfiguration",
                            "severity": "critical",
                            "risk_score": 9.0,
                            "title": "RDP access open to the world",
                            "description": "Security group allows RDP access (port 3389) from any IP address (0.0.0.0/0).",
                            "priority": "critical",
                        }
                        findings.append(finding)

        return findings

    def _check_access_controls(self, resource: CloudResource) -> List[Dict[str, Any]]:
        """Check access control configurations."""

        findings = []

        if not resource.configuration:
            return findings

        # Check for overly permissive IAM policies
        if "iam_policy" in resource.configuration:
            policy = resource.configuration["iam_policy"]
            if isinstance(policy, dict) and "Statement" in policy:
                for statement in policy["Statement"]:
                    if statement.get("Effect") == "Allow" and statement.get("Action") == "*":
                        finding = {
                            "type": "access_control",
                            "severity": "high",
                            "risk_score": 8.0,
                            "title": "Overly permissive IAM policy",
                            "description": "IAM policy grants wildcard (*) permissions, violating principle of least privilege.",
                            "priority": "high",
                        }
                        findings.append(finding)

        return findings

    def _check_logging_monitoring(self, resource: CloudResource) -> List[Dict[str, Any]]:
        """Check logging and monitoring configuration."""

        findings = []

        # Check if CloudTrail logging is enabled (for AWS resources)
        if (resource.provider and resource.provider.name == "aws" and
                resource.resource_type not in ["cloudtrail_trail", "cloudwatch_log_group"]):

            # This would require checking if CloudTrail is enabled for the account
            # For now, we'll create a placeholder finding
            pass

        return findings

    def _ai_analyze_configuration(self, resource: CloudResource) -> List[Dict[str, Any]]:
        """Use AI to analyze resource configuration for security issues."""

        # This would integrate with OpenAI or other AI services
        # For now, return empty list as placeholder
        return []
