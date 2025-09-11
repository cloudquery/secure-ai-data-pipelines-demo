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
                    auto_remediable=finding_data.get("auto_remediable", False),
                    remediation_steps=finding_data.get("remediation_steps"),
                    terraform_fix=finding_data.get("terraform_fix")
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
                "auto_remediable": True,
                "remediation_steps": [
                    "Review if public access is necessary",
                    "Implement proper access controls",
                    "Use VPC endpoints or private connectivity",
                    "Enable logging and monitoring"
                ]
            }

            # Generate Terraform fix
            if resource.resource_type == "s3_bucket":
                finding["terraform_fix"] = self._generate_s3_private_terraform(
                    resource)
            elif resource.resource_type == "rds_instance":
                finding["terraform_fix"] = self._generate_rds_private_terraform(
                    resource)

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
                "auto_remediable": True,
                "remediation_steps": [
                    "Enable encryption at rest",
                    "Use customer-managed KMS keys",
                    "Implement key rotation policies",
                    "Enable encryption in transit"
                ]
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
                "auto_remediable": False,
                "remediation_steps": [
                    "Migrate resource to VPC",
                    "Configure appropriate subnets",
                    "Implement security groups",
                    "Review network access controls"
                ]
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
                            "auto_remediable": True,
                            "remediation_steps": [
                                "Restrict SSH access to specific IP ranges",
                                "Use bastion hosts for SSH access",
                                "Implement VPN or private connectivity",
                                "Enable MFA for SSH access"
                            ]
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
                            "auto_remediable": True
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
                            "auto_remediable": False,
                            "remediation_steps": [
                                "Review and scope down permissions",
                                "Apply principle of least privilege",
                                "Use specific actions instead of wildcards",
                                "Implement regular access reviews"
                            ]
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

    def _generate_s3_private_terraform(self, resource: CloudResource) -> str:
        """Generate Terraform code to make S3 bucket private."""

        return f"""
# Make S3 bucket private
resource "aws_s3_bucket_public_access_block" "{resource.resource_name}_pab" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}

resource "aws_s3_bucket_policy" "{resource.resource_name}_policy" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid       = "DenyPublicAccess"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.{resource.resource_name}.arn,
          "${{aws_s3_bucket.{resource.resource_name}.arn}}/*"
        ]
        Condition = {{
          Bool = {{
            "aws:SecureTransport" = "false"
          }}
        }}
      }}
    ]
  }})
}}
"""

    def _generate_rds_private_terraform(self, resource: CloudResource) -> str:
        """Generate Terraform code to make RDS instance private."""

        return f"""
# Make RDS instance private
resource "aws_db_instance" "{resource.resource_name}" {{
  # ... other configuration ...
  
  publicly_accessible = false
  
  # Ensure it's in a private subnet
  db_subnet_group_name = aws_db_subnet_group.private.name
  
  # Apply security group that doesn't allow public access
  vpc_security_group_ids = [aws_security_group.rds_private.id]
}}

resource "aws_security_group" "rds_private" {{
  name_prefix = "{resource.resource_name}-private"
  vpc_id      = var.vpc_id

  # Only allow access from application servers
  ingress {{
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_servers.id]
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
"""
