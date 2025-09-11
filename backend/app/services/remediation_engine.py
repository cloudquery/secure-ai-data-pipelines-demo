"""
Remediation engine for generating Infrastructure-as-Code fixes and remediation procedures.
"""
import json
from typing import Dict, Any, List, Optional, Tuple
from uuid import UUID, uuid4
from sqlalchemy.orm import Session
from datetime import datetime
from dataclasses import dataclass
import yaml

from ..models import SecurityFinding, CloudResource, CloudProvider
from ..core.config import settings


@dataclass
class RemediationPlan:
    """Remediation plan for a security finding."""
    id: str
    finding_id: str
    resource_id: str
    remediation_type: str  # terraform, manual, policy
    priority: str
    estimated_effort: str
    terraform_code: Optional[str] = None
    manual_steps: Optional[List[str]] = None
    policy_changes: Optional[Dict[str, Any]] = None
    rollback_plan: Optional[str] = None
    validation_steps: Optional[List[str]] = None
    compliance_impact: Optional[List[str]] = None


class RemediationEngine:
    """Engine for generating automated remediation plans and IaC fixes."""

    def __init__(self, db: Session):
        self.db = db
        self.terraform_generators = {
            'public_access': self._generate_public_access_fix,
            'encryption_disabled': self._generate_encryption_fix,
            'network_misconfiguration': self._generate_network_fix,
            'access_control': self._generate_access_control_fix,
            'logging_disabled': self._generate_logging_fix,
        }

    def generate_remediation_plan(self, finding_id: UUID) -> RemediationPlan:
        """Generate a comprehensive remediation plan for a security finding."""

        finding = self.db.query(SecurityFinding).filter(
            SecurityFinding.id == finding_id
        ).first()

        if not finding:
            raise ValueError(f"Security finding {finding_id} not found")

        resource = finding.resource
        if not resource:
            raise ValueError(f"Resource for finding {finding_id} not found")

        plan_id = str(uuid4())

        # Determine remediation approach
        if finding.auto_remediable and finding.finding_type in self.terraform_generators:
            # Generate Terraform fix
            terraform_code = self._generate_terraform_fix(finding, resource)
            rollback_plan = self._generate_rollback_plan(finding, resource)

            plan = RemediationPlan(
                id=plan_id,
                finding_id=str(finding_id),
                resource_id=str(resource.id),
                remediation_type='terraform',
                priority=finding.remediation_priority or 'medium',
                estimated_effort=self._estimate_terraform_effort(finding),
                terraform_code=terraform_code,
                rollback_plan=rollback_plan,
                validation_steps=self._generate_validation_steps(
                    finding, resource),
                compliance_impact=self._assess_compliance_impact(finding)
            )
        else:
            # Generate manual remediation steps
            manual_steps = self._generate_manual_steps(finding, resource)

            plan = RemediationPlan(
                id=plan_id,
                finding_id=str(finding_id),
                resource_id=str(resource.id),
                remediation_type='manual',
                priority=finding.remediation_priority or 'medium',
                estimated_effort=self._estimate_manual_effort(finding),
                manual_steps=manual_steps,
                validation_steps=self._generate_validation_steps(
                    finding, resource),
                compliance_impact=self._assess_compliance_impact(finding)
            )

        return plan

    def generate_bulk_remediation(
        self,
        finding_ids: List[UUID],
        group_by_resource: bool = True
    ) -> List[RemediationPlan]:
        """Generate remediation plans for multiple findings."""

        plans = []

        if group_by_resource:
            # Group findings by resource to optimize remediation
            resource_findings = {}
            for finding_id in finding_ids:
                finding = self.db.query(SecurityFinding).filter(
                    SecurityFinding.id == finding_id
                ).first()
                if finding:
                    resource_id = str(finding.resource_id)
                    if resource_id not in resource_findings:
                        resource_findings[resource_id] = []
                    resource_findings[resource_id].append(finding)

            # Generate combined plans for each resource
            for resource_id, findings in resource_findings.items():
                combined_plan = self._generate_combined_remediation(findings)
                plans.append(combined_plan)
        else:
            # Generate individual plans
            for finding_id in finding_ids:
                plan = self.generate_remediation_plan(finding_id)
                plans.append(plan)

        return plans

    def _generate_terraform_fix(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate Terraform code to fix the security finding."""

        generator = self.terraform_generators.get(finding.finding_type)
        if not generator:
            return self._generate_generic_terraform_comment(finding, resource)

        return generator(finding, resource)

    def _generate_public_access_fix(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate Terraform fix for public access issues."""

        provider = resource.provider.name if resource.provider else 'aws'

        if provider == 'aws':
            if resource.resource_type == 's3_bucket':
                return self._generate_s3_private_terraform(resource)
            elif resource.resource_type == 'rds_instance':
                return self._generate_rds_private_terraform(resource)
            elif resource.resource_type == 'ec2_instance':
                return self._generate_ec2_private_terraform(resource)
        elif provider == 'gcp':
            return self._generate_gcp_private_terraform(resource)
        elif provider == 'azure':
            return self._generate_azure_private_terraform(resource)

        return self._generate_generic_terraform_comment(finding, resource)

    def _generate_encryption_fix(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate Terraform fix for encryption issues."""

        provider = resource.provider.name if resource.provider else 'aws'

        if provider == 'aws':
            if resource.resource_type == 's3_bucket':
                return f"""
# Enable S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "{resource.resource_name}_encryption" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      kms_master_key_id = aws_kms_key.{resource.resource_name}_key.arn
      sse_algorithm     = "aws:kms"
    }}
    bucket_key_enabled = true
  }}
}}

# Create KMS key for encryption
resource "aws_kms_key" "{resource.resource_name}_key" {{
  description             = "KMS key for {resource.resource_name} encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {{
    Name        = "{resource.resource_name}-encryption-key"
    Purpose     = "S3 bucket encryption"
    Environment = var.environment
  }}
}}

resource "aws_kms_alias" "{resource.resource_name}_key_alias" {{
  name          = "alias/{resource.resource_name}-key"
  target_key_id = aws_kms_key.{resource.resource_name}_key.key_id
}}
"""
            elif resource.resource_type == 'rds_instance':
                return f"""
# Enable RDS encryption at rest
resource "aws_db_instance" "{resource.resource_name}" {{
  # ... other configuration ...
  
  storage_encrypted = true
  kms_key_id       = aws_kms_key.{resource.resource_name}_key.arn
  
  tags = {{
    Name        = "{resource.resource_name}"
    Encrypted   = "true"
    Environment = var.environment
  }}
}}

# Create KMS key for RDS encryption
resource "aws_kms_key" "{resource.resource_name}_key" {{
  description             = "KMS key for {resource.resource_name} encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {{
    Name        = "{resource.resource_name}-rds-key"
    Purpose     = "RDS encryption"
    Environment = var.environment
  }}
}}
"""

        return self._generate_generic_terraform_comment(finding, resource)

    def _generate_network_fix(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate Terraform fix for network security issues."""

        if 'SSH' in finding.title or '22' in finding.description:
            return f"""
# Restrict SSH access to specific IP ranges
resource "aws_security_group_rule" "{resource.resource_name}_ssh_restriction" {{
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_cidr_blocks]  # Replace with your admin IP ranges
  security_group_id = aws_security_group.{resource.resource_name}.id
  description       = "SSH access from admin networks only"
}}

# Remove the overly permissive rule (this should be done manually or with state manipulation)
# terraform state rm aws_security_group_rule.{resource.resource_name}_ssh_open

# Alternative: Create a new security group with proper rules
resource "aws_security_group" "{resource.resource_name}_secure" {{
  name_prefix = "{resource.resource_name}-secure"
  vpc_id      = var.vpc_id
  
  # SSH access from bastion host only
  ingress {{
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
    description     = "SSH from bastion host"
  }}
  
  # Application traffic
  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "HTTP from private networks"
  }}
  
  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "HTTPS from private networks"
  }}
  
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }}

  tags = {{
    Name        = "{resource.resource_name}-secure-sg"
    Purpose     = "Secure security group"
    Environment = var.environment
  }}
}}
"""

        return self._generate_generic_terraform_comment(finding, resource)

    def _generate_access_control_fix(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate Terraform fix for access control issues."""

        return f"""
# Create least-privilege IAM policy
resource "aws_iam_policy" "{resource.resource_name}_policy" {{
  name        = "{resource.resource_name}-policy"
  description = "Least-privilege policy for {resource.resource_name}"
  
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = [
          # Replace with specific actions needed
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::{resource.resource_name}/*"
        ]
        Condition = {{
          StringEquals = {{
            "s3:x-amz-server-side-encryption" = "AES256"
          }}
        }}
      }}
    ]
  }})

  tags = {{
    Name        = "{resource.resource_name}-policy"
    Purpose     = "Least privilege access"
    Environment = var.environment
  }}
}}

# Attach policy to role (replace wildcard permissions)
resource "aws_iam_role_policy_attachment" "{resource.resource_name}_attachment" {{
  role       = aws_iam_role.{resource.resource_name}.name
  policy_arn = aws_iam_policy.{resource.resource_name}_policy.arn
}}
"""

    def _generate_logging_fix(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate Terraform fix for logging issues."""

        return f"""
# Enable CloudTrail logging
resource "aws_cloudtrail" "{resource.resource_name}_trail" {{
  name           = "{resource.resource_name}-trail"
  s3_bucket_name = aws_s3_bucket.{resource.resource_name}_logs.bucket
  
  event_selector {{
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []

    data_resource {{
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::{resource.resource_name}/*"]
    }}
  }}

  tags = {{
    Name        = "{resource.resource_name}-trail"
    Purpose     = "Security logging"
    Environment = var.environment
  }}
}}

# Create S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "{resource.resource_name}_logs" {{
  bucket        = "{resource.resource_name}-cloudtrail-logs"
  force_destroy = false

  tags = {{
    Name        = "{resource.resource_name}-logs"
    Purpose     = "CloudTrail logs"
    Environment = var.environment
  }}
}}

# Enable CloudWatch logging
resource "aws_cloudwatch_log_group" "{resource.resource_name}_logs" {{
  name              = "/aws/{resource.service_name}/{resource.resource_name}"
  retention_in_days = 30

  tags = {{
    Name        = "{resource.resource_name}-logs"
    Purpose     = "Application logs"
    Environment = var.environment
  }}
}}
"""

    def _generate_s3_private_terraform(self, resource: CloudResource) -> str:
        """Generate Terraform to make S3 bucket private."""

        return f"""
# Block all public access to S3 bucket
resource "aws_s3_bucket_public_access_block" "{resource.resource_name}_pab" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}

# Remove public bucket policy
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

# Enable versioning for data protection
resource "aws_s3_bucket_versioning" "{resource.resource_name}_versioning" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}
"""

    def _generate_rds_private_terraform(self, resource: CloudResource) -> str:
        """Generate Terraform to make RDS instance private."""

        return f"""
# Make RDS instance private
resource "aws_db_instance" "{resource.resource_name}" {{
  # ... other configuration ...
  
  publicly_accessible = false
  
  # Ensure it's in a private subnet
  db_subnet_group_name = aws_db_subnet_group.{resource.resource_name}_private.name
  
  # Apply restrictive security group
  vpc_security_group_ids = [aws_security_group.{resource.resource_name}_private.id]

  tags = {{
    Name        = "{resource.resource_name}"
    Access      = "private"
    Environment = var.environment
  }}
}}

# Create private subnet group
resource "aws_db_subnet_group" "{resource.resource_name}_private" {{
  name       = "{resource.resource_name}-private"
  subnet_ids = var.private_subnet_ids

  tags = {{
    Name = "{resource.resource_name} private subnet group"
  }}
}}

# Create restrictive security group
resource "aws_security_group" "{resource.resource_name}_private" {{
  name_prefix = "{resource.resource_name}-private"
  vpc_id      = var.vpc_id

  # Only allow access from application servers
  ingress {{
    from_port       = 3306  # Adjust port as needed
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_servers.id]
    description     = "Database access from app servers"
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  tags = {{
    Name        = "{resource.resource_name}-private-sg"
    Purpose     = "Private database access"
    Environment = var.environment
  }}
}}
"""

    def _generate_ec2_private_terraform(self, resource: CloudResource) -> str:
        """Generate Terraform to secure EC2 instance."""

        return f"""
# Move EC2 instance to private subnet
resource "aws_instance" "{resource.resource_name}" {{
  # ... other configuration ...
  
  subnet_id                   = var.private_subnet_id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.{resource.resource_name}_private.id]

  tags = {{
    Name        = "{resource.resource_name}"
    Access      = "private"
    Environment = var.environment
  }}
}}

# Create private security group
resource "aws_security_group" "{resource.resource_name}_private" {{
  name_prefix = "{resource.resource_name}-private"
  vpc_id      = var.vpc_id

  # SSH access only from bastion
  ingress {{
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
    description     = "SSH from bastion"
  }}

  # Application ports from load balancer
  ingress {{
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "HTTP from load balancer"
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  tags = {{
    Name        = "{resource.resource_name}-private-sg"
    Purpose     = "Private instance access"
    Environment = var.environment
  }}
}}
"""

    def _generate_generic_terraform_comment(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate a generic Terraform comment for manual implementation."""

        return f"""
# Manual remediation required for {finding.finding_type}
# Resource: {resource.resource_type} ({resource.resource_name})
# Finding: {finding.title}
# 
# Recommended actions:
# {chr(10).join(f'# - {step}' for step in finding.remediation_steps or [])}
#
# This finding requires manual review and implementation.
# Please refer to the security documentation for detailed steps.
"""

    def _generate_manual_steps(self, finding: SecurityFinding, resource: CloudResource) -> List[str]:
        """Generate manual remediation steps."""

        base_steps = [
            f"Review the {resource.resource_type} configuration for {finding.finding_type}",
            f"Assess the security impact of the current configuration",
            f"Plan the remediation approach considering dependencies",
            f"Test the remediation in a non-production environment",
            f"Apply the remediation during a maintenance window",
            f"Validate the fix and monitor for any issues"
        ]

        # Add finding-specific steps
        if finding.remediation_steps:
            return finding.remediation_steps + base_steps

        return base_steps

    def _generate_rollback_plan(self, finding: SecurityFinding, resource: CloudResource) -> str:
        """Generate rollback plan for Terraform changes."""

        return f"""
# Rollback Plan for {resource.resource_name}
# 
# In case the remediation causes issues:
# 
# 1. Immediate rollback:
#    terraform apply -target=aws_{resource.resource_type}.{resource.resource_name} -var="rollback=true"
# 
# 2. Restore from backup (if applicable):
#    # Restore configuration from backup taken before changes
# 
# 3. Emergency access:
#    # If access is lost, use emergency access procedures
#    # Contact cloud administrator with account access
# 
# 4. Monitoring:
#    # Monitor application logs and metrics after rollback
#    # Verify all services are functioning normally
# 
# 5. Root cause analysis:
#    # Document what went wrong
#    # Plan alternative remediation approach
"""

    def _generate_validation_steps(self, finding: SecurityFinding, resource: CloudResource) -> List[str]:
        """Generate validation steps for remediation."""

        return [
            f"Verify {resource.resource_type} configuration has been updated",
            f"Test access to {resource.resource_name} from expected sources",
            f"Confirm the security finding is resolved",
            f"Run security scans to validate the fix",
            f"Monitor logs for any access issues or errors",
            f"Update documentation with the new configuration",
            f"Schedule follow-up review in 30 days"
        ]

    def _assess_compliance_impact(self, finding: SecurityFinding) -> List[str]:
        """Assess compliance impact of the remediation."""

        impacts = []

        if finding.compliance_frameworks:
            for framework in finding.compliance_frameworks:
                impacts.append(f"Improves {framework} compliance posture")

        # Add general compliance benefits
        if finding.finding_type == 'encryption_disabled':
            impacts.extend([
                "Meets data protection requirements",
                "Satisfies encryption at rest mandates"
            ])
        elif finding.finding_type == 'public_access':
            impacts.extend([
                "Reduces data exposure risk",
                "Improves access control compliance"
            ])

        return impacts or ["General security posture improvement"]

    def _estimate_terraform_effort(self, finding: SecurityFinding) -> str:
        """Estimate effort required for Terraform remediation."""

        effort_map = {
            'public_access': '1-2 hours',
            'encryption_disabled': '2-4 hours',
            'network_misconfiguration': '2-6 hours',
            'access_control': '4-8 hours',
            'logging_disabled': '3-6 hours'
        }

        return effort_map.get(finding.finding_type, '2-4 hours')

    def _estimate_manual_effort(self, finding: SecurityFinding) -> str:
        """Estimate effort required for manual remediation."""

        # Manual remediation typically takes longer
        effort_map = {
            'public_access': '2-4 hours',
            'encryption_disabled': '4-8 hours',
            'network_misconfiguration': '4-12 hours',
            'access_control': '8-16 hours',
            'logging_disabled': '6-12 hours'
        }

        return effort_map.get(finding.finding_type, '4-8 hours')

    def _generate_combined_remediation(self, findings: List[SecurityFinding]) -> RemediationPlan:
        """Generate a combined remediation plan for multiple findings on the same resource."""

        if not findings:
            raise ValueError("No findings provided for combined remediation")

        resource = findings[0].resource
        plan_id = str(uuid4())

        # Combine Terraform fixes
        terraform_parts = []
        manual_steps = []

        for finding in findings:
            if finding.auto_remediable and finding.finding_type in self.terraform_generators:
                tf_code = self._generate_terraform_fix(finding, resource)
                terraform_parts.append(f"# Fix for {finding.title}\n{tf_code}")
            else:
                steps = self._generate_manual_steps(finding, resource)
                manual_steps.extend(
                    [f"{finding.title}: {step}" for step in steps])

        # Determine remediation type
        if terraform_parts:
            remediation_type = 'terraform'
            terraform_code = "\n\n".join(terraform_parts)
        else:
            remediation_type = 'manual'
            terraform_code = None

        # Calculate combined priority
        priorities = [
            f.remediation_priority for f in findings if f.remediation_priority]
        if 'critical' in priorities:
            priority = 'critical'
        elif 'high' in priorities:
            priority = 'high'
        else:
            priority = 'medium'

        return RemediationPlan(
            id=plan_id,
            finding_id=','.join(str(f.id) for f in findings),
            resource_id=str(resource.id),
            remediation_type=remediation_type,
            priority=priority,
            estimated_effort='4-12 hours',  # Combined effort
            terraform_code=terraform_code,
            manual_steps=manual_steps if manual_steps else None,
            rollback_plan=self._generate_rollback_plan(findings[0], resource),
            validation_steps=self._generate_validation_steps(
                findings[0], resource),
            compliance_impact=list(set(
                impact for finding in findings
                for impact in self._assess_compliance_impact(finding)
            ))
        )
