"""
API endpoints for security findings and risk analysis.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc

from ...models import get_db, SecurityFinding, CloudResource, CloudProvider
from ...core.security import verify_token
from ...services.security_service import SecurityService
from ...utils.pagination import paginate

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/findings", response_model=Dict[str, Any])
async def list_security_findings(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    finding_type: Optional[str] = Query(
        None, description="Filter by finding type"),
    status: Optional[str] = Query(
        None, description="Filter by remediation status"),
    provider: Optional[str] = Query(
        None, description="Filter by cloud provider"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    db: Session = Depends(get_db)
):
    """List security findings with filtering and pagination."""

    # Check if we have any real findings in the database
    total_count = db.query(SecurityFinding).count()

    if total_count == 0:
        # Return mock data to match the dashboard
        mock_findings = [
            {
                "id": "mock-1",
                "resource_id": "resource-1",
                "finding_type": "public_s3_bucket",
                "severity": "critical",
                "risk_score": 9.5,
                "title": "Critical: Public S3 Bucket Exposed",
                "description": "S3 bucket has public read access enabled, potentially exposing sensitive data to unauthorized users.",
                "remediation_status": "open",
                "remediation_priority": "critical",
                "first_detected": "2024-09-12T18:00:00Z",
                "last_detected": "2024-09-12T18:00:00Z",
                "resource": {
                    "resource_name": "production-data-bucket",
                    "resource_type": "s3_bucket",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-2",
                "resource_id": "resource-2",
                "finding_type": "exposed_database",
                "severity": "critical",
                "risk_score": 9.1,
                "title": "Critical: Database Publicly Accessible",
                "description": "RDS instance is publicly accessible from the internet, creating a significant security risk.",
                "remediation_status": "open",
                "remediation_priority": "critical",
                "first_detected": "2024-09-12T16:00:00Z",
                "last_detected": "2024-09-12T16:00:00Z",
                "resource": {
                    "resource_name": "prod-database-instance",
                    "resource_type": "rds_instance",
                    "region": "us-west-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-3",
                "resource_id": "resource-3",
                "finding_type": "exposed_secrets",
                "severity": "high",
                "risk_score": 8.8,
                "title": "High: Secrets Exposed in Environment",
                "description": "API keys and secrets are exposed in environment variables without proper encryption.",
                "remediation_status": "open",
                "remediation_priority": "high",
                "first_detected": "2024-09-12T14:00:00Z",
                "last_detected": "2024-09-12T14:00:00Z",
                "resource": {
                    "resource_name": "web-app-lambda",
                    "resource_type": "lambda_function",
                    "region": "eu-west-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-4",
                "resource_id": "resource-4",
                "finding_type": "exposed_azure_sql",
                "severity": "high",
                "risk_score": 8.3,
                "title": "High: Azure SQL Server Public Access",
                "description": "Azure SQL Server allows public access, potentially exposing sensitive database information.",
                "remediation_status": "open",
                "remediation_priority": "high",
                "first_detected": "2024-09-12T12:00:00Z",
                "last_detected": "2024-09-12T12:00:00Z",
                "resource": {
                    "resource_name": "prod-sql-server",
                    "resource_type": "sql_server",
                    "region": "eastus",
                    "provider": "azure"
                }
            },
            {
                "id": "mock-5",
                "resource_id": "resource-5",
                "finding_type": "encryption_disabled",
                "severity": "medium",
                "risk_score": 6.5,
                "title": "Medium: Encryption Disabled on Storage",
                "description": "Storage account has encryption disabled, making data vulnerable to unauthorized access.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-12T10:00:00Z",
                "last_detected": "2024-09-12T10:00:00Z",
                "resource": {
                    "resource_name": "storage-account-1",
                    "resource_type": "storage_account",
                    "region": "westus2",
                    "provider": "azure"
                }
            },
            {
                "id": "mock-6",
                "resource_id": "resource-6",
                "finding_type": "network_misconfiguration",
                "severity": "medium",
                "risk_score": 6.2,
                "title": "Medium: Open Security Group",
                "description": "Security group allows unrestricted access from the internet on port 22.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-12T08:00:00Z",
                "last_detected": "2024-09-12T08:00:00Z",
                "resource": {
                    "resource_name": "web-servers-sg",
                    "resource_type": "security_group",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-7",
                "resource_id": "resource-7",
                "finding_type": "access_control",
                "severity": "medium",
                "risk_score": 5.8,
                "title": "Medium: Overly Permissive IAM Policy",
                "description": "IAM policy grants excessive permissions that could lead to privilege escalation.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-12T06:00:00Z",
                "last_detected": "2024-09-12T06:00:00Z",
                "resource": {
                    "resource_name": "admin-policy",
                    "resource_type": "iam_policy",
                    "region": "us-west-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-8",
                "resource_id": "resource-8",
                "finding_type": "missing_logging",
                "severity": "low",
                "risk_score": 4.2,
                "title": "Low: Missing CloudTrail Logging",
                "description": "CloudTrail logging is not enabled for this region, reducing audit capabilities.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-12T04:00:00Z",
                "last_detected": "2024-09-12T04:00:00Z",
                "resource": {
                    "resource_name": "us-west-2-region",
                    "resource_type": "region",
                    "region": "us-west-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-9",
                "resource_id": "resource-9",
                "finding_type": "missing_logging",
                "severity": "low",
                "risk_score": 3.8,
                "title": "Low: Missing VPC Flow Logs",
                "description": "VPC Flow Logs are not enabled, limiting network traffic monitoring capabilities.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-12T02:00:00Z",
                "last_detected": "2024-09-12T02:00:00Z",
                "resource": {
                    "resource_name": "main-vpc",
                    "resource_type": "vpc",
                    "region": "eu-central-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-10",
                "resource_id": "resource-10",
                "finding_type": "info",
                "severity": "info",
                "risk_score": 2.1,
                "title": "Info: Resource Tagging Best Practice",
                "description": "Resource is missing required tags for cost allocation and governance.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-12T00:00:00Z",
                "last_detected": "2024-09-12T00:00:00Z",
                "resource": {
                    "resource_name": "untagged-instance",
                    "resource_type": "ec2_instance",
                    "region": "ap-southeast-1",
                    "provider": "aws"
                }
            }
        ]

        # Add more mock findings to reach the total of 43 (matching dashboard)
        additional_findings = [
            # More critical findings (total should be 3)
            {
                "id": "mock-11",
                "resource_id": "resource-11",
                "finding_type": "public_access",
                "severity": "critical",
                "risk_score": 9.3,
                "title": "Critical: Publicly Accessible Load Balancer",
                "description": "Application Load Balancer is configured with public access, exposing internal services.",
                "remediation_status": "open",
                "remediation_priority": "critical",
                "first_detected": "2024-09-11T22:00:00Z",
                "last_detected": "2024-09-11T22:00:00Z",
                "resource": {
                    "resource_name": "public-alb",
                    "resource_type": "load_balancer",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            # More high findings (total should be 8)
            {
                "id": "mock-12",
                "resource_id": "resource-12",
                "finding_type": "encryption_disabled",
                "severity": "high",
                "risk_score": 8.5,
                "title": "High: Unencrypted EBS Volume",
                "description": "EBS volume storing sensitive data is not encrypted, creating data exposure risk.",
                "remediation_status": "open",
                "remediation_priority": "high",
                "first_detected": "2024-09-11T20:00:00Z",
                "last_detected": "2024-09-11T20:00:00Z",
                "resource": {
                    "resource_name": "data-volume-1",
                    "resource_type": "ebs_volume",
                    "region": "us-west-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-13",
                "resource_id": "resource-13",
                "finding_type": "network_misconfiguration",
                "severity": "high",
                "risk_score": 8.2,
                "title": "High: Open RDP Port",
                "description": "Security group allows RDP access from any IP address (0.0.0.0/0).",
                "remediation_status": "open",
                "remediation_priority": "high",
                "first_detected": "2024-09-11T18:00:00Z",
                "last_detected": "2024-09-11T18:00:00Z",
                "resource": {
                    "resource_name": "windows-servers-sg",
                    "resource_type": "security_group",
                    "region": "eu-west-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-14",
                "resource_id": "resource-14",
                "finding_type": "access_control",
                "severity": "high",
                "risk_score": 7.9,
                "title": "High: Root Account Usage",
                "description": "Root account has been used recently, which violates security best practices.",
                "remediation_status": "open",
                "remediation_priority": "high",
                "first_detected": "2024-09-11T16:00:00Z",
                "last_detected": "2024-09-11T16:00:00Z",
                "resource": {
                    "resource_name": "root-account",
                    "resource_type": "iam_user",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-15",
                "resource_id": "resource-15",
                "finding_type": "missing_logging",
                "severity": "high",
                "risk_score": 7.6,
                "title": "High: Missing GuardDuty",
                "description": "AWS GuardDuty is not enabled, reducing threat detection capabilities.",
                "remediation_status": "open",
                "remediation_priority": "high",
                "first_detected": "2024-09-11T14:00:00Z",
                "last_detected": "2024-09-11T14:00:00Z",
                "resource": {
                    "resource_name": "us-east-1-region",
                    "resource_type": "region",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-16",
                "resource_id": "resource-16",
                "finding_type": "public_access",
                "severity": "high",
                "risk_score": 7.4,
                "title": "High: Publicly Accessible API Gateway",
                "description": "API Gateway is configured with public access without proper authentication.",
                "remediation_status": "open",
                "remediation_priority": "high",
                "first_detected": "2024-09-11T12:00:00Z",
                "last_detected": "2024-09-11T12:00:00Z",
                "resource": {
                    "resource_name": "public-api-gateway",
                    "resource_type": "api_gateway",
                    "region": "ap-southeast-1",
                    "provider": "aws"
                }
            },
            # More medium findings (total should be 15)
            {
                "id": "mock-17",
                "resource_id": "resource-17",
                "finding_type": "encryption_disabled",
                "severity": "medium",
                "risk_score": 6.8,
                "title": "Medium: Unencrypted S3 Bucket",
                "description": "S3 bucket does not have server-side encryption enabled.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-11T10:00:00Z",
                "last_detected": "2024-09-11T10:00:00Z",
                "resource": {
                    "resource_name": "unencrypted-bucket",
                    "resource_type": "s3_bucket",
                    "region": "us-west-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-18",
                "resource_id": "resource-18",
                "finding_type": "network_misconfiguration",
                "severity": "medium",
                "risk_score": 6.5,
                "title": "Medium: Open HTTP Port",
                "description": "Security group allows HTTP access from any IP address.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-11T08:00:00Z",
                "last_detected": "2024-09-11T08:00:00Z",
                "resource": {
                    "resource_name": "web-servers-sg-2",
                    "resource_type": "security_group",
                    "region": "eu-central-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-19",
                "resource_id": "resource-19",
                "finding_type": "access_control",
                "severity": "medium",
                "risk_score": 6.2,
                "title": "Medium: Weak Password Policy",
                "description": "IAM password policy does not meet security requirements.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-11T06:00:00Z",
                "last_detected": "2024-09-11T06:00:00Z",
                "resource": {
                    "resource_name": "account-password-policy",
                    "resource_type": "iam_policy",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-20",
                "resource_id": "resource-20",
                "finding_type": "missing_logging",
                "severity": "medium",
                "risk_score": 5.9,
                "title": "Medium: Missing Config Rules",
                "description": "AWS Config is not enabled for compliance monitoring.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-11T04:00:00Z",
                "last_detected": "2024-09-11T04:00:00Z",
                "resource": {
                    "resource_name": "us-west-2-region",
                    "resource_type": "region",
                    "region": "us-west-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-21",
                "resource_id": "resource-21",
                "finding_type": "public_access",
                "severity": "medium",
                "risk_score": 5.6,
                "title": "Medium: Publicly Accessible Lambda",
                "description": "Lambda function is publicly accessible without proper access controls.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-11T02:00:00Z",
                "last_detected": "2024-09-11T02:00:00Z",
                "resource": {
                    "resource_name": "public-lambda-function",
                    "resource_type": "lambda_function",
                    "region": "ap-northeast-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-22",
                "resource_id": "resource-22",
                "finding_type": "encryption_disabled",
                "severity": "medium",
                "risk_score": 5.3,
                "title": "Medium: Unencrypted RDS Instance",
                "description": "RDS instance is not encrypted at rest.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-11T00:00:00Z",
                "last_detected": "2024-09-11T00:00:00Z",
                "resource": {
                    "resource_name": "unencrypted-rds",
                    "resource_type": "rds_instance",
                    "region": "sa-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-23",
                "resource_id": "resource-23",
                "finding_type": "network_misconfiguration",
                "severity": "medium",
                "risk_score": 5.0,
                "title": "Medium: Open HTTPS Port",
                "description": "Security group allows HTTPS access from any IP address.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T22:00:00Z",
                "last_detected": "2024-09-10T22:00:00Z",
                "resource": {
                    "resource_name": "web-servers-sg-3",
                    "resource_type": "security_group",
                    "region": "ca-central-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-24",
                "resource_id": "resource-24",
                "finding_type": "access_control",
                "severity": "medium",
                "risk_score": 4.7,
                "title": "Medium: Excessive S3 Permissions",
                "description": "S3 bucket policy grants excessive permissions to anonymous users.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T20:00:00Z",
                "last_detected": "2024-09-10T20:00:00Z",
                "resource": {
                    "resource_name": "overly-permissive-bucket",
                    "resource_type": "s3_bucket",
                    "region": "eu-west-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-25",
                "resource_id": "resource-25",
                "finding_type": "missing_logging",
                "severity": "medium",
                "risk_score": 4.4,
                "title": "Medium: Missing CloudWatch Logs",
                "description": "EC2 instance is not sending logs to CloudWatch.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T18:00:00Z",
                "last_detected": "2024-09-10T18:00:00Z",
                "resource": {
                    "resource_name": "no-logs-instance",
                    "resource_type": "ec2_instance",
                    "region": "ap-south-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-26",
                "resource_id": "resource-26",
                "finding_type": "public_access",
                "severity": "medium",
                "risk_score": 4.1,
                "title": "Medium: Publicly Accessible EFS",
                "description": "Elastic File System is accessible from the internet.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T16:00:00Z",
                "last_detected": "2024-09-10T16:00:00Z",
                "resource": {
                    "resource_name": "public-efs",
                    "resource_type": "efs_filesystem",
                    "region": "us-east-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-27",
                "resource_id": "resource-27",
                "finding_type": "encryption_disabled",
                "severity": "medium",
                "risk_score": 3.8,
                "title": "Medium: Unencrypted ElastiCache",
                "description": "ElastiCache cluster is not encrypted in transit.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T14:00:00Z",
                "last_detected": "2024-09-10T14:00:00Z",
                "resource": {
                    "resource_name": "unencrypted-cache",
                    "resource_type": "elasticache_cluster",
                    "region": "eu-west-3",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-28",
                "resource_id": "resource-28",
                "finding_type": "network_misconfiguration",
                "severity": "medium",
                "risk_score": 3.5,
                "title": "Medium: Open Database Port",
                "description": "Security group allows database access from any IP address.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T12:00:00Z",
                "last_detected": "2024-09-10T12:00:00Z",
                "resource": {
                    "resource_name": "database-sg",
                    "resource_type": "security_group",
                    "region": "ap-southeast-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-29",
                "resource_id": "resource-29",
                "finding_type": "access_control",
                "severity": "medium",
                "risk_score": 3.2,
                "title": "Medium: Weak MFA Policy",
                "description": "Multi-factor authentication is not enforced for all users.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T10:00:00Z",
                "last_detected": "2024-09-10T10:00:00Z",
                "resource": {
                    "resource_name": "mfa-policy",
                    "resource_type": "iam_policy",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-30",
                "resource_id": "resource-30",
                "finding_type": "missing_logging",
                "severity": "medium",
                "risk_score": 2.9,
                "title": "Medium: Missing S3 Access Logging",
                "description": "S3 bucket does not have access logging enabled.",
                "remediation_status": "open",
                "remediation_priority": "medium",
                "first_detected": "2024-09-10T08:00:00Z",
                "last_detected": "2024-09-10T08:00:00Z",
                "resource": {
                    "resource_name": "no-access-logs-bucket",
                    "resource_type": "s3_bucket",
                    "region": "us-west-1",
                    "provider": "aws"
                }
            },
            # More low findings (total should be 12)
            {
                "id": "mock-31",
                "resource_id": "resource-31",
                "finding_type": "public_access",
                "severity": "low",
                "risk_score": 3.8,
                "title": "Low: Publicly Accessible CloudFront",
                "description": "CloudFront distribution allows public access without restrictions.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-10T06:00:00Z",
                "last_detected": "2024-09-10T06:00:00Z",
                "resource": {
                    "resource_name": "public-cloudfront",
                    "resource_type": "cloudfront_distribution",
                    "region": "global",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-32",
                "resource_id": "resource-32",
                "finding_type": "encryption_disabled",
                "severity": "low",
                "risk_score": 3.5,
                "title": "Low: Unencrypted DynamoDB Table",
                "description": "DynamoDB table is not encrypted at rest.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-10T04:00:00Z",
                "last_detected": "2024-09-10T04:00:00Z",
                "resource": {
                    "resource_name": "unencrypted-table",
                    "resource_type": "dynamodb_table",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-33",
                "resource_id": "resource-33",
                "finding_type": "network_misconfiguration",
                "severity": "low",
                "risk_score": 3.2,
                "title": "Low: Open DNS Port",
                "description": "Security group allows DNS access from any IP address.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-10T02:00:00Z",
                "last_detected": "2024-09-10T02:00:00Z",
                "resource": {
                    "resource_name": "dns-sg",
                    "resource_type": "security_group",
                    "region": "eu-west-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-34",
                "resource_id": "resource-34",
                "finding_type": "access_control",
                "severity": "low",
                "risk_score": 2.9,
                "title": "Low: Unused IAM Role",
                "description": "IAM role exists but has not been used recently.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-10T00:00:00Z",
                "last_detected": "2024-09-10T00:00:00Z",
                "resource": {
                    "resource_name": "unused-role",
                    "resource_type": "iam_role",
                    "region": "us-west-2",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-35",
                "resource_id": "resource-35",
                "finding_type": "missing_logging",
                "severity": "low",
                "risk_score": 2.6,
                "title": "Low: Missing VPC Endpoint Logs",
                "description": "VPC endpoint does not have logging enabled.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T22:00:00Z",
                "last_detected": "2024-09-09T22:00:00Z",
                "resource": {
                    "resource_name": "no-logs-endpoint",
                    "resource_type": "vpc_endpoint",
                    "region": "ap-northeast-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-36",
                "resource_id": "resource-36",
                "finding_type": "public_access",
                "severity": "low",
                "risk_score": 2.3,
                "title": "Low: Publicly Accessible SNS Topic",
                "description": "SNS topic allows public subscriptions.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T20:00:00Z",
                "last_detected": "2024-09-09T20:00:00Z",
                "resource": {
                    "resource_name": "public-sns-topic",
                    "resource_type": "sns_topic",
                    "region": "eu-central-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-37",
                "resource_id": "resource-37",
                "finding_type": "encryption_disabled",
                "severity": "low",
                "risk_score": 2.0,
                "title": "Low: Unencrypted SQS Queue",
                "description": "SQS queue is not encrypted.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T18:00:00Z",
                "last_detected": "2024-09-09T18:00:00Z",
                "resource": {
                    "resource_name": "unencrypted-queue",
                    "resource_type": "sqs_queue",
                    "region": "sa-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-38",
                "resource_id": "resource-38",
                "finding_type": "network_misconfiguration",
                "severity": "low",
                "risk_score": 1.7,
                "title": "Low: Open SMTP Port",
                "description": "Security group allows SMTP access from any IP address.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T16:00:00Z",
                "last_detected": "2024-09-09T16:00:00Z",
                "resource": {
                    "resource_name": "smtp-sg",
                    "resource_type": "security_group",
                    "region": "ca-central-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-39",
                "resource_id": "resource-39",
                "finding_type": "access_control",
                "severity": "low",
                "risk_score": 1.4,
                "title": "Low: Unused Access Key",
                "description": "IAM access key has not been used recently.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T14:00:00Z",
                "last_detected": "2024-09-09T14:00:00Z",
                "resource": {
                    "resource_name": "unused-access-key",
                    "resource_type": "iam_access_key",
                    "region": "ap-south-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-40",
                "resource_id": "resource-40",
                "finding_type": "missing_logging",
                "severity": "low",
                "risk_score": 1.1,
                "title": "Low: Missing Route53 Query Logs",
                "description": "Route53 hosted zone does not have query logging enabled.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T12:00:00Z",
                "last_detected": "2024-09-09T12:00:00Z",
                "resource": {
                    "resource_name": "no-query-logs-zone",
                    "resource_type": "route53_hosted_zone",
                    "region": "global",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-41",
                "resource_id": "resource-41",
                "finding_type": "public_access",
                "severity": "low",
                "risk_score": 0.8,
                "title": "Low: Publicly Accessible SES",
                "description": "SES configuration allows public email sending.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T10:00:00Z",
                "last_detected": "2024-09-09T10:00:00Z",
                "resource": {
                    "resource_name": "public-ses",
                    "resource_type": "ses_configuration",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-42",
                "resource_id": "resource-42",
                "finding_type": "encryption_disabled",
                "severity": "low",
                "risk_score": 0.5,
                "title": "Low: Unencrypted Kinesis Stream",
                "description": "Kinesis stream is not encrypted.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T08:00:00Z",
                "last_detected": "2024-09-09T08:00:00Z",
                "resource": {
                    "resource_name": "unencrypted-stream",
                    "resource_type": "kinesis_stream",
                    "region": "eu-west-2",
                    "provider": "aws"
                }
            },
            # More info findings (total should be 5)
            {
                "id": "mock-43",
                "resource_id": "resource-43",
                "finding_type": "info",
                "severity": "info",
                "risk_score": 1.8,
                "title": "Info: Missing Cost Allocation Tags",
                "description": "Resource is missing cost allocation tags for budget tracking.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T06:00:00Z",
                "last_detected": "2024-09-09T06:00:00Z",
                "resource": {
                    "resource_name": "untagged-cost-resource",
                    "resource_type": "ec2_instance",
                    "region": "us-east-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-44",
                "resource_id": "resource-44",
                "finding_type": "info",
                "severity": "info",
                "risk_score": 1.5,
                "title": "Info: Resource Naming Convention",
                "description": "Resource name does not follow organizational naming conventions.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T04:00:00Z",
                "last_detected": "2024-09-09T04:00:00Z",
                "resource": {
                    "resource_name": "badly-named-resource",
                    "resource_type": "s3_bucket",
                    "region": "us-west-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-45",
                "resource_id": "resource-45",
                "finding_type": "info",
                "severity": "info",
                "risk_score": 1.2,
                "title": "Info: Missing Backup Configuration",
                "description": "Resource does not have automated backup configured.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T02:00:00Z",
                "last_detected": "2024-09-09T02:00:00Z",
                "resource": {
                    "resource_name": "no-backup-rds",
                    "resource_type": "rds_instance",
                    "region": "eu-west-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-46",
                "resource_id": "resource-46",
                "finding_type": "info",
                "severity": "info",
                "risk_score": 0.9,
                "title": "Info: Resource Lifecycle Policy",
                "description": "Resource does not have lifecycle management configured.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-09T00:00:00Z",
                "last_detected": "2024-09-09T00:00:00Z",
                "resource": {
                    "resource_name": "no-lifecycle-bucket",
                    "resource_type": "s3_bucket",
                    "region": "ap-southeast-1",
                    "provider": "aws"
                }
            },
            {
                "id": "mock-47",
                "resource_id": "resource-47",
                "finding_type": "info",
                "severity": "info",
                "risk_score": 0.6,
                "title": "Info: Missing Monitoring Alarms",
                "description": "Resource does not have CloudWatch alarms configured.",
                "remediation_status": "open",
                "remediation_priority": "low",
                "first_detected": "2024-09-08T22:00:00Z",
                "last_detected": "2024-09-08T22:00:00Z",
                "resource": {
                    "resource_name": "no-alarms-instance",
                    "resource_type": "ec2_instance",
                    "region": "us-west-2",
                    "provider": "aws"
                }
            }
        ]

        # Combine all mock findings
        mock_findings.extend(additional_findings)

        # Apply filters to mock data
        filtered_findings = mock_findings

        if severity:
            severity_list = [s.strip() for s in severity.split(',')]
            filtered_findings = [
                f for f in filtered_findings if f["severity"] in severity_list]

        if finding_type:
            filtered_findings = [
                f for f in filtered_findings if f["finding_type"] == finding_type]

        if status:
            filtered_findings = [
                f for f in filtered_findings if f["remediation_status"] == status]

        if provider:
            filtered_findings = [
                f for f in filtered_findings if f["resource"]["provider"] == provider]

        # Apply pagination
        total_filtered = len(filtered_findings)
        start_idx = (page - 1) * size
        end_idx = start_idx + size
        paginated_findings = filtered_findings[start_idx:end_idx]

        return {
            "items": paginated_findings,
            "total": total_filtered,
            "page": page,
            "size": size,
            "pages": (total_filtered + size - 1) // size
        }

    # Real database query when data exists
    query = db.query(SecurityFinding).join(CloudResource).join(CloudProvider)

    # Apply filters
    if severity:
        query = query.filter(SecurityFinding.severity == severity)

    if finding_type:
        query = query.filter(SecurityFinding.finding_type == finding_type)

    if status:
        query = query.filter(SecurityFinding.remediation_status == status)

    if provider:
        query = query.filter(CloudProvider.name == provider)

    # Order by risk score descending
    query = query.order_by(desc(SecurityFinding.risk_score))

    # Paginate results
    result = paginate(query, page, size)

    # Format results
    findings = []
    for finding in result["items"]:
        finding_dict = {
            "id": str(finding.id),
            "resource_id": str(finding.resource_id),
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "title": finding.title,
            "description": finding.description,
            "remediation_status": finding.remediation_status,
            "remediation_priority": finding.remediation_priority,
            "first_detected": finding.first_detected.isoformat() if finding.first_detected else None,
            "last_detected": finding.last_detected.isoformat() if finding.last_detected else None,
            "resource": {
                "resource_name": finding.resource.resource_name,
                "resource_type": finding.resource.resource_type,
                "region": finding.resource.region,
                "provider": finding.resource.provider.name
            } if finding.resource else None
        }
        findings.append(finding_dict)

    return {
        "items": findings,
        "total": result["total"],
        "page": result["page"],
        "size": result["size"],
        "pages": result["pages"]
    }


@router.get("/findings/{finding_id}", response_model=Dict[str, Any])
async def get_security_finding(
    finding_id: UUID,
    db: Session = Depends(get_db),
    token: Dict[str, Any] = Depends(verify_token)
):
    """Get detailed information about a specific security finding."""

    finding = db.query(SecurityFinding).filter(
        SecurityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found"
        )

    return {
        "id": str(finding.id),
        "resource_id": str(finding.resource_id),
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "risk_score": finding.risk_score,
        "title": finding.title,
        "description": finding.description,
        "ai_analysis": finding.ai_analysis,
        "attack_vectors": finding.attack_vectors,
        "impact_assessment": finding.impact_assessment,
        "compliance_frameworks": finding.compliance_frameworks,
        "cis_controls": finding.cis_controls,
        "mitre_tactics": finding.mitre_tactics,
        "remediation_status": finding.remediation_status,
        "remediation_priority": finding.remediation_priority,
        "remediation_effort": finding.remediation_effort,
        "first_detected": finding.first_detected.isoformat() if finding.first_detected else None,
        "last_detected": finding.last_detected.isoformat() if finding.last_detected else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "resource": {
            "resource_id": finding.resource.resource_id,
            "resource_name": finding.resource.resource_name,
            "resource_type": finding.resource.resource_type,
            "region": finding.resource.region,
            "provider": finding.resource.provider.name,
            "account_id": finding.resource.account.account_id
        } if finding.resource else None
    }


@router.put("/findings/{finding_id}/status", response_model=Dict[str, Any])
async def update_finding_status(
    finding_id: UUID,
    status: str = Query(...,
                        description="New status: open, in_progress, resolved, false_positive"),
    db: Session = Depends(get_db),
    token: Dict[str, Any] = Depends(verify_token)
):
    """Update the remediation status of a security finding."""

    valid_statuses = ["open", "in_progress", "resolved", "false_positive"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )

    finding = db.query(SecurityFinding).filter(
        SecurityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found"
        )

    # Update status and timestamps
    finding.remediation_status = status

    if status == "resolved":
        from datetime import datetime
        finding.resolved_at = datetime.utcnow()
    elif status == "false_positive":
        from datetime import datetime
        finding.false_positive_at = datetime.utcnow()

    db.commit()

    return {
        "message": f"Finding status updated to {status}",
        "finding_id": str(finding_id),
        "new_status": status
    }


@router.get("/dashboard", response_model=Dict[str, Any])
async def get_security_dashboard(
    db: Session = Depends(get_db)
):
    """Get security dashboard statistics with enhanced data."""

    # For now, return mock data since no security findings exist in the database yet
    # This will be replaced with real database queries once data is populated

    from datetime import datetime, timedelta

    # Mock severity distribution
    severity_distribution = [
        {"severity": "critical", "count": 3},
        {"severity": "high", "count": 8},
        {"severity": "medium", "count": 15},
        {"severity": "low", "count": 12},
        {"severity": "info", "count": 5}
    ]

    # Mock status distribution
    status_distribution = [
        {"status": "open", "count": 25},
        {"status": "in_progress", "count": 8},
        {"status": "resolved", "count": 15},
        {"status": "false_positive", "count": 2}
    ]

    # Mock finding types
    top_finding_types = [
        {"type": "public_access", "count": 8},
        {"type": "encryption_disabled", "count": 12},
        {"type": "network_misconfiguration", "count": 6},
        {"type": "access_control", "count": 4},
        {"type": "missing_logging", "count": 10}
    ]

    # Mock resource types
    top_resource_types = [
        {"resource_type": "EC2 Instance", "count": 45, "findings": 23},
        {"resource_type": "S3 Bucket", "count": 32, "findings": 18},
        {"resource_type": "RDS Database", "count": 28, "findings": 15},
        {"resource_type": "IAM Role", "count": 22, "findings": 12},
        {"resource_type": "VPC", "count": 18, "findings": 8}
    ]

    # Mock urgent findings
    urgent_findings = [
        {
            "id": "mock-1",
            "title": "Critical: Public S3 Bucket Exposed",
            "severity": "critical",
            "risk_score": 9.5,
            "finding_type": "public_access",
            "resource_name": "production-data-bucket",
            "provider": "aws"
        },
        {
            "id": "mock-2",
            "title": "Critical: Database Publicly Accessible",
            "severity": "critical",
            "risk_score": 9.1,
            "finding_type": "public_access",
            "resource_name": "prod-database-instance",
            "provider": "aws"
        }
    ]

    # Mock trends data
    trends_data = []
    for i in range(30):
        date = datetime.utcnow() - timedelta(days=i)
        findings_count = max(0, 10 - i // 3)
        resolved_count = max(0, 8 - i // 4)

        trends_data.append({
            "date": date.strftime("%Y-%m-%d"),
            "findings": findings_count,
            "resolved": resolved_count
        })

    # Mock compliance violations
    compliance_violations = [
        {
            "framework": "PCI DSS",
            "violations": 12,
            "critical_violations": 3,
            "compliance_score": 75.5
        },
        {
            "framework": "SOC 2",
            "violations": 8,
            "critical_violations": 1,
            "compliance_score": 82.1
        },
        {
            "framework": "ISO 27001",
            "violations": 15,
            "critical_violations": 4,
            "compliance_score": 68.9
        }
    ]

    total_findings = sum(stat["count"] for stat in severity_distribution)
    high_risk_findings = sum(
        stat["count"] for stat in severity_distribution if stat["severity"] in ["critical", "high"])
    recent_findings = 5  # Mock recent findings
    average_risk_score = 6.8  # Mock average risk score

    return {
        "total_findings": total_findings,
        "high_risk_findings": high_risk_findings,
        "recent_findings": recent_findings,
        "average_risk_score": average_risk_score,
        "severity_distribution": severity_distribution,
        "status_distribution": status_distribution,
        "top_finding_types": top_finding_types,
        "top_resource_types": top_resource_types,
        "urgent_findings": urgent_findings,
        "trends_data": trends_data,
        "compliance_violations": compliance_violations
    }


@router.post("/analyze", response_model=Dict[str, Any])
async def trigger_security_analysis(
    resource_ids: Optional[List[UUID]] = None,
    provider: Optional[str] = None,
    db: Session = Depends(get_db)
    # token: Dict[str, Any] = Depends(verify_token)  # Temporarily disabled for demo
):
    """Trigger AI-powered security analysis for resources."""

    service = SecurityService(db)

    # Build query for resources to analyze
    query = db.query(CloudResource).join(CloudProvider)

    if resource_ids:
        query = query.filter(CloudResource.id.in_(resource_ids))

    if provider:
        query = query.filter(CloudProvider.name == provider)

    # Get detailed breakdown before analysis
    resources = query.all()

    if not resources:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No resources found for analysis"
        )

    # Calculate detailed breakdown
    provider_breakdown = {}
    resource_type_breakdown = {}
    total_resources = len(resources)

    for resource in resources:
        provider_name = resource.provider.name
        resource_type = resource.resource_type

        # Count by provider
        if provider_name not in provider_breakdown:
            provider_breakdown[provider_name] = {
                "count": 0,
                "display_name": resource.provider.display_name,
                "resource_types": {}
            }
        provider_breakdown[provider_name]["count"] += 1

        # Count resource types within provider
        if resource_type not in provider_breakdown[provider_name]["resource_types"]:
            provider_breakdown[provider_name]["resource_types"][resource_type] = 0
        provider_breakdown[provider_name]["resource_types"][resource_type] += 1

        # Count overall resource types
        if resource_type not in resource_type_breakdown:
            resource_type_breakdown[resource_type] = 0
        resource_type_breakdown[resource_type] += 1

    # Start analysis (this would be async in production)
    analysis_id = service.start_security_analysis([r.id for r in resources])

    return {
        "message": "Security analysis started",
        "analysis_id": analysis_id,
        "resources_count": total_resources,
        "analysis_breakdown": {
            "total_resources": total_resources,
            "providers": [
                {
                    "name": provider_name,
                    "display_name": data["display_name"],
                    "count": data["count"],
                    "resource_types": [
                        {
                            "type": resource_type,
                            "count": count
                        }
                        for resource_type, count in data["resource_types"].items()
                    ]
                }
                for provider_name, data in provider_breakdown.items()
            ],
            "resource_types": [
                {
                    "type": resource_type,
                    "count": count
                }
                for resource_type, count in sorted(resource_type_breakdown.items(), key=lambda x: x[1], reverse=True)
            ]
        }
    }


@router.get("/urgent", response_model=Dict[str, Any])
async def get_urgent_findings(
    db: Session = Depends(get_db)
):
    """Get urgent security findings that require immediate attention."""

    # Return mock data for now since no findings exist in the database yet
    critical_findings = [
        {
            "id": "urgent-1",
            "title": "Critical: Public S3 Bucket Exposed",
            "severity": "critical",
            "risk_score": 9.5,
            "finding_type": "public_s3_bucket",
            "description": "S3 bucket has public read access enabled, potentially exposing sensitive data to unauthorized users.",
            "resource_name": "production-data-bucket",
            "resource_type": "s3_bucket",
            "provider": "aws",
            "region": "us-east-1",
            "first_detected": "2024-09-12T18:00:00Z",
            "remediation_priority": "critical"
        },
        {
            "id": "urgent-2",
            "title": "Critical: Database Publicly Accessible",
            "severity": "critical",
            "risk_score": 9.1,
            "finding_type": "exposed_database",
            "description": "RDS instance is publicly accessible from the internet, creating a significant security risk.",
            "resource_name": "prod-database-instance",
            "resource_type": "rds_instance",
            "provider": "aws",
            "region": "us-west-2",
            "first_detected": "2024-09-12T16:00:00Z",
            "remediation_priority": "critical"
        }
    ]

    high_risk_findings = [
        {
            "id": "high-1",
            "title": "High: Secrets Exposed in Environment",
            "severity": "high",
            "risk_score": 8.8,
            "finding_type": "exposed_secrets",
            "description": "API keys and secrets are exposed in environment variables without proper encryption.",
            "resource_name": "web-app-lambda",
            "resource_type": "lambda_function",
            "provider": "aws",
            "region": "eu-west-1",
            "first_detected": "2024-09-12T14:00:00Z",
            "remediation_priority": "high"
        },
        {
            "id": "high-2",
            "title": "High: Azure SQL Server Public Access",
            "severity": "high",
            "risk_score": 8.3,
            "finding_type": "exposed_azure_sql",
            "description": "Azure SQL server is configured with public network access enabled.",
            "resource_name": "azure-sql-server-prod",
            "resource_type": "sql_server",
            "provider": "azure",
            "region": "eastus",
            "first_detected": "2024-09-12T12:00:00Z",
            "remediation_priority": "high"
        }
    ]

    recent_critical = critical_findings[:1]  # Just the first critical finding

    return {
        "critical_findings": critical_findings,
        "high_risk_findings": high_risk_findings,
        "recent_critical": recent_critical,
        "summary": {
            "total_critical": len(critical_findings),
            "total_high_risk": len(high_risk_findings),
            "recent_critical_count": len(recent_critical)
        }
    }


@router.get("/compliance", response_model=Dict[str, Any])
async def get_compliance_overview(
    framework: Optional[str] = Query(
        None, description="Filter by compliance framework"),
    db: Session = Depends(get_db)
    # token: Dict[str, Any] = Depends(verify_token)  # Temporarily disabled for demo
):
    """Get compliance overview and violations."""

    # This would be implemented based on specific compliance frameworks
    # For now, return a placeholder response

    return {
        "frameworks": [
            {
                "name": "PCI DSS",
                "compliance_score": 75.5,
                "violations": 12,
                "critical_violations": 3
            },
            {
                "name": "SOC 2",
                "compliance_score": 82.1,
                "violations": 8,
                "critical_violations": 1
            },
            {
                "name": "ISO 27001",
                "compliance_score": 68.9,
                "violations": 15,
                "critical_violations": 4
            }
        ],
        "overall_score": 75.5,
        "total_violations": 35,
        "critical_violations": 8
    }
