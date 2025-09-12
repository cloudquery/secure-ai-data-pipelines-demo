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
