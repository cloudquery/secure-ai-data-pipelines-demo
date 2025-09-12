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

    # Total findings by severity
    severity_stats = db.query(
        SecurityFinding.severity,
        func.count(SecurityFinding.id).label("count")
    ).group_by(SecurityFinding.severity).all()

    # Findings by status
    status_stats = db.query(
        SecurityFinding.remediation_status,
        func.count(SecurityFinding.id).label("count")
    ).group_by(SecurityFinding.remediation_status).all()

    # Top finding types
    type_stats = db.query(
        SecurityFinding.finding_type,
        func.count(SecurityFinding.id).label("count")
    ).group_by(SecurityFinding.finding_type).order_by(desc(func.count(SecurityFinding.id))).limit(10).all()

    # Top resource types with security findings
    resource_type_stats = db.query(
        CloudResource.resource_type,
        func.count(CloudResource.id).label("count"),
        func.count(SecurityFinding.id).label("findings")
    ).outerjoin(SecurityFinding).group_by(CloudResource.resource_type).order_by(desc(func.count(SecurityFinding.id))).limit(10).all()

    # High risk findings (score >= 7)
    high_risk_count = db.query(func.count(SecurityFinding.id)).filter(
        SecurityFinding.risk_score >= 7.0,
        SecurityFinding.remediation_status == "open"
    ).scalar()

    # Recent findings (last 7 days)
    from datetime import datetime, timedelta
    recent_findings = db.query(func.count(SecurityFinding.id)).filter(
        SecurityFinding.first_detected >= datetime.utcnow() - timedelta(days=7)
    ).scalar()

    # Average risk score
    avg_risk_score = db.query(
        func.avg(SecurityFinding.risk_score)).scalar() or 0.0

    # Urgent findings (critical severity, open status)
    urgent_findings = db.query(SecurityFinding).join(CloudResource).join(CloudProvider).filter(
        SecurityFinding.severity == "critical",
        SecurityFinding.remediation_status == "open"
    ).limit(5).all()

    # Trends data (last 30 days)
    trends_data = []
    for i in range(30):
        date = datetime.utcnow() - timedelta(days=i)
        findings_count = db.query(func.count(SecurityFinding.id)).filter(
            func.date(SecurityFinding.first_detected) == date.date()
        ).scalar() or 0

        resolved_count = db.query(func.count(SecurityFinding.id)).filter(
            func.date(SecurityFinding.resolved_at) == date.date()
        ).scalar() or 0

        trends_data.append({
            "date": date.strftime("%Y-%m-%d"),
            "findings": findings_count,
            "resolved": resolved_count
        })

    # Compliance violations (mock data for now)
    compliance_violations = [
        {
            "framework": "PCI DSS",
            "violations": db.query(func.count(SecurityFinding.id)).filter(
                SecurityFinding.compliance_frameworks.contains("PCI DSS")
            ).scalar() or 12,
            "critical_violations": db.query(func.count(SecurityFinding.id)).filter(
                SecurityFinding.compliance_frameworks.contains("PCI DSS"),
                SecurityFinding.severity == "critical"
            ).scalar() or 3,
            "compliance_score": 75.5
        },
        {
            "framework": "SOC 2",
            "violations": db.query(func.count(SecurityFinding.id)).filter(
                SecurityFinding.compliance_frameworks.contains("SOC 2")
            ).scalar() or 8,
            "critical_violations": db.query(func.count(SecurityFinding.id)).filter(
                SecurityFinding.compliance_frameworks.contains("SOC 2"),
                SecurityFinding.severity == "critical"
            ).scalar() or 1,
            "compliance_score": 82.1
        },
        {
            "framework": "ISO 27001",
            "violations": db.query(func.count(SecurityFinding.id)).filter(
                SecurityFinding.compliance_frameworks.contains("ISO 27001")
            ).scalar() or 15,
            "critical_violations": db.query(func.count(SecurityFinding.id)).filter(
                SecurityFinding.compliance_frameworks.contains("ISO 27001"),
                SecurityFinding.severity == "critical"
            ).scalar() or 4,
            "compliance_score": 68.9
        }
    ]

    return {
        "total_findings": sum(stat.count for stat in severity_stats),
        "high_risk_findings": high_risk_count,
        "recent_findings": recent_findings,
        "average_risk_score": round(float(avg_risk_score), 2),
        "severity_distribution": [
            {
                "severity": stat.severity,
                "count": stat.count
            }
            for stat in severity_stats
        ],
        "status_distribution": [
            {
                "status": stat.remediation_status,
                "count": stat.count
            }
            for stat in status_stats
        ],
        "top_finding_types": [
            {
                "type": stat.finding_type,
                "count": stat.count
            }
            for stat in type_stats
        ],
        "top_resource_types": [
            {
                "resource_type": stat.resource_type,
                "count": stat.count,
                "findings": stat.findings
            }
            for stat in resource_type_stats
        ],
        "urgent_findings": [
            {
                "id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "finding_type": finding.finding_type,
                "resource_name": finding.resource.resource_name,
                "provider": finding.resource.provider.name
            }
            for finding in urgent_findings
        ],
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

    # Critical findings
    critical_findings = db.query(SecurityFinding).join(CloudResource).join(CloudProvider).filter(
        SecurityFinding.severity == "critical",
        SecurityFinding.remediation_status == "open"
    ).order_by(desc(SecurityFinding.risk_score)).limit(10).all()

    # High risk findings
    high_risk_findings = db.query(SecurityFinding).join(CloudResource).join(CloudProvider).filter(
        SecurityFinding.severity == "high",
        SecurityFinding.remediation_status == "open",
        SecurityFinding.risk_score >= 8.0
    ).order_by(desc(SecurityFinding.risk_score)).limit(10).all()

    # Recent critical findings (last 24 hours)
    from datetime import datetime, timedelta
    recent_critical = db.query(SecurityFinding).join(CloudResource).join(CloudProvider).filter(
        SecurityFinding.severity.in_(["critical", "high"]),
        SecurityFinding.first_detected >= datetime.utcnow() - timedelta(hours=24)
    ).order_by(desc(SecurityFinding.risk_score)).limit(5).all()

    def format_finding(finding):
        return {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "finding_type": finding.finding_type,
            "description": finding.description,
            "resource_name": finding.resource.resource_name,
            "resource_type": finding.resource.resource_type,
            "provider": finding.resource.provider.name,
            "region": finding.resource.region,
            "first_detected": finding.first_detected.isoformat() if finding.first_detected else None,
            "remediation_priority": finding.remediation_priority
        }

    return {
        "critical_findings": [format_finding(f) for f in critical_findings],
        "high_risk_findings": [format_finding(f) for f in high_risk_findings],
        "recent_critical": [format_finding(f) for f in recent_critical],
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
    db: Session = Depends(get_db),
    token: Dict[str, Any] = Depends(verify_token)
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
