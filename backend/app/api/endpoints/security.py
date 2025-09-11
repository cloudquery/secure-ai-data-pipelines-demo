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
    auto_remediable: Optional[bool] = Query(
        None, description="Filter by auto-remediable status"),
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

    if auto_remediable is not None:
        query = query.filter(
            SecurityFinding.auto_remediable == auto_remediable)

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
            "auto_remediable": finding.auto_remediable,
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
        "auto_remediable": finding.auto_remediable,
        "remediation_steps": finding.remediation_steps,
        "terraform_fix": finding.terraform_fix,
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
    """Get security dashboard statistics."""

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

    # Auto-remediable findings
    auto_remediable_count = db.query(func.count(SecurityFinding.id)).filter(
        SecurityFinding.auto_remediable == True,
        SecurityFinding.remediation_status == "open"
    ).scalar()

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

    return {
        "total_findings": sum(stat.count for stat in severity_stats),
        "high_risk_findings": high_risk_count,
        "auto_remediable_findings": auto_remediable_count,
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
        ]
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
    query = db.query(CloudResource)

    if resource_ids:
        query = query.filter(CloudResource.id.in_(resource_ids))

    if provider:
        query = query.join(CloudProvider).filter(
            CloudProvider.name == provider)

    resources = query.limit(100).all()  # Limit to prevent overload

    if not resources:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No resources found for analysis"
        )

    # Start analysis (this would be async in production)
    analysis_id = service.start_security_analysis([r.id for r in resources])

    return {
        "message": "Security analysis started",
        "analysis_id": analysis_id,
        "resources_count": len(resources)
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
